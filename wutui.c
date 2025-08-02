/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/sbuf.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <wpa_ctrl.h>

#include "ctrl_seq.h"
#include "usage.h"
#include "wifi.h"

struct wutui {
	int tty, wpa_fd, kq;
	struct termios cooked;
	struct wpa_ctrl *ctrl;
	struct winsize winsize;
};

static struct wutui wutui;

static const int MAX_COLS = 80;
static const int MAX_ROWS = 36;

#define MARGIN ((wutui.winsize.ws_col - MAX_COLS) / 2)

static void parse_args(int argc, char *argv[], const char **ctrl_path);

static void init_wutui(const char *ctrl_path);
static void deinit_wutui(void);
static void event_loop(void);

static void render_tui(void);
static void render_wifi_info(struct sbuf *sb);
static void render_known_networks(struct sbuf *sb);
static void render_network_scan(struct sbuf *sb);

static void heading(struct sbuf *sb, const char *text, bool is_top);

static int fetch_cursor_position(unsigned short *row, unsigned short *col);
static int fetch_winsize(void);
static void on_sig_winch(int signo);

static void disable_raw_mode(void);
static void enter_raw_mode(void);
static void enter_alt_buffer(void);
static void leave_alt_buffer(void);

void die(const char *, ...);
void diex(const char *, ...);

static int read_key(void);
static void handle_input(void);
static void handle_wpa_event(void);

int
main(int argc, char *argv[])
{
	const char *ctrl_path = wpa_ctrl_default_path();

	if (!isatty(STDIN_FILENO))
		errx(EXIT_FAILURE, "not a TTY");

	parse_args(argc, argv, &ctrl_path);
	if (ctrl_path == NULL) {
		errx(EXIT_FAILURE,
		    "no wpa ctrl interface on default path, provide --ctrl-interface");
	}

	init_wutui(ctrl_path);
	enter_raw_mode();
	enter_alt_buffer();

	event_loop();

	return (EXIT_SUCCESS);
}

static void
parse_args(int argc, char *argv[], const char **ctrl_path)
{
	int opt;
	struct option opts[] = {
		{ "ctrl-interface", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "+c:h", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			*ctrl_path = optarg;
			break;
		case 'h':
			usage_tui(stdout);
			exit(EXIT_SUCCESS);
		case '?':
		default:
			usage_tui(stderr);
			exit(EXIT_FAILURE);
		}
	}

	if (argc - optind != 0) {
		warnx("wrong number of arguments");
		usage_tui(stderr);
		exit(EXIT_FAILURE);
	}
}

static void
init_wutui(const char *ctrl_path)
{
	struct sigaction sa = { 0 };

	wutui.wpa_fd = wutui.tty = wutui.kq = -1;

	if (atexit(deinit_wutui) != 0)
		err(EXIT_FAILURE, "atexit");

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = on_sig_winch;
	if (sigaction(SIGWINCH, &sa, 0) == -1)
		err(EXIT_FAILURE, "sigaction SIGWINCH");

	if ((wutui.ctrl = wpa_ctrl_open(ctrl_path)) == NULL) {
		err(EXIT_FAILURE,
		    "failed to open wpa_supplicant ctrl_interface, %s",
		    ctrl_path);
	}

	if (wpa_ctrl_attach(wutui.ctrl) != 0) {
		err(EXIT_FAILURE,
		    "failed to register to wpa_ctrl event monitor");
	}

	if ((wutui.wpa_fd = wpa_ctrl_get_fd(wutui.ctrl)) == -1)
		err(EXIT_FAILURE, "invalid wpa_ctrl socket");

	if ((wutui.kq = kqueue()) == -1)
		err(EXIT_FAILURE, "kqueue()");

	if ((wutui.tty = open("/dev/tty", O_RDWR)) == -1)
		err(EXIT_FAILURE, "open(/dev/tty)");

	if (tcgetattr(wutui.tty, &wutui.cooked) == -1)
		err(EXIT_FAILURE, "tcgetattr()");

	if (fetch_winsize() == -1)
		err(EXIT_FAILURE, "failed to fetch terminal winsize");
}

static void
deinit_wutui(void)
{
	if (wutui.tty != -1)
		disable_raw_mode();

	close(wutui.tty);
	close(wutui.kq);

	wpa_ctrl_detach(wutui.ctrl);
	wpa_ctrl_close(wutui.ctrl);
}

static void
event_loop(void)
{
	struct kevent events[2], tevent;

	EV_SET(&events[0], wutui.tty, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&events[1], wutui.wpa_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(wutui.kq, events, 2, NULL, 0, NULL) == -1)
		die("kevent register");

	for (;;) {
		int nev = -1;

		render_tui();

		nev = kevent(wutui.kq, NULL, 0, &tevent, 1, NULL);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			die("kevent wait");
		}

		if (nev > 0 && tevent.flags & EV_ERROR)
			diex("event error: %s", strerror(tevent.data));

		if (tevent.ident == (uintptr_t)wutui.tty)
			handle_input();
		else if (tevent.ident == (uintptr_t)wutui.wpa_fd)
			handle_wpa_event();
	}
}

static void
render_tui(void)
{
	struct sbuf *sb = sbuf_new_auto();

	sbuf_cat(sb, ERASE_IN_DISPLAY(ERASE_ENTIRE) CURSOR_MOVE(1, 1));

	if (wutui.winsize.ws_col < MAX_COLS ||
	    wutui.winsize.ws_row < MAX_ROWS) {
		const char warning[] = "Terminal size too small";
		int warning_len = sizeof(warning) - 1;
		int vertical_offset = (wutui.winsize.ws_row - 1) / 2;
		int text_offset = (wutui.winsize.ws_col - warning_len) / 2;

		vertical_offset = MAX(vertical_offset, 0);
		text_offset = MAX(text_offset, 0);

		sbuf_printf(sb, CURSOR_DOWN_FMT, vertical_offset);
		sbuf_printf(sb, "%*s" BOLD "%s" RESET_SGR, text_offset, "",
		    warning);
	} else {
		int vertical_offset = (wutui.winsize.ws_row - MAX_ROWS) / 2;

		vertical_offset = MAX(vertical_offset, 0);
		sbuf_printf(sb, CURSOR_DOWN_FMT, vertical_offset + 1);

		heading(sb, "WiFi Info", true);
		render_wifi_info(sb);

		heading(sb, "Known Networks", false);
		render_known_networks(sb);

		heading(sb, "Network Scan", false);
		render_network_scan(sb);

		sbuf_printf(sb, "%*s╰", MARGIN, "");
		for (int i = 0; i < MAX_COLS - 2; i++)
			sbuf_cat(sb, "─");
		sbuf_cat(sb, "╯");
	}

	if (sbuf_finish(sb) != 0)
		die("sbuf failed");

	if (write(wutui.tty, sbuf_data(sb), sbuf_len(sb)) != sbuf_len(sb))
		die("write");

	sbuf_delete(sb);
}

static void
render_wifi_info(struct sbuf *sb)
{
	struct supplicant_status *status = get_supplicant_status(wutui.ctrl);
	int freq = 0;
	const int FREQ_LEN = sizeof("5180") - 1;
	/* wpa state with max len*/
	const int WPA_STATE_LEN = sizeof("INTERFACE_DISABLED") - 1;
	const int IP_LEN = sizeof("255.255.255.255") - 1;

	if (status == NULL)
		diex("failed retrieve wpa_supplicant status");

	if (status->bssid != NULL)
		freq = get_bss_freq(wutui.ctrl, status->bssid);

	sbuf_printf(sb,
	    "%*s│  SSID:      %-*s    Frequency:  %*d MHz         │\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN,
	    status->ssid == NULL ? "N/A" : status->ssid, FREQ_LEN, freq);
	sbuf_printf(sb,
	    "%*s│  WPA State: %-*s                  IP Address: %-*s  │\r\n",
	    MARGIN, "", WPA_STATE_LEN,
	    status->state == NULL ? "N/A" : status->state, IP_LEN,
	    status->ip_address == NULL ? "N/A" : status->ip_address);
}

static void
render_known_networks(struct sbuf *sb)
{
	struct known_network *nw, *nw_tmp;
	struct known_networks *nws = get_known_networks(wutui.ctrl);
	int i = 0;
	const int SECURITY_LEN = sizeof("Security") - 1;
	const int HIDDEN_LEN = sizeof("Hidden") - 1;
	const int PRIORITY_LEN = sizeof("Priority") - 1;
	const int AUTO_CONNECT_LEN = sizeof("Auto Connect") - 1;

	if (nws == NULL)
		diex("failed to retrieve known networks");

	sbuf_printf(sb,
	    "%*s│  %-*s  Security  Hidden  Priority  Auto Connect  │\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN, "SSID");

	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (i == 13)
			break;
		i++;

		sbuf_printf(sb, "%*s│ %s%-*s  %-*s  %-*s  %*d  %-*s  │\r\n",
		    MARGIN, "", nw->state == KN_CURRENT ? ">" : " ",
		    IEEE80211_NWID_LEN, nw->ssid, SECURITY_LEN,
		    security_to_string[known_network_security(wutui.ctrl,
			nw->id)],
		    HIDDEN_LEN,
		    is_hidden_network(wutui.ctrl, nw->id) ? "Yes" : "No",
		    PRIORITY_LEN, get_network_priority(wutui.ctrl, nw->id),
		    AUTO_CONNECT_LEN,
		    nw->state == KN_ENABLED	? "Yes" :
			nw->state == KN_CURRENT ? "Current" :
						  "No");
	}

	for (; i != 13; i++)
		sbuf_printf(sb, "%*s│%*s│\r\n", MARGIN, "", MAX_COLS - 2, "");

	free_known_networks(nws);
}

static void
render_network_scan(struct sbuf *sb)
{
	struct scan_result *sr, *sr_tmp;
	struct scan_results *srs = get_scan_results(wutui.ctrl);
	int i = 0;
	const int SECURITY_LEN = sizeof("Security") - 1;
	const int SIGNAL_LEN = sizeof("Signal") - 1;
	const int FREQ_LEN = sizeof("5180") - 1;

	if (srs == NULL)
		diex("failed to retrieve scan results");

	sbuf_printf(sb,
	    "%*s│  %-*s      Security      Signal      Frequency   │\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN, "SSID");

	STAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
		if (i == 13)
			break;
		i++;

		sbuf_printf(sb,
		    "%*s│  %-*s      %-*s      %*d      %-*d MHz    │\r\n",
		    MARGIN, "", IEEE80211_NWID_LEN, sr->ssid, SECURITY_LEN,
		    security_to_string[sr->security], SIGNAL_LEN, sr->signal,
		    FREQ_LEN, sr->freq);
	}

	for (; i != 13; i++)
		sbuf_printf(sb, "%*s│%*s│\r\n", MARGIN, "", MAX_COLS - 2, "");

	free_scan_results(srs);
}

static void
heading(struct sbuf *sb, const char *text, bool is_top)
{
	int len = strlen(text) + 3; /* == len(─┐%s┌) */
	const char *left_corner = is_top ? "╭" : "├";
	const char *right_corner = is_top ? "╮" : "┤";

	sbuf_printf(sb, "%*s%s", MARGIN, "", left_corner);
	sbuf_printf(sb, "─┐%s┌", text);
	for (int i = 0; i < MAX_COLS - 2 - len; i++)
		sbuf_cat(sb, "─");
	sbuf_printf(sb, "%s\r\n", right_corner);
}

static int
fetch_cursor_position(unsigned short *row, unsigned short *col)
{
	char buf[32] = "";

	if (dprintf(wutui.tty, CURSOR_POS) < 0)
		return (-1);

	/* Reply: ESC[<row>;<col>R */
	for (size_t i = 0; i < sizeof(buf) - 1; i++) {
		if (read(wutui.tty, &buf[i], 1) != 1 || buf[i] == 'R')
			break;
	}

	if (buf[0] != CSI[0] || buf[1] != CSI[1] ||
	    sscanf(&buf[2], "%hd;%hd", row, col) != 2)
		return (-1);

	return (0);
}

static int
fetch_winsize(void)
{
	if (ioctl(wutui.tty, TIOCGWINSZ, &wutui.winsize) == -1 ||
	    wutui.winsize.ws_col == 0) {
		if (dprintf(wutui.tty, CURSOR_FORWARD(999) CURSOR_DOWN(999)) <
		    0)
			return (-1);
		return (fetch_cursor_position(&wutui.winsize.ws_row,
		    &wutui.winsize.ws_col));
	}

	return (0);
}

static void
on_sig_winch(int signo)
{
	(void)signo;
	if (fetch_winsize() == -1)
		die("failed to fetch terminal winsize");
}

static void
disable_raw_mode(void)
{
	if (tcsetattr(wutui.tty, TCSAFLUSH, &wutui.cooked) == -1)
		err(EXIT_FAILURE, "tcsetattr()");
}

static void
enter_raw_mode(void)
{
	struct termios raw = wutui.cooked;

	raw.c_iflag &= ~(BRKINT | INPCK | ISTRIP | ICRNL | IXON);
	raw.c_oflag &= ~(OPOST);
	raw.c_cflag |= CS8;
	raw.c_lflag &= ~(ECHO | ISIG | ICANON | IEXTEN);
	raw.c_cc[VTIME] = raw.c_cc[VMIN] = 0;

	if (tcsetattr(wutui.tty, TCSAFLUSH, &raw) == -1)
		err(EXIT_FAILURE, "tcsetattr()");
}

static void
enter_alt_buffer(void)
{
	if (dprintf(wutui.tty, ALT_BUF_ON CURSOR_HIDE) < 0)
		die("dprintf");
}

static void
leave_alt_buffer(void)
{
	dprintf(wutui.tty, ALT_BUF_OFF CURSOR_SHOW);
}

void
die(const char *fmt, ...)
{
	leave_alt_buffer();

	va_list ap;
	va_start(ap, fmt);
	verr(EXIT_FAILURE, fmt, ap);
	va_end(ap);
}

void
diex(const char *fmt, ...)
{
	leave_alt_buffer();

	va_list ap;
	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
	va_end(ap);
}

static int
read_key(void)
{
	int nread;
	char c;

	while ((nread = read(wutui.tty, &c, 1)) != 1) {
		if (nread == -1 && errno != EAGAIN)
			die("read");
	}

	return (c);
}

static void
handle_input(void)
{
	int c = read_key();

	switch (c) {
	case 'q':
		leave_alt_buffer();
		exit(EXIT_SUCCESS);
		break;
	default:
		break;
	}
}

static void
handle_wpa_event(void)
{
	char buf[4096];
	int len = recv(wutui.wpa_fd, buf, sizeof(buf) - 1, 0);

	if (len == -1)
		die("recv(wpa_fd)");
	else if (len == 0)
		die("wpa ctrl interface socket closed");

	buf[len] = '\0';
}
