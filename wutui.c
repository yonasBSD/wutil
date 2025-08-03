/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/queue_mergesort.h>
#include <sys/sbuf.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
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
	enum { SECTION_KN = 0, SECTION_NS } current_section;
	int current_kn, current_sr;
	int kn_offset, sr_offset;
	struct supplicant_status *status;
	struct scan_results *srs;
	int srs_len;
	struct known_networks *kns;
	int kns_len;
};

enum wutui_key {
	ARROW_UP = 127,
	ARROW_DOWN,
};

static struct wutui wutui;

static const int MAX_COLS = 80;
static const int MAX_ROWS = 36;
static const int KN_ENTRIES = 13;
static const int SR_ENTRIES = 13;

#define MARGIN			   ((wutui.winsize.ws_col - MAX_COLS) / 2)

#define WRAPPED_INCR(var, max)	   ((var) = ((var) + 1) % (max))
#define WRAPPED_DECR(var, max)	   ((var) = ((var) - 1 + (max)) % (max))

#define CLAMP(val, minval, maxval) MAX((minval), MIN((val), (maxval)))

static void parse_args(int argc, char *argv[], const char **ctrl_path);

static void init_wutui(const char *ctrl_path);
static void deinit_wutui(void);
static void event_loop(void);

static void render_tui(void);
static void render_wifi_info(struct sbuf *sb);
static void render_known_networks(struct sbuf *sb);
static void render_network_scan(struct sbuf *sb);

static void heading(struct sbuf *sb, const char *text, bool is_top);
static const char *signal_bars(int dbm);

static const char *right_corner_block(int pos, int max_entries, int scrollbar);
static int get_scrollbar_pos(int offset, int entries, int max_entries);

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

	if ((wutui.status = get_supplicant_status(wutui.ctrl)) == NULL)
		errx(EXIT_FAILURE, "failed retrieve wpa_supplicant status");

	if ((wutui.kns = get_known_networks(wutui.ctrl)) == NULL)
		errx(EXIT_FAILURE, "failed to retrieve known networks");
	wutui.kns_len = known_networks_len(wutui.kns);

	if ((wutui.srs = get_scan_results(wutui.ctrl)) == NULL)
		errx(EXIT_FAILURE, "failed to retrieve scan results");
	remove_hidden_networks(wutui.srs);
	wutui.srs_len = scan_results_len(wutui.srs);

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

	free_supplicant_status(wutui.status);
	free_known_networks(wutui.kns);
	free_scan_results(wutui.srs);

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

		render_wifi_info(sb);
		render_known_networks(sb);
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
	const int FREQ_LEN = sizeof("5180") - 1;
	/* wpa state with max len*/
	const int WPA_STATE_LEN = sizeof("INTERFACE_DISABLED") - 1;
	const int IP_LEN = sizeof("255.255.255.255") - 1;

	heading(sb, "WiFi Info", true);
	sbuf_printf(sb,
	    "%*s│  SSID:      %-*s    Frequency:  %*d MHz         │\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN,
	    wutui.status->ssid == NULL ? "N/A" : wutui.status->ssid, FREQ_LEN,
	    wutui.status->freq);
	sbuf_printf(sb,
	    "%*s│  WPA State: %-*s                  IP Address: %-*s  │\r\n",
	    MARGIN, "", WPA_STATE_LEN,
	    wutui.status->state == NULL ? "N/A" : wutui.status->state, IP_LEN,
	    wutui.status->ip_address == NULL ? "N/A" :
					       wutui.status->ip_address);
}

static void
render_known_networks(struct sbuf *sb)
{
	int i = 0, scrollbar = -1;
	const int SECURITY_LEN = sizeof("Security") - 1;
	const int HIDDEN_LEN = sizeof("Hidden") - 1;
	const int PRIORITY_LEN = sizeof("Priority") - 1;
	const int AUTO_CONNECT_LEN = sizeof("Auto Connect") - 1;
	struct known_network *kn, *kn_tmp;

	wutui.kn_offset = wutui.current_kn < wutui.kn_offset ?
	    wutui.current_kn :
	    wutui.current_kn - KN_ENTRIES + 1;
	scrollbar = get_scrollbar_pos(wutui.kn_offset, wutui.kns_len,
	    KN_ENTRIES);

	heading(sb,
	    wutui.current_section == SECTION_KN ? "<Known Networks>" :
						  "Known Networks",
	    false);

	sbuf_printf(sb,
	    "%*s│  " BOLD COLOR(FG,
		BLUE) "%-*s  Security  Hidden  Priority  Auto Connect" RESET_SGR
		      "  ↑\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN, "SSID");

	TAILQ_FOREACH_SAFE(kn, wutui.kns, next, kn_tmp) {
		if (i == KN_ENTRIES)
			break;

		sbuf_printf(sb,
		    "%*s│ %s%s%-*s  %-*s  %-*s  %*d  %-*s " RESET_SGR " %s\r\n",
		    MARGIN, "",
		    wutui.current_section == SECTION_KN &&
			    i == wutui.current_kn ?
			INVERT :
			"",
		    kn->state == KN_CURRENT ? ">" : " ", IEEE80211_NWID_LEN,
		    kn->ssid, SECURITY_LEN, security_to_string[kn->security],
		    HIDDEN_LEN, kn->hidden ? "Yes" : "No", PRIORITY_LEN,
		    kn->priority, AUTO_CONNECT_LEN,
		    kn->state == KN_ENABLED	? "Yes" :
			kn->state == KN_CURRENT ? "Current" :
						  "No",
		    right_corner_block(i, KN_ENTRIES, scrollbar));

		i++;
	}

	for (; i != KN_ENTRIES; i++)
		sbuf_printf(sb, "%*s│%*s%s\r\n", MARGIN, "", MAX_COLS - 2, "",
		    right_corner_block(i, KN_ENTRIES, scrollbar));
}

static void
render_network_scan(struct sbuf *sb)
{
	int i = 0, scrollbar = -1;
	const int SECURITY_LEN = sizeof("Security") - 1;
	const int SIGNAL_LEN = sizeof("Signal") - 1;
	const int FREQ_LEN = sizeof("5180") - 1;
	struct scan_result *sr, *sr_tmp;

	wutui.sr_offset = wutui.current_sr < wutui.sr_offset ?
	    wutui.current_sr :
	    wutui.current_sr - SR_ENTRIES + 1;
	scrollbar = get_scrollbar_pos(wutui.sr_offset, wutui.srs_len,
	    SR_ENTRIES);

	heading(sb,
	    wutui.current_section == SECTION_NS ? "<Network Scan>" :
						  "Network Scan",
	    false);
	sbuf_printf(sb,
	    "%*s│  " BOLD COLOR(FG,
		BLUE) "%-*s      Security      Signal      Frequency" RESET_SGR
		      "   ↑\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN, "SSID");

	TAILQ_FOREACH_SAFE(sr, wutui.srs, next, sr_tmp) {
		if (i == SR_ENTRIES)
			break;

		sbuf_printf(sb,
		    "%*s│ %s %-*s      %-*s       %-*s       %-*d MHz   " RESET_SGR
		    " %s\r\n",
		    MARGIN, "",
		    wutui.current_section == SECTION_NS &&
			    i == wutui.current_sr ?
			INVERT :
			"",
		    IEEE80211_NWID_LEN, sr->ssid, SECURITY_LEN,
		    security_to_string[sr->security], SIGNAL_LEN,
		    signal_bars(sr->signal), FREQ_LEN, sr->freq,
		    right_corner_block(i, SR_ENTRIES, scrollbar));

		i++;
	}

	for (; i != SR_ENTRIES; i++)
		sbuf_printf(sb, "%*s│%*s%s\r\n", MARGIN, "", MAX_COLS - 2, "",
		    right_corner_block(i, SR_ENTRIES, scrollbar));
}

static void
heading(struct sbuf *sb, const char *text, bool is_top)
{
	int len = strlen(text) + 3; /* == len(─┐%s┌) */
	const char *left_corner = is_top ? "╭" : "├";
	const char *right_corner = is_top ? "╮" : "┤";

	sbuf_printf(sb, "%*s%s", MARGIN, "", left_corner);
	sbuf_printf(sb, "─┐" BOLD "%s" RESET_SGR "┌", text);
	for (int i = 0; i < MAX_COLS - 2 - len; i++)
		sbuf_cat(sb, "─");
	sbuf_printf(sb, "%s\r\n", right_corner);
}

static const char *
signal_bars(int dbm)
{
	if (dbm >= -50)
		return ("▂▄▆█");
	if (dbm >= -60)
		return ("▂▄▆▁");
	if (dbm >= -70)
		return ("▂▄▁▁");
	if (dbm >= -80)
		return ("▂▁▁▁");
	return ("▁▁▁▁");
}

static const char *
right_corner_block(int pos, int max_entries, int scrollbar)
{
	return (pos == max_entries - 1 ? "↓" : pos == scrollbar ? "█" : " ");
}

static int
get_scrollbar_pos(int offset, int entries, int max_entries)
{
	int pos;
	double scroll_ratio;

	if (entries <= max_entries)
		return (-1);

	scroll_ratio = (double)offset / (entries - max_entries);
	pos = round(scroll_ratio * max_entries);

	return (CLAMP(pos, 0, max_entries - 1 /* down arrow */ - 1));
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

	if (c == ESC_CHAR) {
		char seq[3];

		if (read(wutui.tty, &seq[0], 1) != 1)
			return (c);
		if (read(wutui.tty, &seq[1], 1) != 1)
			return (c);

		if (seq[0] == CSI[1]) {
			switch (seq[1]) {
			case 'A':
				return (ARROW_UP);
			case 'B':
				return (ARROW_DOWN);
			}
		}
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
	case '\t':
		wutui.current_section = !wutui.current_section;
		break;
	case ARROW_DOWN:
	case 'j':
		if (wutui.current_section == SECTION_KN) {
			WRAPPED_INCR(wutui.current_kn, wutui.kns_len);
		} else {
			WRAPPED_INCR(wutui.current_sr, wutui.srs_len);
		}
		break;
	case ARROW_UP:
	case 'k':
		if (wutui.current_section == SECTION_KN) {
			WRAPPED_DECR(wutui.current_kn, wutui.kns_len);
		} else {
			WRAPPED_DECR(wutui.current_sr, wutui.srs_len);
		}
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
