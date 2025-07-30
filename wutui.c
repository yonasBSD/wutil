/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/types.h>
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
	int tty, kq;
	struct termios cooked;
	struct wpa_ctrl *ctrl;
	struct winsize winsize;
};

static struct wutui wutui;

static void parse_args(int argc, char *argv[], const char **ctrl_path);

static void init_wutui(const char *ctrl_path);
static void deinit_wutui(void);
static void event_loop(void);

static int fetch_cursor_position(short *row, short *col);
static int fetch_winsize(void);
static void on_sig_winch(int signo);

static void disable_raw_mode(void);
static void enter_raw_mode(void);
static void enter_alt_buffer(void);
static void leave_alt_buffer(void);

void die(const char *, ...);
void diex(const char *, ...);

static int read_key(void);
static void process_keypress(void);

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
	wutui.tty = wutui.kq = -1;
	struct sigaction sa = { 0 };

	atexit(deinit_wutui);

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
	int wpa_fd = wpa_ctrl_get_fd(wutui.ctrl);
	struct kevent events[2], tevent;

	if (wpa_fd == -1)
		die("invalid wpa_ctrl socket");

	EV_SET(&events[0], wutui.tty, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&events[1], wpa_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(wutui.kq, events, 2, NULL, 0, NULL) == -1)
		die("kevent register");

	for (;;) {
		int nev = kevent(wutui.kq, NULL, 0, &tevent, 1, NULL);

		if (nev == -1) {
			if (errno == EINTR)
				continue;
			die("kevent wait");
		}

		if (nev > 0 && tevent.flags & EV_ERROR)
			diex("event error: %s", strerror(tevent.data));

		if (tevent.ident == (uintptr_t)wutui.tty) {
			process_keypress();
		} else if (tevent.ident == (uintptr_t)wpa_fd) {
			char buf[4096];
			int len = recv(wpa_fd, buf, sizeof(buf) - 1, 0);

			if (len == -1)
				die("recv(wpa_fd)");
			else if (len == 0)
				die("wpa ctrl interface socket closed");

			buf[len] = '\0';
			dprintf(wutui.tty,
			    COLOR(BG_BRIGHT, RED) COLOR(FG, YELLOW)
				ERASE_IN_LINE(
				    ERASE_TO_BEGINNING) "%s\r\n" RESET_SGR,
			    buf);
		}
	}
}

static int
fetch_cursor_position(short *row, short *col)
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
	if (dprintf(wutui.tty,
		ALT_BUF_ON CURSOR_HIDE ERASE_IN_DISPLAY(ERASE_ENTIRE)
		    CURSOR_MOVE(1, 1)) < 0)
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
process_keypress(void)
{
	int c = read_key();

	switch (c) {
	case 'q':
		leave_alt_buffer();
		exit(EXIT_SUCCESS);
		break;
	default:
		dprintf(wutui.tty,
		    ERASE_IN_LINE(ERASE_TO_BEGINNING) "key: %c\r\n", c);
		break;
	}
}
