/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/event.h>
#include <sys/socket.h>

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <wpa_ctrl.h>

#include "ctl_seq.h"
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

static void cook_tty(void);
static void uncook_tty(void);
static void enter_alt_buffer(void);
static void leave_alt_buffer(void);

int
main(int argc, char *argv[])
{
	const char *ctrl_path = wpa_ctrl_default_path();

	parse_args(argc, argv, &ctrl_path);
	if (ctrl_path == NULL) {
		errx(EXIT_FAILURE,
		    "no wpa ctrl interface on default path, provide --ctrl-interface");
	}

	init_wutui(ctrl_path);

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

	atexit(deinit_wutui);

	if ((wutui.ctrl = wpa_ctrl_open(ctrl_path)) == NULL) {
		err(EXIT_FAILURE,
		    "failed to open wpa_supplicant ctrl_interface, %s",
		    ctrl_path);
	}

	if ((wutui.tty = open("/dev/tty", O_RDWR)) == -1)
		err(EXIT_FAILURE, "open(/dev/tty)");

	if (tcgetattr(wutui.tty, &wutui.cooked) == -1)
		err(EXIT_FAILURE, "tcgetattr()");

	uncook_tty();
}

static void
deinit_wutui(void)
{
	if (wutui.tty != -1)
		cook_tty();

	close(wutui.tty);
	close(wutui.kq);

	wpa_ctrl_close(wutui.ctrl);
}

static void
cook_tty(void)
{
	if (tcsetattr(wutui.tty, TCSAFLUSH, &wutui.cooked) == -1)
		err(EXIT_FAILURE, "tcsetattr()");

	leave_alt_buffer();
}

static void
uncook_tty(void)
{
	struct termios raw = wutui.cooked;

	raw.c_iflag &= ~(BRKINT | INPCK | ISTRIP | ICRNL | IXON);
	raw.c_oflag &= ~(OPOST);
	raw.c_cflag |= CS8;
	raw.c_lflag &= ~(ECHO | ISIG | ICANON | IEXTEN);
	raw.c_cc[VTIME] = raw.c_cc[VMIN] = 0;

	if (tcsetattr(wutui.tty, TCSAFLUSH, &raw) == -1)
		err(EXIT_FAILURE, "tcsetattr()");

	enter_alt_buffer();
}

static void
enter_alt_buffer(void)
{
	if (dprintf(wutui.tty,
		ALT_BUF_ON CURSOR_HIDE ERASE_IN_DISPLAY(ERASE_ENTIRE)
		    CURSOR_MOVE(1, 1)) < 0) {
		err(EXIT_FAILURE, "dprintf");
	}
}

static void
leave_alt_buffer(void)
{
	dprintf(wutui.tty, ALT_BUF_OFF CURSOR_SHOW);
}
