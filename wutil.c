/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>

#include <err.h>
#include <getopt.h>
#include <libifconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <wpa_ctrl.h>

#include "ieee80211.h"
#include "interface.h"
#include "usage.h"

typedef int (*cmd_handler_f)(int argc, char **argv);

struct command {
	const char *name;
	cmd_handler_f handler;
};

static int cmd_help(int argc, char **argv);
static int cmd_interface(int argc, char *argv[]);
static int cmd_known_network(int argc, char *argv[]);
static int cmd_station(int argc, char *argv[]);

static struct command commands[] = {
	{ "help", cmd_help },

	{ "interface", cmd_interface },
	{ "if", cmd_interface },

	{ "known-network", cmd_known_network },
	{ "kn", cmd_known_network },

	{ "station", cmd_station },
	{ "sta", cmd_station },
};

static int
cmd_interface(int argc, char *argv[])
{
	struct interface_command *cmd;
	struct ifconfig_handle *lifh;
	int ret = 0;

	if (argc < 2) {
		warnx("wrong number of arguments");
		usage_interface(stderr, true);
		return (1);
	}

	for (size_t i = 0; i < nitems(interface_cmds); i++) {
		if (strcmp(argv[1], interface_cmds[i].name) == 0) {
			cmd = &interface_cmds[i];
			break;
		}
	}

	if (cmd == NULL) {
		warnx("Unknown subcommand: %s", argv[1]);
		usage_interface(stderr, true);
		return (1);
	}

	if ((lifh = ifconfig_open()) == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	ret = cmd->handler(lifh, argc, argv);

	ifconfig_close(lifh);

	return (ret);
}

static int
cmd_known_network(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return (0);
}

static int
cmd_station(int argc, char *argv[])
{
	int ret = 0;
	struct wpa_command *cmd = NULL;
	const char *wpa_ctrl_path = wpa_ctrl_default_path(
	    "wlan0"); /* TODO: rework */
	struct wpa_ctrl *ctrl = wpa_ctrl_open(wpa_ctrl_path);

	(void)argc;
	(void)argv;

	if (ctrl == NULL) {
		warn("failed to open wpa_supplicant ctrl_interface, %s",
		    wpa_ctrl_path);
		return (1);
	}

	if (argc < 2) {
		warnx("wrong number of arguments");
		usage_station(stderr, true);
		return (1);
	}

	for (size_t i = 0; i < nitems(station_cmds); i++) {
		if (strcmp(argv[1], station_cmds[i].name) == 0) {
			cmd = &station_cmds[i];
			break;
		}
	}

	ret = cmd->handler(ctrl, argc, argv);

	wpa_ctrl_close(ctrl);

	return (ret);
}

static int
cmd_help(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	usage(stdout);
	return (0);
}

int
main(int argc, char *argv[])
{
	struct command *cmd = NULL;

	if (argc < 2) {
		warnx("wrong number of arguments");
		usage(stderr);
		return (EXIT_FAILURE);
	}

	for (size_t i = 0; i < nitems(commands); i++) {
		if (strcmp(argv[1], commands[i].name) == 0) {
			cmd = &commands[i];
			break;
		}
	}

	if (cmd == NULL) {
		warnx("Unknown command: %s", argv[1]);
		usage(stderr);
		return (EXIT_FAILURE);
	}

	return (cmd->handler(--argc, ++argv));
}
