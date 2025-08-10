/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
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

#include "interface.h"
#include "usage.h"
#include "wifi.h"

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
	{ "interfaces", cmd_interface },
	{ "interface", cmd_interface },

	{ "known-networks", cmd_known_network },
	{ "known-network", cmd_known_network },
	{ "forget", cmd_known_network },
	{ "set", cmd_known_network },

	{ "scan", cmd_station },
	{ "networks", cmd_station },
	{ "status", cmd_station },
	{ "disconnect", cmd_station },
	{ "connect", cmd_station },
};

static const char *ctrl_path = NULL;

static int
cmd_interface(int argc, char *argv[])
{
	struct interface_command *cmd = NULL;
	struct ifconfig_handle *lifh;
	int ret = 0;

	if ((lifh = ifconfig_open()) == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	for (size_t i = 0; i < nitems(interface_cmds); i++) {
		if (strcmp(*argv, interface_cmds[i].name) == 0) {
			cmd = &interface_cmds[i];
			break;
		}
	}

	ret = cmd->handler(lifh, argc, argv);

	ifconfig_close(lifh);

	return (ret);
}

static int
cmd_known_network(int argc, char *argv[])
{
	return (template_cmd_wpa(argc, argv, known_network_cmds,
	    nitems(known_network_cmds), ctrl_path));
}

static int
cmd_station(int argc, char *argv[])
{
	return (template_cmd_wpa(argc, argv, station_cmds, nitems(station_cmds),
	    ctrl_path));
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
	int opt = -1;
	struct option opts[] = {
		{ "ctrl-interface", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "+c:h", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			ctrl_path = optarg;
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

	argc -= optind;
	argv += optind;

	optreset = 1;
	optind = 1;

	if (argc == 0) {
		usage_tui(stderr);
		exit(EXIT_FAILURE);
	}

	if (ctrl_path == NULL &&
	    (ctrl_path = wpa_ctrl_default_path()) == NULL) {
		warn(
		    "no wpa ctrl interface on default path, provide --ctrl-interface");
		return (1);
	}

	for (size_t i = 0; i < nitems(commands); i++) {
		if (strcmp(*argv, commands[i].name) == 0) {
			cmd = &commands[i];
			break;
		}
	}

	if (cmd == NULL) {
		warnx("Unknown command: %s", argv[1]);
		usage(stderr);
		return (EXIT_FAILURE);
	}

	return (cmd->handler(argc, argv));
}
