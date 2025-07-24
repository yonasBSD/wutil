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
	return (template_cmd_wpa(argc, argv, known_network_cmds,
	    nitems(known_network_cmds), usage_known_networks));
}

static int
cmd_station(int argc, char *argv[])
{
	return (template_cmd_wpa(argc, argv, station_cmds, nitems(station_cmds),
	    usage_station));
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
