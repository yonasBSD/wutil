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
#include <readpassphrase.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <wpa_ctrl.h>

#include "interface.h"
#include "usage.h"
#include "utils.h"
#include "ieee80211.h"

typedef int (*cmd_handler_f)(int argc, char **argv);

struct command {
	const char *name;
	cmd_handler_f handler;
};

static int cmd_help(int argc, char **argv);
static int cmd_enable(int argc, char **argv);
static int cmd_disable(int argc, char **argv);
static int cmd_restart(int argc, char **argv);
static int cmd_scan(int argc, char **argv);
static int cmd_disconnect(int argc, char **argv);
static int cmd_connect(int argc, char **argv);

static struct command old_commands[] = {
	{ "help", cmd_help },
	{ "enable", cmd_enable },
	{ "disable", cmd_disable },
	{ "restart", cmd_restart },
	{ "scan", cmd_scan },
	{ "disconnect", cmd_disconnect },
	{ "connect", cmd_connect },
};

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
	(void)argc;
	(void)argv;
	return (0);
}

static int
cmd_help(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	usage(stdout);
	return (0);
}

static int
cmd_enable(int argc, char **argv)
{
	const char *interface_name = parse_interface_arg(argc, argv, 3);

	if (interface_name == NULL)
		return (1);

	return (enable_interface(interface_name));
}

static int
cmd_disable(int argc, char **argv)
{
	char *interface_name = parse_interface_arg(argc, argv, 3);

	if (interface_name == NULL)
		return (1);

	return (disable_interface(interface_name));
}

static int
cmd_restart(int argc, char **argv)
{
	char *interface_name = parse_interface_arg(argc, argv, 3);

	if (interface_name == NULL)
		return (1);

	return (restart_interface(interface_name));
}

static int
cmd_scan(int argc, char **argv)
{
	const char *ifname = parse_interface_arg(argc, argv, 3);
	struct scan_results *srs = NULL;
	struct scan_result *sr, *sr_tmp;
	struct wpa_ctrl *ctrl;

	if (ifname == NULL)
		return (1);

	ctrl = wpa_ctrl_open(wpa_ctrl_default_path(ifname));
	if (ctrl == NULL) {
		warn("failed to open wpa_ctrl interface");
		return (1);
	}

	if (scan_and_wait_wpa(ctrl) != 0) {
		warnx("scan failed");
		return (1);
	}

	if ((srs = get_scan_results(ctrl)) == NULL) {
		warnx("failed to retrieve scan results");
		return (1);
	}

	printf("%-20.20s %-9.9s %6s %s\n", "SSID", "SIGNAL", "FREQUENCY",
	    "CAPABILITIES");
	STAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
		char signal_str[9];

		snprintf(signal_str, sizeof(signal_str), "%d dBm", sr->signal);
		printf("%-20.20s %-9s %6d  %s\n", sr->ssid, signal_str,
		    sr->freq, sr->flags);
	}

	free_scan_results(srs);

	return (0);
}

static int
cmd_disconnect(int argc, char **argv)
{
	int ret = 0;
	char reply[4096];
	size_t reply_len = sizeof(reply);
	const char *wpa_ctrl_path;
	struct wpa_ctrl *ctrl;
	const char *ifname = parse_interface_arg(argc, argv, 3);

	if (ifname == NULL)
		return (1);

	wpa_ctrl_path = wpa_ctrl_default_path(ifname);
	ctrl = wpa_ctrl_open(wpa_ctrl_path);
	if (ctrl == NULL) {
		warn("failed to open wpa_supplicant ctrl_interface, %s",
		    wpa_ctrl_path);
		return (1);
	}

	if (wpa_ctrl_request(ctrl, "DISCONNECT", strlen("DISCONNECT"), reply,
		&reply_len, NULL) != 0) {
		warnx("failed to disconnect");
		ret = 1;
	}

	wpa_ctrl_close(ctrl);

	return (ret);
}

static int
cmd_connect(int argc, char **argv)
{
	int ret = 0;
	int nwid = -1;
	struct scan_results *srs = NULL;
	struct scan_result *sr, *sr_tmp;
	struct known_networks *nws = NULL;
	struct known_network *nw, *nw_tmp;
	struct wpa_ctrl *ctrl;
	char *ssid, *ifname = parse_interface_arg(argc, argv, 4);

	if (ifname == NULL)
		return (1);

	if (argc < 4) {
		warnx("<ssid> not provided");
		return (1);
	}
	ssid = argv[3];

	ctrl = wpa_ctrl_open(wpa_ctrl_default_path(ifname));
	if (ctrl == NULL) {
		warn("failed to open wpa_ctrl interface");
		return (1);
	}

	if (scan_and_wait_wpa(ctrl) != 0) {
		warnx("scan failed");
		ret = 1;
		goto cleanup;
	}

	if ((srs = get_scan_results(ctrl)) == NULL) {
		warnx("failed to retrieve scan results");
		ret = 1;
		goto cleanup;
	}

	STAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
		if (strcmp(sr->ssid, ssid) == 0)
			break;
	}

	if (sr == NULL) {
		warnx("SSID unavailable");
		ret = 1;
		goto cleanup;
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		goto cleanup;
	}

	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0) {
			nwid = nw->id;
			break;
		}
	}

	if (nwid == -1) {
		if ((nwid = add_network(ctrl, sr)) == -1) {
			warnx("failed to create new network");
			goto cleanup;
		}

		if (strstr(sr->flags, "PSK") !=
		    NULL) { /* TODO: cleanup & check psk length */
			char psk[256] = "";

			if (argc == 5)
				strlcpy(psk, argv[4], sizeof(psk));
			else
				readpassphrase("network password: ", psk,
				    sizeof(psk), RPP_REQUIRE_TTY);

			ret = configure_psk(ctrl, nwid, psk);
		} else {
			ret = configure_ess(ctrl, nwid);
		}

		if (ret != 0) {
			warnx("failed to configure key_mgmt");
			goto cleanup;
		}
	}

	if ((ret = select_network(ctrl, nwid)) != 0) {
		warnx("failed to select network");
	} else {
		ret = update_config(ctrl);
	}

cleanup:
	free_scan_results(srs);
	free_known_networks(nws);

	wpa_ctrl_close(ctrl);

	return (ret);
}

int
main(int argc, char *argv[])
{
	struct command *cmd = NULL;

	(void)old_commands;

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
