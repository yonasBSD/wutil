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

#include <err.h>
#include <getopt.h>
#include <libifconfig.h>
#include <readpassphrase.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "usage.h"
#include "utils.h"
#include "wpa_ctrl.h"

typedef int (*cmd_handler_f)(int argc, char **argv);

struct command {
	const char *name;
	cmd_handler_f handler;
};

static int cmd_help(int argc, char **argv);
static int cmd_list(int argc, char **argv);
static int cmd_show(int argc, char **argv);
static int cmd_enable(int argc, char **argv);
static int cmd_disable(int argc, char **argv);
static int cmd_restart(int argc, char **argv);
static int cmd_scan(int argc, char **argv);
static int cmd_configure(int argc, char **argv);
static int cmd_disconnect(int argc, char **argv);
static int cmd_connect(int argc, char **argv);

static const struct command commands[] = {
	{ "help", cmd_help },
	{ "list", cmd_list },
	{ "show", cmd_show },
	{ "enable", cmd_enable },
	{ "disable", cmd_disable },
	{ "restart", cmd_restart },
	{ "scan", cmd_scan },
	{ "configure", cmd_configure },
	{ "disconnect", cmd_disconnect },
	{ "connect", cmd_connect },
	{ NULL, NULL },
};

static char *parse_interface_arg(int argc, char **argv, int max_argc);

static int
cmd_help(int argc, char **argv)
{
	(void)argc;
	usage(argv[0]);
	return (0);
}

static int
cmd_list(int argc, char **argv)
{
	int ret = 0;
	struct ifconfig_handle *lifh;
	regex_t ignore;

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if (regcomp_ignored_ifaces(&ignore) != 0)
		return (1);

	lifh = ifconfig_open();
	if (lifh == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	printf("%-10s %-12s %-20s\n", "NAME", "STATE", "CONNECTED SSID");
	if (ifconfig_foreach_iface(lifh, print_interface, &ignore) != 0) {
		warnx("failed to get network interfaces");
		ret = 1;
	}

	regfree(&ignore);
	ifconfig_close(lifh);

	return (ret);
}

static char *
parse_interface_arg(int argc, char **argv, int max_argc)
{
	if (argc < 3) {
		warnx("<interface> not provided");
		return (NULL);
	}

	if (!is_valid_interface(argv[2])) {
		warnx("unknown interface %s", argv[2]);
		return (NULL);
	}

	if (argc > max_argc) {
		warnx("bad value %s", argv[3]);
		return (NULL);
	}

	return (argv[2]);
}

static int
cmd_show(int argc, char **argv)
{
	int ret = 0;
	struct ifconfig_handle *lifh;
	struct network_interface iface = { 0 };

	iface.name = parse_interface_arg(argc, argv, 3);
	if (iface.name == NULL)
		return (1);

	lifh = ifconfig_open();
	if (lifh == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	ret = ifconfig_foreach_iface(lifh, retrieve_interface, &iface);
	ifconfig_close(lifh);

	if (ret != 0) {
		warnx("failed to get network interfaces");
		return (ret);
	}

	printf("%-10s %-12s %-20s\n", iface.name,
	    connection_state_to_string[iface.state], iface.connected_ssid);

	return (ret);
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
	const char *interface_name = parse_interface_arg(argc, argv, 3);
	struct wifi_network_list *networks;
	struct wifi_network *network;

	if (interface_name == NULL)
		return (1);

	int rt_sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (rt_sockfd == -1) {
		perror("socket(PF_ROUTE)");
		return (1);
	}
	scan_and_wait_ioctl(rt_sockfd, interface_name);
	networks = get_scan_results_ioctl(rt_sockfd, interface_name);
	close(rt_sockfd);

	if (networks == NULL)
		return (1);

	printf("%-20.20s %-9.9s %6s %s\n", "SSID", "SIGNAL", "CHANNEL",
	    "CAPABILITIES");
	STAILQ_FOREACH(network, networks, next) {
		char signal_str[9];

		snprintf(signal_str, sizeof(signal_str), "%d dBm",
		    network->signal_dbm);
		printf("%-20.20s %-9s %6d  %s\n", network->ssid, signal_str,
		    network->channel, network->capabilities);
	}

	free_wifi_network_list(networks);
	return (0);
}

static int
cmd_configure(int argc, char **argv)
{
	char *interface_name;
	struct network_configuration config = { 0 };
	if (argc < 3) {
		warnx("<interface> not provided");
		return (1);
	}

	interface_name = argv[2];
	if (!is_valid_interface(interface_name)) {
		warnx("unknown interface %s", interface_name);
		return (1);
	}

	if (parse_network_config(argc - 2, argv + 2, &config) != 0)
		return (1);

	return (configure_nic(interface_name, &config));
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
	struct scan_results *srs;
	struct scan_result *sr, *sr_tmp;
	struct known_networks *nws;
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

	ctrl = wpa_ctrl_open(wpa_ctrl_default_path(argv[1]));
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

	if ((ret = select_network(ctrl, nwid)) != 0)
		warnx("failed to select network");

cleanup:
	free_scan_results(srs);
	free_known_networks(nws);

	wpa_ctrl_close(ctrl);

	return (ret);
}

int
main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return (1);
	}

	for (const struct command *cmd = commands; cmd->name != NULL; cmd++) {
		if (strcmp(argv[1], cmd->name) == 0)
			return (cmd->handler(argc, argv));
	}

	warnx("unsupported command '%s'", argv[1]);
	usage(argv[0]);

	return (1);
}
