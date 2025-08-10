/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/pciio.h>

#include <err.h>
#include <getopt.h>
#include <ifaddrs.h>
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
static int cmd_known_network(int argc, char *argv[]);
static int cmd_station(int argc, char *argv[]);

static int cmd_interfaces(int argc, char **argv);
static int cmd_interface(int argc, char **argv);

static void list_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);

static struct command commands[] = {
	{ "help", cmd_help },
	{ "interfaces", cmd_interfaces },
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
			usage(stdout);
			exit(EXIT_SUCCESS);
		case '?':
		default:
			usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	optreset = 1;
	optind = 1;

	if (argc == 0) {
		usage(stderr);
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

static int
cmd_interfaces(int argc, char **argv)
{
	struct ifconfig_handle *lifh = NULL;
	int ret = 0;

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((lifh = ifconfig_open()) == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	printf("%-*s %-17s %-4s %-*s %-12s\n", IFNAMSIZ, "Interface", "MAC",
	    "State", PCI_MAXNAMELEN, "Device", "Connection");
	if (ifconfig_foreach_iface(lifh, list_interface, NULL) != 0) {
		warnx("failed to get network interfaces");
		ret = 1;
		goto cleanup;
	}

cleanup:
	ifconfig_close(lifh);

	return (ret);
}

static int
cmd_interface(int argc, char **argv)
{
	int ret = 0;
	struct ifconfig_handle *lifh = NULL;
	const char *ifname = NULL;

	if (argc < 2) {
		warnx("<interface> not provided");
		return (1);
	}

	if (if_nametoindex(argv[1]) == 0) { /* returns 0 if invalid i.e false */
		warnx("unknown interface %s", argv[1]);
		return (1);
	}

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((lifh = ifconfig_open()) == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	ifname = argv[1];
	if (!is_wlan_group(lifh, ifname)) {
		warnx("invalid interface %s", argv[1]);
		ret = 1;
		goto cleanup;
	}

	if (ifconfig_foreach_iface(lifh, show_interface, &ifname) != 0) {
		warnx("failed to get network interfaces");
		ret = 1;
		goto cleanup;
	}

cleanup:
	ifconfig_close(lifh);

	return (ret);
}

static void
list_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa, void *udata)
{
	enum connection_state status;
	const char *state = (ifa->ifa_flags & IFF_UP) ? "Up" : "Down";
	char device[PCI_MAXNAMELEN + 1];
	char mac[18];
	struct ether_addr ea = { 0 };
	struct ifgroupreq ifgr;

	(void)udata;

	if (!is_wlan_group(lifh, ifa->ifa_name))
		return;

	status = get_connection_state(lifh, ifa);

	if (get_iface_parent(ifa->ifa_name, strlen(ifa->ifa_name), device,
		sizeof(device)) != 0)
		device[0] = '\0';

	if (ifconfig_get_groups(lifh, ifa->ifa_name, &ifgr) == -1)
		return;

	ifconfig_foreach_ifaddr(lifh, ifa, get_mac_addr, &ea);

	if (ether_ntoa_r(&ea, mac) == NULL)
		strcpy(mac, "N/A");

	printf("%-*s %-17s %-5s %-*s %-12s\n", IFNAMSIZ, ifa->ifa_name, mac,
	    state, PCI_MAXNAMELEN, device, connection_state_to_string[status]);
}
