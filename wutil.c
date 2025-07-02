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

#include <getopt.h>
#include <libifconfig.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "usage.h"
#include "utils.h"

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

static char *parse_interface_arg(int argc, char **argv);
static void read_password(char *buffer, size_t size, const char *prompt_format,
    ...);

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
	regex_t regex;
	struct {
		regex_t *ignore;
		char *ifname;
	} data = { &regex, NULL };

	if (argc > 2) {
		fprintf(stderr, "bad value %s\n", argv[2]);
		return (1);
	}

	if (regcomp_ignored_ifaces(data.ignore) != 0)
		return (1);

	lifh = ifconfig_open();
	if (lifh == NULL) {
		fprintf(stderr, "Failed to open libifconfig handle.\n");
		return (1);
	}

	printf("%-10s %-12s %-20s\n", "NAME", "STATE", "CONNECTED SSID");
	if (ifconfig_foreach_iface(lifh, print_interface, &data) != 0) {
		fprintf(stderr, "Failed to get network interfaces.\n");
		ret = 1;
	}

	regfree(data.ignore);
	ifconfig_close(lifh);

	return (ret);
}

static char *
parse_interface_arg(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "<interface> not provided\n");
		return (NULL);
	}

	if (argc > 3) {
		fprintf(stderr, "bad value %s\n", argv[3]);
		return (NULL);
	}

	if (!is_valid_interface(argv[2])) {
		fprintf(stderr, "unknown interface %s\n", argv[2]);
		return (NULL);
	}

	return (argv[2]);
}

static int
cmd_show(int argc, char **argv)
{
	int ret = 0;
	char *interface_name = parse_interface_arg(argc, argv);
	struct ifconfig_handle *lifh;
	struct {
		regex_t *ignore;
		char *ifname;
	} data = { NULL, interface_name };

	if (interface_name == NULL)
		return (1);

	lifh = ifconfig_open();
	if (lifh == NULL) {
		fprintf(stderr, "Failed to open libifconfig handle.\n");
		return (1);
	}

	if (ifconfig_foreach_iface(lifh, print_interface, &data) != 0) {
		fprintf(stderr, "Failed to get network interfaces.\n");
		ret = 1;
	}

	ifconfig_close(lifh);
	return (ret);
}

static int
cmd_enable(int argc, char **argv)
{
	const char *interface_name = parse_interface_arg(argc, argv);

	if (interface_name == NULL)
		return (1);

	return (enable_interface(interface_name));
}

static int
cmd_disable(int argc, char **argv)
{
	char *interface_name = parse_interface_arg(argc, argv);

	if (interface_name == NULL)
		return (1);

	return (disable_interface(interface_name));
}

static int
cmd_restart(int argc, char **argv)
{
	char *interface_name = parse_interface_arg(argc, argv);

	if (interface_name == NULL)
		return (1);

	return (restart_interface(interface_name));
}

static int
cmd_scan(int argc, char **argv)
{
	const char *interface_name = parse_interface_arg(argc, argv);
	struct wifi_network_list *networks;
	struct wifi_network *network;

	if (interface_name == NULL)
		return (1);

	int rt_sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (rt_sockfd < 0) {
		perror("socket(PF_ROUTE)");
		return (1);
	}
	scan_and_wait(rt_sockfd, interface_name);
	networks = get_scan_results(rt_sockfd, interface_name);
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

	free_wifi_networks_list(networks);
	return (0);
}

static int
cmd_configure(int argc, char **argv)
{
	char *interface_name;
	struct network_configuration *config;
	int ret = 0;

	if (argc < 3) {
		fprintf(stderr, "<interface> not provided\n");
		return (1);
	}

	interface_name = argv[2];
	if (!is_valid_interface(interface_name)) {
		fprintf(stderr, "unknown interface %s\n", interface_name);
		return (1);
	}

	config = generate_network_configuration(argc - 2, argv + 2);
	if (config == NULL)
		return (1);

	printf("applying the following changes:\n");
	printf("interface: %s\n", interface_name);
	if (config->method != UNCHANGED)
		printf("method: %s\n",
		    config->method == DHCP ? "dhcp" : "manual");
	if (config->ip)
		printf("IP: %s\n", config->ip);
	if (config->netmask)
		printf("netmask: %s\n", config->netmask);
	if (config->gateway)
		printf("gateway: %s\n", config->gateway);
	if (config->dns1)
		printf("DNS1: %s\n", config->dns1);
	if (config->dns2)
		printf("DNS2: %s\n", config->dns2);
	if (config->search_domain)
		printf("search domain: %s\n", config->search_domain);

	ret = configure_nic(interface_name, config);
	free_network_configuration(config);

	return (ret);
}

static int
cmd_disconnect(int argc, char **argv)
{
	char *interface_name = parse_interface_arg(argc, argv);
	struct network_interface *interface;

	if (interface_name == NULL)
		return (1);

	interface = get_network_interface_by_name(interface_name);
	if (interface->state != CONNECTED) {
		fprintf(stderr, "%s is not connected\n", interface_name);
		return (1);
	}

	return (disconnect_network_interface(interface->name));
}

static void
read_password(char *buffer, size_t size, const char *prompt_format, ...)
{
	struct termios oldt, newt;

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;

	newt.c_lflag &= ~(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	va_list args;
	va_start(args, prompt_format);
	vprintf(prompt_format, args);
	va_end(args);

	if (fgets(buffer, size, stdin) == NULL) {
		perror("error reading password");
		buffer[0] = '\0';
	}

	buffer[strcspn(buffer, "\n")] = '\0';

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	printf("\n");
}

static int
cmd_connect(int argc, char **argv)
{
	int status;
	char *interface_name, *ssid;
	struct network_interface *interface;
	struct wifi_network *network;

	if (argc < 3) {
		fprintf(stderr, "<interface> not provided\n");
		return (1);
	}

	interface_name = argv[2];
	interface = get_network_interface_by_name(interface_name);
	if (interface == NULL) {
		fprintf(stderr, "unavailable interface %s\n", interface_name);
		return (1);
	}

	if (argc < 4) {
		fprintf(stderr, "<ssid> not provided\n");
		return (1);
	}

	ssid = argv[3];
	network = get_wifi_network_by_ssid(interface_name, ssid);
	if (network == NULL) {
		fprintf(stderr, "network '%s' is unavailable on %s\n", ssid,
		    interface_name);
		return (1);
	}

	if (!is_ssid_configured(ssid)) {
		char password[256] = "";

		if (argv[4] != NULL)
			strncpy(password, argv[4], sizeof(password) - 1);
		else if (is_wifi_network_secured(network))
			read_password(password, sizeof(password),
			    "enter password for %s: ", ssid);
		password[sizeof(password) - 1] = '\0';

		if (configure_wifi_network(network, password) != 0) {
			printf("failed to configure '%s'\n", ssid);
			free_wifi_network(network);
			return (1);
		}
	}
	free_wifi_network(network);

	status = connect_to_ssid(interface_name, ssid);
	printf(status == 0 ? "connected to '%s'\n" :
			     "failed to connect to '%s'\n",
	    ssid);

	return (status);
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

	fprintf(stderr, "unsupported command '%s'\n", argv[1]);
	usage(argv[0]);

	return (1);
}
