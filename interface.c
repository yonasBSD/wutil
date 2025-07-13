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
#include <regex.h>
#include <stdio.h>

#include "interface.h"
#include "utils.h"

struct interface_command interface_cmds[3] = {
	{ "list", cmd_interface_list },
	{ "show", cmd_interface_show },
	{ "set", cmd_interface_set },
};

int
cmd_interface_list(struct ifconfig_handle *lifh, int argc, char **argv)
{
	int ret = 0;
	regex_t ignore;

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if (regcomp_ignored_ifaces(&ignore) != 0)
		return (1);

	printf("%-10s %-12s %-20s\n", "NAME", "STATE", "CONNECTED SSID");
	if (ifconfig_foreach_iface(lifh, print_interface, &ignore) != 0) {
		warnx("failed to get network interfaces");
		ret = 1;
	}

	regfree(&ignore);

	return (ret);
}

int
cmd_interface_show(struct ifconfig_handle *lifh, int argc, char **argv)
{
	int ret = 0;
	struct network_interface iface = { 0 };

	iface.name = parse_interface_arg(argc, argv, 3);
	if (iface.name == NULL)
		return (1);

	ret = ifconfig_foreach_iface(lifh, retrieve_interface, &iface);

	if (ret != 0) {
		warnx("failed to get network interfaces");
		return (ret);
	}

	printf("%-10s %-12s %-20s\n", iface.name,
	    connection_state_to_string[iface.state], iface.connected_ssid);

	return (ret);
}

int
cmd_interface_set(struct ifconfig_handle *lifh, int argc, char **argv)
{
	char *interface_name;
	struct network_configuration config = { 0 };

	(void)lifh;

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

char *
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
