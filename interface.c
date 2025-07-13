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

#include <sys/types.h>
#include <sys/pciio.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <err.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interface.h"
#include "libifconfig.h"
#include "utils.h"

struct interface_command interface_cmds[3] = {
	{ "list", cmd_interface_list },
	{ "show", cmd_interface_show },
	{ "set", cmd_interface_set },
};

static void list_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);
static void show_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);

static void get_mac_addr(ifconfig_handle_t *lifh, struct ifaddrs *ifa,
    void *udata);
static bool is_wlan_group(struct ifconfig_handle *lifh, const char *ifname);
static int get_iface_parent(const char *ifname, int ifname_len, char *buf,
    int buf_len);

int
cmd_interface_list(struct ifconfig_handle *lifh, int argc, char **argv)
{
	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	printf("%-*s %-17s %-4s %-*s %-12s\n", IFNAMSIZ, "Interface", "MAC",
	    "State", PCI_MAXNAMELEN, "Device", "Connection");
	if (ifconfig_foreach_iface(lifh, list_interface, NULL) != 0) {
		warnx("failed to get network interfaces");
		return (1);
	}

	return (0);
}

int
cmd_interface_show(struct ifconfig_handle *lifh, int argc, char **argv)
{
	const char *ifname = parse_interface_arg(argc, argv, 3);

	if (ifname == NULL)
		return (1);

	if (!is_wlan_group(lifh, argv[2])) {
		warnx("invalid interface %s", argv[2]);
		return (1);
	}

	if (ifconfig_foreach_iface(lifh, show_interface, &ifname) != 0) {
		warnx("failed to get network interfaces");
		return (1);
	}

	return (0);
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
	if (!is_wlan_group(lifh, interface_name)) {
		warnx("invalid interface %s", interface_name);
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

	if (if_nametoindex(argv[2]) == 0) { /* returns 0 if invalid i.e false */
		warnx("unknown interface %s", argv[2]);
		return (NULL);
	}

	if (argc > max_argc) {
		warnx("bad value %s", argv[3]);
		return (NULL);
	}

	return (argv[2]);
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

static void
print_ifaddr(ifconfig_handle_t *lifh, struct ifaddrs *ifa, void *udata __unused)
{
	struct ether_addr ea = { 0 };
	struct ifconfig_inet_addr inet;
	struct ifconfig_inet6_addr inet6;
	char addr_buf[INET6_ADDRSTRLEN];

	switch (ifa->ifa_addr->sa_family) {
	case AF_INET: {
		if (ifconfig_inet_get_addrinfo(lifh, ifa->ifa_name, ifa,
			&inet) != 0)
			return;

		if (inet_ntop(AF_INET, &inet.sin->sin_addr, addr_buf,
			sizeof(addr_buf)) == NULL)
			return;
		printf("%-9s: %s/%d\n", "inet", addr_buf, inet.prefixlen);

		break;
	}
	case AF_INET6: {
		if (ifconfig_inet6_get_addrinfo(lifh, ifa->ifa_name, ifa,
			&inet6) != 0)
			return;

		if (inet_ntop(AF_INET6, &inet6.sin6->sin6_addr, addr_buf,
			sizeof(addr_buf)) == NULL)
			return;
		printf("%-9s: %s/%d\n", "inet6", addr_buf, inet6.prefixlen);

		break;
	}
	case AF_LINK: {
		struct sockaddr_dl *sdl = (void *)ifa->ifa_addr;

		if (sdl->sdl_family != AF_LINK ||
		    sdl->sdl_alen != ETHER_ADDR_LEN)
			return;

		memcpy(&ea, LLADDR(sdl), ETHER_ADDR_LEN);

		if (ether_ntoa_r(&ea, addr_buf) == NULL)
			strcpy(addr_buf, "N/A");
		printf("%-9s: %s\n", "MAC", addr_buf);

		break;
	}
	default:
		break;
	};
}

static void
show_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa, void *udata)
{
	char device[PCI_MAXNAMELEN + 1];
	const char **ifname = udata;
	const char *state = (ifa->ifa_flags & IFF_UP) ? "Up" : "Down";

	if (ifname == NULL || strcmp(*ifname, ifa->ifa_name) != 0)
		return;

	if (get_iface_parent(ifa->ifa_name, strlen(ifa->ifa_name), device,
		sizeof(device)) != 0)
		device[0] = '\0';

	printf("%-9s: %s\n", "Interface", ifa->ifa_name);
	printf("%-9s: %s\n", "State", state);
	printf("%-9s: %s\n", "Device", device);
	ifconfig_foreach_ifaddr(lifh, ifa, print_ifaddr, NULL);
}

static void
get_mac_addr(ifconfig_handle_t *lifh, struct ifaddrs *ifa, void *udata)
{
	struct ether_addr *ea = udata;
	struct sockaddr_dl *sdl = (void *)ifa->ifa_addr;

	(void)lifh;

	if (ea == NULL)
		return;

	if (sdl->sdl_family == AF_LINK && sdl->sdl_alen == ETHER_ADDR_LEN)
		memcpy(ea, LLADDR(sdl), ETHER_ADDR_LEN);
}

static bool
is_wlan_group(struct ifconfig_handle *lifh, const char *ifname)
{
	struct ifgroupreq ifgr;

	if (ifname == NULL)
		return (false);

	if (if_nametoindex(ifname) == 0) /* returns 0 if invalid i.e false */
		return (false);

	if (ifconfig_get_groups(lifh, ifname, &ifgr) == -1)
		return (false);

	for (size_t i = 0; i < ifgr.ifgr_len / sizeof(struct ifg_req); i++) {
		struct ifg_req *ifg = &ifgr.ifgr_groups[i];

		if (strcmp(ifg->ifgrq_group, "wlan") == 0)
			return (true);
	}

	return (false);
}

static int
get_iface_parent(const char *ifname, int ifname_len, char *buf, int buf_len)
{ /* assumes ifname[ifname_len] == '\0' */
	char name[32];
	int group_len = sizeof("wlan") - 1;
	size_t len = buf_len;

	if (ifname_len - group_len <= 0)
		return (1);

	if (snprintf(name, sizeof(name), "net.wlan.%s.%%parent",
		ifname + group_len) >= (int)sizeof(name))
		return (1);

	if (sysctlbyname(name, buf, &len, NULL, 0) == -1)
		return (1);

	if ((int)len >= buf_len)
		len = buf_len - 1;
	buf[len] = '\0';

	return (0);
}
