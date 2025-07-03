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
#include <sys/event.h>
#include <sys/ioccom.h>
#include <sys/sockio.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>

#include <arpa/inet.h>
#include <err.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <lib80211/lib80211_ioctl.h>
#include <libifconfig.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

static int configure_ip(const char *ifname,
    struct network_configuration *config);
static int configure_ip_manually(const char *ifname,
    struct network_configuration *config);

static int configure_resolvd(struct network_configuration *config);

static void is_ifaddr_af_inet(ifconfig_handle_t *lifh, struct ifaddrs *ifa,
    void *udata);

static enum connection_state get_connection_state(struct ifconfig_handle *lifh,
    struct ifaddrs *ifa);

static void append_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);

static int prefixlen(const char *netmask);

static bool is_valid_inet(const char *inet);
static int set_inet(struct snl_state *ss, uint32_t ifindex, const char *inet,
    uint8_t prefixlen, struct snl_errmsg_data *e);
static int set_default_gateway(struct snl_state *ss, uint32_t oif,
    const char *gateway, struct snl_errmsg_data *e);

const char *connection_state_to_string[] = {
	[CONNECTED] = "Connected",
	[DISCONNECTED] = "Disconnected",
	[UNPLUGGED] = "Unplugged",
	[DISABLED] = "Disabled",
	[NA] = "N/A",
};

static void
append_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa, void *udata)
{
	struct network_interface *nif;
	struct network_interface_list *networks = udata;

	if (networks == NULL)
		return;

	nif = calloc(1, sizeof(*nif));
	if (nif == NULL)
		return;

	nif->name = strdup(ifa->ifa_name);
	if (nif->name == NULL) {
		free(nif);
		return;
	}

	nif->state = get_connection_state(lifh, ifa);
	if (get_ssid(ifa->ifa_name, nif->connected_ssid, IEEE80211_NWID_LEN) !=
	    0)
		nif->connected_ssid[0] = '\0';

	STAILQ_INSERT_TAIL(networks, nif, next);
}

struct network_interface_list *
get_interfaces(struct ifconfig_handle *lifh)
{
	struct network_interface_list *ifaces = malloc(sizeof(*ifaces));

	if (ifaces == NULL)
		return (NULL);

	STAILQ_INIT(ifaces);

	if (ifconfig_foreach_iface(lifh, append_interface, ifaces) != 0) {
		free_network_interface_list(ifaces);
		return (NULL);
	}

	return (ifaces);
}

void
free_network_interface_list(struct network_interface_list *head)
{
	struct network_interface *entry, *tmp;
	STAILQ_FOREACH_SAFE(entry, head, next, tmp)
		free_network_interface(entry);
	free(head);
}

void
free_network_interface(struct network_interface *interface)
{
	free(interface->name);
	free(interface);
}

void
guard_root_access(void)
{
	if (geteuid() != 0) {
		warnx("insufficient permissions");
		exit(EXIT_FAILURE);
	}
}

int
modify_if_flags(int sockfd, const char *ifname, int set_flag, int clear_flag)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl SIOCGIFFLAGS failed");
		return (-1);
	}

	ifr.ifr_flags |= set_flag;
	ifr.ifr_flags &= ~clear_flag;

	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
		perror("ioctl SIOCSIFFLAGS failed");

	return (0);
}

int
enable_interface(const char *ifname)
{
	int ret = 0;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0)
		return (-1);

	ret = modify_if_flags(sockfd, ifname, IFF_UP, 0);

	close(sockfd);

	return (ret);
}

int
disable_interface(const char *ifname)
{
	int ret = 0;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0)
		return (-1);

	ret = modify_if_flags(sockfd, ifname, 0, IFF_UP);

	close(sockfd);

	return (ret);
}

int
restart_interface(char *interface_name)
{
	char command[256];

	guard_root_access();

	snprintf(command, sizeof(command),
	    "service netif restart %s > /dev/null 2>&1", interface_name);
	return (system(command));
}

bool
is_valid_interface(const char *ifname)
{
	bool is_valid;
	regex_t ignored_ifaces;

	if (ifname == NULL)
		return (false);

	is_valid = if_nametoindex(ifname); /* returns 0 if invalid i.e false */

	regcomp_ignored_ifaces(&ignored_ifaces);
	if (regexec(&ignored_ifaces, ifname, 0, NULL, 0) == 0)
		is_valid = false;
	regfree(&ignored_ifaces);

	return (is_valid);
}

static bool
is_valid_inet(const char *inet)
{
	struct in_addr addr;

	return (inet != NULL && inet_pton(AF_INET, inet, &addr) == 1);
}

int
parse_network_config(int argc, char **argv,
    struct network_configuration *config)
{
	int opt;
	struct option options[] = {
		{ "method", required_argument, NULL, 'm' },
		{ "ip", required_argument, NULL, 'i' },
		{ "netmask", required_argument, NULL, 'n' },
		{ "gateway", required_argument, NULL, 'g' },
		{ "dns1", required_argument, NULL, 'd' },
		{ "dns2", required_argument, NULL, 's' },
		{ "search", required_argument, NULL, 'r' },
		{ NULL, 0, NULL, 0 },
	};

	if (argc == 1) {
		warnx("no options provided");
		return (1);
	}

	if (config == NULL)
		return (1);

	config->prefix_len = -1;
	while ((opt = getopt_long(argc, argv, "m:i:n:g:d:s:r:", options,
		    NULL)) != -1) {
		switch (opt) {
		case 'm':
			if (strcasecmp(optarg, "dhcp") == 0) {
				config->method = DHCP;
			} else if (strcasecmp(optarg, "manual") == 0) {
				config->method = MANUAL;
			} else {
				warnx("invalid method: %s", optarg);
				return (1);
			}
			break;
		case 'i':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				warnx("-i <ip> requires --method=manual");
				return (1);
			}
			if (!is_valid_inet(optarg)) {
				warnx("invalid inet: %s", optarg);
				return (1);
			}
			config->ip = optarg;
			break;
		case 'n':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				warnx("-n <netmask> requires --method=manual");
				return (1);
			}
			config->prefix_len = prefixlen(optarg);
			if (config->prefix_len == -1) {
				warnx("invalid gateway: %s", optarg);
				return (1);
			}
			break;
		case 'g':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				warnx("-g <gateway> requires --method=manual");
				return (1);
			}
			if (!is_valid_inet(optarg)) {
				warnx("invalid gateway: %s", optarg);
				return (1);
			}
			config->gateway = optarg;
			break;
		case 'd':
			config->dns1 = optarg;
			break;
		case 's':
			config->dns2 = optarg;
			break;
		case 'r':
			config->search_domain = optarg;
			break;
		case '?':
		default:
			return (1);
		}
	}

	if (optind < argc) {
		warnx("unexpected argument: %s", argv[optind]);
		return (1);
	}

	if (config->method == MANUAL) {
		bool has_ip = config->ip != NULL;
		bool has_nm = config->prefix_len != -1;
		bool has_gw = config->gateway != NULL;

		if ((has_ip && !has_nm) || (!has_ip && has_nm) ||
		    (!has_nm && !has_gw)) {
			warnx("provide both -i and -n or -g");
			return (1);
		}
	}

	return (0);
}

static int
set_inet(struct snl_state *ss, uint32_t ifindex, const char *inet,
    uint8_t prefixlen, struct snl_errmsg_data *e)
{
	struct nlmsghdr *hdr;
	struct ifaddrmsg *ifahdr;
	struct in_addr addr;
	struct snl_writer nw;

	snl_init_writer(ss, &nw);
	hdr = snl_create_msg_request(&nw, RTM_NEWADDR);
	if (hdr == NULL) {
		warnx("failed to create nlmsghdr");
		return (1);
	}

	ifahdr = snl_reserve_msg_object(&nw, struct ifaddrmsg);
	if (ifahdr == NULL) {
		warnx("failed to init snl_state");
		return (1);
	}

	ifahdr->ifa_family = AF_INET;
	ifahdr->ifa_prefixlen = prefixlen;
	ifahdr->ifa_index = ifindex;

	if (inet_pton(AF_INET, inet, &addr) != 1) {
		warnx("unparseable inet: %s", inet);
		return (1);
	}

	snl_add_msg_attr_ip4(&nw, IFA_LOCAL, &addr);

	if ((hdr = snl_finalize_msg(&nw)) == NULL) {
		warnx("failed to finalize snl message");
		return (1);
	}

	if (!snl_send_message(ss, hdr)) {
		warnx("failed to send snl message");
		return (1);
	}

	snl_read_reply_code(ss, hdr->nlmsg_seq, e);

	return (e->error);
}

static int
set_default_gateway(struct snl_state *ss, uint32_t oif, const char *gateway,
    struct snl_errmsg_data *e)
{
	struct nlmsghdr *hdr;
	struct rtmsg *rt_hdr;
	struct in_addr gw, dest = { 0 };
	struct snl_writer nw;

	snl_init_writer(ss, &nw);
	hdr = snl_create_msg_request(&nw, RTM_NEWROUTE);
	if (hdr == NULL) {
		warnx("failed to create nlmsghdr");
		return (1);
	}

	hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

	rt_hdr = snl_reserve_msg_object(&nw, struct rtmsg);
	if (rt_hdr == NULL) {
		warnx("failed to init snl_state");
		return (1);
	}

	rt_hdr->rtm_family = AF_INET;
	rt_hdr->rtm_dst_len = 0;
	rt_hdr->rtm_src_len = 0;
	rt_hdr->rtm_table = RT_TABLE_MAIN;
	rt_hdr->rtm_protocol = RTPROT_STATIC;
	rt_hdr->rtm_scope = RT_SCOPE_UNIVERSE;
	rt_hdr->rtm_type = RTN_UNICAST;
	rt_hdr->rtm_flags = 0;

	if (inet_pton(AF_INET, gateway, &gw) != 1) {
		warnx("unparseable inet: %s", gateway);
		return (1);
	}

	snl_add_msg_attr_ip4(&nw, RTA_GATEWAY, &gw);
	snl_add_msg_attr_ip4(&nw, RTA_DST, &dest);
	snl_add_msg_attr_u32(&nw, RTA_OIF, oif);

	if ((hdr = snl_finalize_msg(&nw)) == NULL) {
		warnx("failed to finalize snl message");
		return (1);
	}

	if (!snl_send_message(ss, hdr)) {
		warnx("failed to send snl message");
		return (1);
	}

	snl_read_reply_code(ss, hdr->nlmsg_seq, e);

	return (e->error);
}

static int
prefixlen(const char *netmask)
{
	uint32_t addr;
	uint32_t mask = UINT32_MAX;

	if (inet_pton(AF_INET, netmask, &addr) != 1)
		return (-1);

	addr = ntohl(addr);
	for (int plen = 32; plen >= 0; plen--) {
		if (addr == mask)
			return (plen);
		mask <<= 1;
	}

	return (-1);
}

static int
configure_ip_manually(const char *ifname, struct network_configuration *config)
{
	uint32_t ifindex = if_nametoindex(ifname);
	struct snl_state ss;
	struct snl_errmsg_data e = { 0 };

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		warnx("failed to init snl_state");
		return (1);
	}

	if (config->ip != NULL &&
	    set_inet(&ss, ifindex, config->ip, config->prefix_len, &e) != 0) {
		warnx("failed to set ip/netmask");
		goto cleanup;
	}

	if (config->gateway != NULL &&
	    set_default_gateway(&ss, ifindex, config->gateway, &e) != 0) {
		warnx("failed to set gateway");
		goto cleanup;
	}

cleanup:
	if (e.error_str != NULL)
		warnx("snl_error: %s", e.error_str);

	snl_free(&ss);
	return (e.error);
}

static int
configure_resolvd(struct network_configuration *config)
{
	FILE *config_file = fopen("/etc/resolv.conf", "w");

	if (config_file == NULL) {
		perror("failed to open /etc/resolv.conf");
		return (1);
	}

	fprintf(config_file, "# Generated by wutil\n");
	if (config->search_domain != NULL)
		fprintf(config_file, "search %s\n", config->search_domain);

	if (config->dns1 != NULL)
		fprintf(config_file, "nameserver %s\n", config->dns1);

	if (config->dns2 != NULL)
		fprintf(config_file, "nameserver %s\n", config->dns2);

	fclose(config_file);
	return (0);
}

static int
configure_ip(const char *ifname, struct network_configuration *config)
{
	int ret = 0;

	if (config->method == MANUAL) {
		ret = configure_ip_manually(ifname, config);
	} else if (config->method == DHCP) { /* TODO: remove call to dhclient */
		char command[256];
		snprintf(command, sizeof(command), "dhclient %s", ifname);
		ret = system(command);
	}

	return (ret);
}

int
configure_nic(char *ifname, struct network_configuration *config)
{
	int ret = 0;

	if (config->method != UNCHANGED &&
	    (ret = configure_ip(ifname, config)) != 0)
		return (ret);

	if (config->dns1 != NULL || config->dns2 != NULL ||
	    config->search_domain != NULL) {
		printf("configuring resolvd...\n");
		ret = configure_resolvd(config);
	}

	return (ret);
}

static void
is_ifaddr_af_inet(ifconfig_handle_t *lifh, struct ifaddrs *ifa, void *udata)
{
	bool *is_af_inet = udata;

	(void)lifh;

	if (is_af_inet == NULL)
		return;

	if (ifa->ifa_addr->sa_family == AF_INET ||
	    ifa->ifa_addr->sa_family == AF_INET6) {
		*is_af_inet = true;
	}
}

static enum connection_state
get_connection_state(struct ifconfig_handle *lifh, struct ifaddrs *ifa)
{
	bool is_interface_online = false;
	struct ifmediareq *ifmr;
	enum connection_state state = NA;
	const char *status;

	if (lifh == NULL || ifa == NULL)
		return (NA);

	ifconfig_foreach_ifaddr(lifh, ifa, is_ifaddr_af_inet,
	    &is_interface_online);

	if (ifconfig_media_get_mediareq(lifh, ifa->ifa_name, &ifmr) != 0)
		return (NA);

	status = ifconfig_media_get_status(ifmr);
	if (strncmp("wlan", ifa->ifa_name, strlen("wlan")) == 0) {
		state = (ifa->ifa_flags & IFF_UP) == 0 ? DISABLED :
		    strcmp(status, "associated") == 0 && is_interface_online ?
							 CONNECTED :
							 DISCONNECTED;
	} else if (strcmp(status, "active") == 0) {
		state = is_interface_online ? CONNECTED : DISCONNECTED;
	} else {
		state = UNPLUGGED;
	}

	free(ifmr);
	return (state);
}

void
print_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa, void *udata)
{
	regex_t *ignore = udata;
	enum connection_state state;
	char ssid[IEEE80211_NWID_LEN + 1] = { 0 };

	if (ignore != NULL && regexec(ignore, ifa->ifa_name, 0, NULL, 0) == 0)
		return;

	state = get_connection_state(lifh, ifa);
	if (get_ssid(ifa->ifa_name, ssid, IEEE80211_NWID_LEN) != 0)
		ssid[0] = '\0';

	printf("%-10s %-12s %-20s\n", ifa->ifa_name,
	    connection_state_to_string[state], ssid);
}

void
retrieve_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata)
{
	struct network_interface *iface = udata;

	if (iface == NULL || iface->name == NULL ||
	    strcmp(ifa->ifa_name, iface->name) != 0)
		return;

	iface->state = get_connection_state(lifh, ifa);

	memset(iface->connected_ssid, 0, IEEE80211_NWID_LEN + 1);
	if (get_ssid(ifa->ifa_name, iface->connected_ssid,
		IEEE80211_NWID_LEN) != 0)
		iface->connected_ssid[0] = '\0';
}

int
regcomp_ignored_ifaces(regex_t *re)
{
	const char not_nics[] =
	    "(enc|lo|fwe|fwip|tap|plip|pfsync|pflog|ipfw|tun|sl|faith|ppp|bridge|wg)"
	    "[0-9]+([[:space:]]*)|vm-[a-z]+([[:space:]]*)";
	return (regcomp(re, not_nics, REG_EXTENDED | REG_NOSUB) != 0);
}
