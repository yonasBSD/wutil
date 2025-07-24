/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef UTILS_H
#define UTILS_H

#include <sys/cdefs.h>
#include <sys/queue.h>

#include <net/ethernet.h>
#include <net80211/ieee80211.h>

#include <libifconfig.h>
#include <regex.h>
#include <stdbool.h>
#include <wpa_ctrl.h>

enum connection_state {
	CONNECTED,
	DISCONNECTED,
	UNPLUGGED,
	DISABLED,
	NA,
};

extern const char *connection_state_to_string[];

struct network_interface {
	char *name;
	char connected_ssid[IEEE80211_NWID_LEN + 1];
	enum connection_state state;
	STAILQ_ENTRY(network_interface) next;
};

STAILQ_HEAD(network_interface_list, network_interface);

enum ip_configuration {
	IP_UNCHANGED = 0,
	IP_DHCP,
	IP_MANUAL,
};

struct network_configuration {
	enum ip_configuration method;
	char *ip;
	int prefix_len;
	char *gateway;
	char *dns1;
	char *dns2;
	char *search_domain;
};

struct network_interface_list *get_interfaces(struct ifconfig_handle *lifh);
void free_network_interface(struct network_interface *interface);
void free_network_interface_list(struct network_interface_list *head);

enum connection_state get_connection_state(struct ifconfig_handle *lifh,
    struct ifaddrs *ifa);
int enable_interface(const char *ifname);
int disable_interface(const char *ifname);
int restart_interface(const char *ifname);

int parse_network_config(int argc, char **argv,
    struct network_configuration *config);
int configure_nic(char *interface_name, struct network_configuration *config);

int modify_if_flags(int sockfd, const char *ifname, int set_flag,
    int clear_flag);

bool is_valid_inet(const char *inet);
bool is_valid_inet6(const char *inet6);

#endif /* !UTILS_H */
