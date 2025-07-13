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
	UNCHANGED = 0,
	DHCP,
	MANUAL,
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

int regcomp_ignored_ifaces(regex_t *re);

int modify_if_flags(int sockfd, const char *ifname, int set_flag,
    int clear_flag);

bool is_valid_inet(const char *inet);
bool is_valid_inet6(const char *inet6);

#endif /* !UTILS_H */
