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

struct wifi_network {
	char *ssid;
	char *bssid;
	char *capabilities;
	int channel;
	int data_rate;
	int signal_dbm;
	int noise_dbm;
	int beacon_interval;
	STAILQ_ENTRY(wifi_network) next;
};

STAILQ_HEAD(wifi_network_list, wifi_network);

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

struct known_network {
	int id;
	enum { KN_ENABLED = 0, KN_DISABLED, KN_CURRENT } state;
	char ssid[IEEE80211_NWID_LEN + 1];
	struct ether_addr bssid;
	STAILQ_ENTRY(known_network) next;
};

STAILQ_HEAD(known_networks, known_network);

struct network_interface_list *get_interfaces(struct ifconfig_handle *lifh);
void free_network_interface(struct network_interface *interface);
void free_network_interface_list(struct network_interface_list *head);

int enable_interface(const char *ifname);
int disable_interface(const char *ifname);
int restart_interface(const char *ifname);
bool is_valid_interface(const char *ifname);

int configure_wifi_network(struct wifi_network *network, const char *password);
int connect_with_wpa(const char *ifname, const char *ssid);

bool is_ssid_configured(const char *ssid);
bool is_wifi_network_secured(struct wifi_network *network);

int parse_network_config(int argc, char **argv,
    struct network_configuration *config);
int configure_nic(char *interface_name, struct network_configuration *config);

void print_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);
void retrieve_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);

int regcomp_ignored_ifaces(regex_t *re);

int set_ssid(const char *ifname, const char *ssid);
int get_ssid(const char *ifname, char *ssid, int ssid_len);

void scan_and_wait(int route_socket, const char *iface);
struct wifi_network_list *get_scan_results(int route_socket,
    const char *ifname);
void free_wifi_network(struct wifi_network *network);
void free_wifi_network_list(struct wifi_network_list *);

int modify_if_flags(int sockfd, const char *ifname, int set_flag,
    int clear_flag);

void guard_root_access(void);

struct known_networks *get_known_networks(struct wpa_ctrl *ctrl);
void free_known_networks(struct known_networks *nws);

#endif /* !UTILS_H */
