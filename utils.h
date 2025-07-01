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

#include <libifconfig.h>
#include <regex.h>
#include <stdbool.h>

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
	char *connected_ssid;
	enum connection_state state;
};

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
	char *netmask;
	char *gateway;
	char *dns1;
	char *dns2;
	char *search_domain;
};

char **get_network_interface_names(void);
struct network_interface **get_network_interfaces(void);
struct network_interface *get_network_interface_by_name(char *interface_name);
struct wifi_network **scan_network_interface(char *interface_name);
char *retrieve_network_interface_connected_ssid(char *interface_name);
void free_network_interface(struct network_interface *interface);
void free_network_interfaces(struct network_interface **interfaces);
enum connection_state get_interface_connection_state(char *interface_name);

int enable_interface(const char *ifname);
int disable_interface(const char *ifname);
int disconnect_network_interface(char *interface_name);
int restart_interface(char *interface_name);
bool is_valid_interface(const char *ifname);

struct wifi_network *get_wifi_network_by_ssid(char *network_interface,
    char *ssid);
int configure_wifi_network(struct wifi_network *network, const char *password);
bool is_wifi_network_secured(struct wifi_network *network);
void free_wifi_network(struct wifi_network *network);
void free_wifi_networks(struct wifi_network **network);

int connect_to_ssid(char *network_interface, char *ssid);
bool is_ssid_configured(char *ssid);

struct network_configuration *generate_network_configuration(int argc,
    char **argv);
int configure_nic(char *interface_name, struct network_configuration *config);
void free_network_configuration(struct network_configuration *configuration);
void print_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);
int get_ssid(const char *ifname, char *ssid, int ssid_len);
int regcomp_ignored_ifaces(regex_t *re);

void free_wifi_networks_list(struct wifi_network_list *);

struct wifi_network_list *get_scan_results(const char *ifname);
void scan(const char *iface);

#endif /* !UTILS_H */
