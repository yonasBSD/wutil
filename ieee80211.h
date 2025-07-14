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

#ifndef IEEE80211_H
#define IEEE80211_H

#include <sys/cdefs.h>
#include <sys/queue.h>

#include <net/ethernet.h>
#include <net80211/ieee80211.h>

#include <stdio.h>
#include <wpa_ctrl.h>

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

struct known_network {
	int id;
	enum { KN_ENABLED = 0, KN_DISABLED, KN_CURRENT } state;
	char ssid[IEEE80211_NWID_LEN + 1];
	struct ether_addr bssid;
	STAILQ_ENTRY(known_network) next;
};

STAILQ_HEAD(known_networks, known_network);

enum security { OPEN = 0, EAP, PSK };

extern const char *security_to_string[];

struct scan_result {
	int freq, signal;
	struct ether_addr bssid;
	char ssid[IEEE80211_NWID_LEN + 1];
	enum security security;
	STAILQ_ENTRY(scan_result) next;
};

STAILQ_HEAD(scan_results, scan_result);

struct wpa_command {
	const char *name;
	int (*handler)(struct wpa_ctrl *ctrl, int argc, char **argv);
};

void scan_and_wait_ioctl(int route_socket, const char *iface);
struct wifi_network_list *get_scan_results_ioctl(int route_socket,
    const char *ifname);
void free_wifi_network(struct wifi_network *network);
void free_wifi_network_list(struct wifi_network_list *);

int set_ssid(const char *ifname, const char *ssid);
int get_ssid(const char *ifname, char *ssid, int ssid_len);

char *wpa_ctrl_default_path(void);
int wpa_ctrl_wait(int wpa_fd, const char *wpa_event, struct timespec *timeout);
struct scan_results *get_scan_results(struct wpa_ctrl *ctrl);
void free_scan_results(struct scan_results *head);
int scan_and_wait(struct wpa_ctrl *ctrl);

struct known_networks *get_known_networks(struct wpa_ctrl *ctrl);
void free_known_networks(struct known_networks *nws);

int add_network(struct wpa_ctrl *ctrl, const char *ssid);
int configure_psk(struct wpa_ctrl *ctrl, int, const char *psk);
int configure_eap(struct wpa_ctrl *ctrl, int nwid, const char *identity,
    const char *password);
int configure_ess(struct wpa_ctrl *ctrl, int nwid);
/* use nwid = -1 to select any network */
int select_network(struct wpa_ctrl *ctrl, int nwid);
int update_config(struct wpa_ctrl *ctrl);

int cmd_wpa_scan(struct wpa_ctrl *ctrl, int argc, char **argv);
int cmd_wpa_networks(struct wpa_ctrl *ctrl, int argc, char **argv);
int cmd_wpa_status(struct wpa_ctrl *ctrl, int argc, char **argv);
int cmd_wpa_disconnect(struct wpa_ctrl *ctrl, int argc, char **argv);
int cmd_wpa_connect(struct wpa_ctrl *ctrl, int argc, char **argv);

int cmd_known_network_list(struct wpa_ctrl *ctrl, int argc, char **argv);
int cmd_known_network_show(struct wpa_ctrl *ctrl, int argc, char **argv);
int cmd_known_network_forget(struct wpa_ctrl *ctrl, int argc, char **argv);
int cmd_known_network_set(struct wpa_ctrl *ctrl, int argc, char **argv);

int template_cmd_wpa(int argc, char *argv[], struct wpa_command *cmds,
    size_t cmds_len, void (*usage_fn)(FILE *, bool));

extern struct wpa_command station_cmds[5];
extern struct wpa_command known_network_cmds[4];

#endif /* !IEEE80211_H */
