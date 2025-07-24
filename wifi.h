/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef IEEE80211_H
#define IEEE80211_H

#include <sys/cdefs.h>
#include <sys/queue.h>

#include <net/ethernet.h>
#include <net80211/ieee80211.h>

#include <stdio.h>
#include <wpa_ctrl.h>
#include "usage.h"

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

enum security { SEC_OPEN = 0, SEC_EAP, SEC_PSK, SEC_NA };

extern const char *security_to_string[];

struct scan_result {
	int freq, signal;
	struct ether_addr bssid;
	char ssid[IEEE80211_NWID_LEN + 1];
	enum security security;
	STAILQ_ENTRY(scan_result) next;
};

STAILQ_HEAD(scan_results, scan_result);

typedef int (*wpa_cmd_handler_f)(struct wpa_ctrl *ctrl, int argc, char **argv);

struct wpa_command {
	const char *name;
	wpa_cmd_handler_f handler;
};

int template_cmd_wpa(int argc, char *argv[], struct wpa_command *cmds,
    size_t cmds_len, usage_f usage_handler);

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

extern struct wpa_command station_cmds[5];
extern struct wpa_command known_network_cmds[4];

#endif /* !IEEE80211_H */
