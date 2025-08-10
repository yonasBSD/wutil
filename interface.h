/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdbool.h>

#include "libifconfig.h"

enum connection_state {
	CONNECTED,
	DISCONNECTED,
	UNPLUGGED,
	DISABLED,
	NA,
};

bool is_wlan_group(struct ifconfig_handle *lifh, const char *ifname);
enum connection_state get_connection_state(struct ifconfig_handle *lifh,
    struct ifaddrs *ifa);
int get_iface_parent(const char *ifname, int ifname_len, char *buf,
    int buf_len);
void get_mac_addr(ifconfig_handle_t *lifh, struct ifaddrs *ifa, void *udata);
void is_ifaddr_af_inet(ifconfig_handle_t *lifh, struct ifaddrs *ifa,
    void *udata);

extern const char *connection_state_to_string[];

#endif /* !INTERFACE_H */
