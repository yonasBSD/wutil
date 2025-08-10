/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdbool.h>

#include "libifconfig.h"

bool is_wlan_group(struct ifconfig_handle *lifh, const char *ifname);

void list_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);
void show_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);

#endif /* !INTERFACE_H */
