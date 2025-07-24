/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdbool.h>

#include "libifconfig.h"

typedef int (
    *iface_cmd_handler_f)(struct ifconfig_handle *lifh, int argc, char **argv);

struct interface_command {
	const char *name;
	iface_cmd_handler_f handler;
};

extern struct interface_command interface_cmds[3];

int cmd_interface_list(struct ifconfig_handle *lifh, int argc, char **argv);
int cmd_interface_show(struct ifconfig_handle *lifh, int argc, char **argv);
int cmd_interface_set(struct ifconfig_handle *lifh, int argc, char **argv);

bool is_wlan_group(struct ifconfig_handle *lifh, const char *ifname);
int get_iface_parent(const char *ifname, int ifname_len, char *buf,
    int buf_len);

#endif /* !INTERFACE_H */
