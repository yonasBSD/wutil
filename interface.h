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

extern struct interface_command interface_cmds[2];

int cmd_interface_list(struct ifconfig_handle *lifh, int argc, char **argv);
int cmd_interface_show(struct ifconfig_handle *lifh, int argc, char **argv);

#endif /* !INTERFACE_H */
