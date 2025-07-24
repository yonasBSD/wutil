/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef UTILS_H
#define UTILS_H

enum connection_state {
	CONNECTED,
	DISCONNECTED,
	UNPLUGGED,
	DISABLED,
	NA,
};

extern const char *connection_state_to_string[];

int modify_if_flags(int sockfd, const char *ifname, int set_flag,
    int clear_flag);

#endif /* !UTILS_H */
