/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/sockio.h>

#include <libifconfig.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

const char *connection_state_to_string[] = {
	[CONNECTED] = "Connected",
	[DISCONNECTED] = "Disconnected",
	[UNPLUGGED] = "Unplugged",
	[DISABLED] = "Disabled",
	[NA] = "N/A",
};

int
modify_if_flags(int sockfd, const char *ifname, int set_flag, int clear_flag)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl SIOCGIFFLAGS failed");
		return (-1);
	}

	ifr.ifr_flags |= set_flag;
	ifr.ifr_flags &= ~clear_flag;

	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
		perror("ioctl SIOCSIFFLAGS failed");
		return (-1);
	}

	return (0);
}
