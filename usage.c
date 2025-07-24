/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <stdio.h>

#include "usage.h"

void
usage(FILE *fout)
{
	fprintf(fout, "Usage:\twutil help\n");
	usage_interface(fout, false);
	usage_known_networks(fout, false);
	usage_station(fout, false);
}

void
usage_interface(FILE *fout, bool usage_str)
{
	fprintf(fout,
	    "%s"
	    "\twutil {interface | if} list\n"
	    "\twutil {interface | if} show <interface>\n"
	    "\twutil {interface | if} set\n"
	    "\twutil {interface | if} set [--state {up | down}] <interface>\n"
	    "\twutil {interface | if} set [-s {up | down}] <interface>\n",
	    usage_str ? "Usage:" : "");
}

void
usage_known_networks(FILE *fout, bool usage_str)
{
	fprintf(fout,
	    "%s"
	    "\twutil {known-network | kn} [--ctrl-interface <path>] list\n"
	    "\twutil {known-network | kn} [-c <path>] {show | forget} <ssid>\n"
	    "\twutil {known-network | kn} [--ctrl-interface <path>] set\n"
	    "\t  [--priority <num>] [--autoconnect {yes | no}] <ssid>\n"
	    "\twutil {known-network | kn} [-c <path>] set\n"
	    "\t  [-p <num>] [-a {y | n}] <ssid>\n",
	    usage_str ? "Usage:" : "");
}

void
usage_station(FILE *fout, bool usage_str)
{
	fprintf(fout,
	    "%s"
	    "\twutil {station | sta} [--ctrl-interface <path>]\n"
	    "\t  {scan | networks | status | disconnect}\n"
	    "\twutil {station | sta} [--ctrl-interface <path>] connect\n"
	    "\t  [--identity <id>] [--password <password>] [--hidden] <ssid>\n"
	    "\twutil {station | sta} [-c <path>] connect\n"
	    "\t  [-i <id>] [-p <password>] [-h] <ssid> [password]\n",
	    usage_str ? "Usage:" : "");
}
