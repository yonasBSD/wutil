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
	    "\t  [-i <id>] [-p <password>] [-h] <ssid>\n",
	    usage_str ? "Usage:" : "");
}
