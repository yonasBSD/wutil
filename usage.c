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
usage(char *program_name)
{
	fprintf(stderr,
	    "Usage: %s [commands] [args]\n"
	    "Commands:\n"
	    "  help                                     Show this message and exit\n"
	    "  list                                     List all network interfaces with their current status\n"
	    "  show       <interface>                   Display detailed status for <interface>\n"
	    "  enable     <interface>                   Enable <interface>\n"
	    "  disable    <interface>                   Disable <interface>\n"
	    "  restart    <interface>                   Restart <interface>\n"
	    "  configure  <interface>                   Configure network settings for <interface>\n"
	    "                                             Options:\n"
	    "                                               --method [dhcp|manual] Set IP assignment method\n"
	    "                                               --ip <ip_address> Static IP address (required if manual)\n"
	    "                                               --netmask <netmask> Subnet mask (required if manual)\n"
	    "                                               --gateway <gateway> Default gateway (required if manual)\n"
	    "                                               --dns1 <dns_server> Primary DNS server\n"
	    "                                               --dns2 <dns_server> Secondary DNS server (optional)\n"
	    "                                               --search <domain> Search domain (optional)\n"
	    "  scan       <interface>                         Scan available Wi-Fi networks\n"
	    "  disconnect <interface>                   Disconnect from the current Wi-Fi network\n"
	    "  connect    <interface> <ssid> [psk]      Connect to a Wi-Fi network with optional PSK (password)\n",
	    program_name);
}
