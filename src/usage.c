#include <stdio.h>

void
usage(char *program_name)
{
	// clang-format off
  fprintf(stderr,
      "Usage: %s [commands] [args]\n"
      "Commands:\n"
      "  help                                     Show this message and exit\n"
      "  list                                     List all network interfaces with their current status\n"
      "  show       <interface>                   Display detailed status for <interface>\n"
      "  enable     <interface>                   Enable <interface>\n"
      "  disable    <interface>                   Disable <interface>\n"
      "  restart    <interface>                   Restart <interface>\n"
      "  config     <interface>                   Configure network settings for <interface>\n"
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
	// clang-format on
}
