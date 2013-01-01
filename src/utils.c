#include "utils.h"
#include "string_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *connection_state_to_string[] = {
    [CONNECTED] = "Connected",
    [DISCONNECTED] = "Disconnected",
    [UNPLUGGED] = "Unplugged",
};

void usage(char *program_name) {
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

static bool file_contains(FILE *fp, char *pattern) {
  char buffer[1024];
  bool online = false;
  while (fgets(buffer, sizeof(buffer), fp) != NULL) {
    if (strstr(buffer, pattern) != NULL)
      return true;
  }
  return false;
}

enum connection_state get_interface_connection_state(char *interface_name) {
  char command[16];
  sprintf(command, "ifconfig %s", interface_name);
  FILE *fp = popen(command, "r");
  if (fp == NULL)
    return false;

  enum connection_state state = file_contains(fp, "inet ") ? CONNECTED
                                : file_contains(fp, "status: active")
                                    ? DISCONNECTED
                                    : UNPLUGGED;

  pclose(fp);
  return state;
}

char **get_network_interface_names() {
  FILE *fp = popen("ifconfig -l", "r");
  if (fp == NULL) {
    perror("popen `ifconfig -l` failed");
    return NULL;
  }

  char buffer[256];
  if (fgets(buffer, sizeof(buffer), fp) == 0) {
    pclose(fp);
    return NULL;
  }
  pclose(fp);

  buffer[strcspn(buffer, "\n")] = '\0';
  char **interface_names = split_string(buffer, " ");
  if (interface_names == NULL)
    return NULL;

  const char pattern[] =
      "(enc|lo|fwe|fwip|tap|plip|pfsync|pflog|ipfw|tun|sl|faith|ppp|bridge|wg)"
      "[0-9]+([[:space:]]*)|vm-[a-z]+([[:space:]]*)";
  if (remove_matching_strings(interface_names, pattern) != 0) {
    free_string_array(interface_names);
    return NULL;
  }

  return interface_names;
}

struct network_interface **get_network_interfaces() {
  char **interface_names = get_network_interface_names();

  int interfaces_count = 0;
  while (interface_names[interfaces_count] != NULL)
    interfaces_count++;

  struct network_interface **interfaces =
      calloc(sizeof(struct network_interface *), interfaces_count + 1);
  for (int i = 0; interface_names[i] != NULL; i++) {
    interfaces[i] = malloc(sizeof(struct network_interface));
    interfaces[i]->name = interface_names[i];
    interfaces[i]->state = get_interface_connection_state(interfaces[i]->name);
  }
  interfaces[interfaces_count] = NULL;
  free(interface_names);

  return interfaces;
}

void free_network_intefaces(struct network_interface **interfaces) {
  for (int i = 0; interfaces[i] != NULL; i++) {
    free(interfaces[i]->name);
    free(interfaces[i]);
  }
  free(interfaces);
}
