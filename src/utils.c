#include "utils.h"
#include "string_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *connection_state_to_string[] = {
    [CONNECTED] = "Connected",
    [DISCONNECTED] = "Disconnected",
    [UNPLUGGED] = "Unplugged",
};

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

static void guard_root_access() {
  if (geteuid() != 0) {
    fprintf(stderr, "insufficient permissions\n");
    exit(EXIT_FAILURE);
  }
}

int enable_interface(char *interface_name) {
  guard_root_access();

  char command[32];
  sprintf(command, "ifconfig %s up", interface_name);
  return system(command);
}

int disable_interface(char *interface_name) {
  guard_root_access();

  char command[32];
  sprintf(command, "ifconfig %s down", interface_name);
  return system(command);
}

int restart_interface(char *interface_name) {
  guard_root_access();

  char command[128];
  sprintf(command, "service netif restart %s > /dev/null 2>&1", interface_name);
  return system(command);
}

bool is_valid_interface(char *interface_name) {
  char **interface_names = get_network_interface_names();
  bool is_valid = string_array_contains(interface_names, interface_name);
  free_string_array(interface_names);
  return is_valid;
}
