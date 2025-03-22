#include "utils.h"
#include "string_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *connection_state_to_string[] = {
    [CONNECTED] = "Connected",
    [DISCONNECTED] = "Disconnected",
    [UNPLUGGED] = "Unplugged",
};

enum connection_state get_interface_connection_state(char *interface_name) {
  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s", interface_name);
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
    perror("popen failed");
    exit(1);
  }

  char **lines = file_read_lines(fp);
  pclose(fp);
  if (lines == NULL)
    exit(1);

  char *output = lines_to_string(lines);
  free_string_array(lines);
  if (lines == NULL)
    exit(1);

  enum connection_state state = strstr(output, "inet ") ? CONNECTED
                                : strstr(output, "status: active")
                                    ? DISCONNECTED
                                    : UNPLUGGED;
  free(output);
  return state;
}

struct network_interface *get_network_interface_by_name(char *interface_name) {
  struct network_interface **interfaces = get_network_interfaces();
  int count = 0;
  while (interfaces[count] != NULL)
    count++;

  struct network_interface *interface = NULL;
  for (int i = 0; interfaces[i] != NULL; i++) {
    if (strcmp(interfaces[i]->name, interface_name) == 0) {
      interface = interfaces[i];
      interfaces[i] = interfaces[count - 1];
      interfaces[count - 1] = NULL;
      break;
    }
  }

  free_network_intefaces(interfaces);
  return interface;
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

  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s up", interface_name);
  return system(command);
}

int disable_interface(char *interface_name) {
  guard_root_access();

  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s down", interface_name);
  return system(command);
}

int restart_interface(char *interface_name) {
  guard_root_access();

  char command[256];
  snprintf(command, sizeof(command),
           "service netif restart %s > /dev/null 2>&1", interface_name);
  return system(command);
}

bool is_valid_interface(char *interface_name) {
  char **interface_names = get_network_interface_names();
  bool is_valid = string_array_contains(interface_names, interface_name);
  free_string_array(interface_names);
  return is_valid;
}

static struct wifi_network *extract_wifi_network(char *network_info) {
  char ssid[256], bssid[18], channel[5], date_rate[5], sn[8],
      beacon_interval[4], capabilities[256];
  if (sscanf(network_info, "%255s %17s %4s %4s %7s %3s %[^\n]", ssid, bssid,
             channel, date_rate, sn, beacon_interval, capabilities) != 7)
    return NULL;
  int signal, noise;
  if (sscanf(sn, "%d:%d", &signal, &noise) != 2)
    return NULL;

  struct wifi_network *network = malloc(sizeof(struct wifi_network));
  if (network == NULL)
    return NULL;

  network->ssid = strdup(ssid);
  if (network->ssid == NULL) {
    free(network);
    return NULL;
  }

  network->bssid = strdup(bssid);
  if (network->bssid == NULL) {
    free(network->ssid);
    free(network);
    return NULL;
  }

  network->channel = atoi(channel);
  network->data_rate = atoi(date_rate);
  network->signal_dbm = signal;
  network->noise_dbm = noise;
  network->beacon_interval = atoi(beacon_interval);

  network->capabilities = strdup(capabilities);
  if (network->capabilities == NULL) {
    free(network->bssid);
    free(network->ssid);
    free(network);
    return NULL;
  }

  return network;
}

void free_wifi_network(struct wifi_network *network) {
  if (network == NULL)
    return;
  free(network->capabilities);
  free(network->bssid);
  free(network->ssid);
  free(network);
}

void free_wifi_networks(struct wifi_network **networks) {
  for (int i = 0; networks[i] != NULL; i++)
    free_wifi_network(networks[i]);
  free(networks);
}

struct wifi_network **scan_network_interface(char *interface_name) {
  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s scan", interface_name);
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
    perror("popen failed");
    return NULL;
  }

  char **lines = file_read_lines(fp);
  pclose(fp);
  if (lines == NULL)
    return NULL;
  int line_count = string_array_length(lines);
  if (line_count == 0) {
    free_string_array(lines);
    return NULL;
  }

  char *output = lines_to_string(lines);
  if (strstr(output, "unable to get scan results"))
    return NULL;

  struct wifi_network **wifi_networks =
      calloc(line_count, sizeof(struct wifi_network **));
  for (int i = 1; lines[i] != NULL; i++) {
    wifi_networks[i - 1] = extract_wifi_network(lines[i]);
    if (wifi_networks[i - 1] == NULL) {
      free_wifi_networks(wifi_networks);
      return NULL;
    }
  }
  wifi_networks[line_count - 1] = NULL;

  free(output);
  free_string_array(lines);
  return wifi_networks;
}

int disconnect_network_interface(char *interface_name) {
  guard_root_access();

  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s down", interface_name);
  if (system(command) != 0) {
    fprintf(stderr, "failed to bring %s down\n", interface_name);
    return 1;
  }

  snprintf(command, sizeof(command), "ifconfig %s ssid 'none'", interface_name);
  if (system(command) != 0) {
    fprintf(stderr, "failed to clear SSID on %s\n", interface_name);
    return 1;
  }

  snprintf(command, sizeof(command), "ifconfig %s up", interface_name);
  if (system(command) != 0) {
    fprintf(stderr, "failed to bring %s up\n", interface_name);
    return 1;
  }

  return 0;
}
