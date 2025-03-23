#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

enum connection_state {
  CONNECTED,
  DISCONNECTED,
  UNPLUGGED,
};

extern const char *connection_state_to_string[];

struct network_interface {
  char *name;
  enum connection_state state;
  char *connected_ssid;
};

struct wifi_network {
  char *ssid;
  char *bssid;
  int channel;
  int data_rate;
  int signal_dbm;
  int noise_dbm;
  int beacon_interval;
  char *capabilities;
};

char **get_network_interface_names();
enum connection_state get_interface_connection_state(char *interface_name);
struct network_interface *get_network_interface_by_name(char *interface_name);
struct network_interface **get_network_interfaces();
void free_network_interfaces(struct network_interface **interfaces);
int enable_interface(char *interface_name);
int disable_interface(char *interface_name);
int restart_interface(char *interface_name);
bool is_valid_interface(char *interface_name);
struct wifi_network **scan_network_interface(char *interface_name);
void free_wifi_network(struct wifi_network *network);
void free_wifi_networks(struct wifi_network **network);
int disconnect_network_interface(char *interface_name);
char *retrieve_network_interface_connected_ssid(char *interface_name);

#endif
