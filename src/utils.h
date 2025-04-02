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

enum ip_configuration {
	UNCHANGED = 0,
	DHCP,
	MANUAL,
};

struct network_configuration {
	enum ip_configuration method;
	char *ip;
	char *netmask;
	char *gateway;
	char *dns1;
	char *dns2;
	char *search_domain;
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
struct wifi_network *get_wifi_network_by_ssid(char *network_interface,
    char *ssid);
void free_wifi_network(struct wifi_network *network);
void free_wifi_networks(struct wifi_network **network);
int disconnect_network_interface(char *interface_name);
char *retrieve_network_interface_connected_ssid(char *interface_name);
int connect_to_ssid(char *network_interface, char *ssid);
bool is_ssid_configured(char *ssid);
int configure_wifi_network(struct wifi_network *network, char *password);
bool is_wifi_network_secured(struct wifi_network *network);
struct network_configuration *generate_network_configuration(int argc,
    char **argv);
void free_network_configuration(struct network_configuration *configuration);
int configure_nic(char *interface_name, struct network_configuration *config);

#endif
