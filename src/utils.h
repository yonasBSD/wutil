#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

enum connection_state {
  CONNECTED,
  DISCONNECTED,
  UNPLUGGED,
};

extern char *connection_state_to_string[];

struct network_interface {
  char *name;
  enum connection_state state;
};

char **get_network_interface_names();
enum connection_state get_interface_connection_state(char *interface_name);
struct network_interface **get_network_interfaces();
void free_network_intefaces(struct network_interface **interfaces);
int enable_interface(char *interface_name);
int disable_interface(char *interface_name);
int restart_interface(char *interface_name);
bool is_valid_interface(char *interface_name);

#endif
