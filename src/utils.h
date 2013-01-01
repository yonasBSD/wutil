#ifndef UTILS_H
#define UTILS_H

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

#endif
