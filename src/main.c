#include "string_utils.h"
#include "usage.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cmd_handler_t)(int argc, char **argv);

struct command_t {
  const char *name;
  cmd_handler_t handler;
};

static int cmd_help(int argc, char **argv) {
  usage(argv[0]);
  return 0;
}

static int cmd_list(int argc, char **argv) {
  if (argc > 2) {
    fprintf(stderr, "bad value %s\n", argv[3]);
    return 1;
  }

  struct network_interface **interfaces = get_network_interfaces();
  puts("name\tstate");
  puts("----\t-----");
  for (char i = 0; interfaces[i] != NULL; i++) {
    printf("%s\t%s\n", interfaces[i]->name,
           connection_state_to_string[interfaces[i]->state]);
  }

  free_network_intefaces(interfaces);
  return 0;
}

static int cmd_show(int argc, char **argv) {
  if (argc < 3) {
    fputs("<interface> not provided", stderr);
    return 1;
  }

  if (argc > 3) {
    fprintf(stderr, "bad value %s\n", argv[3]);
    return 1;
  }

  char **interface_names = get_network_interface_names();
  char *interface_name = argv[2];
  if (!string_array_contains(interface_names, interface_name)) {
    fprintf(stderr, "unknown interface %s\n", interface_name);
    return 1;
  }
  free_string_array(interface_names);

  enum connection_state state = get_interface_connection_state(interface_name);
  printf("%s\t%s\n", interface_name, connection_state_to_string[state]);

  return 0;
}

static const struct command_t commands[] = {
    {"help", cmd_help},
    {"list", cmd_list},
    {"show", cmd_show},
    {NULL, NULL},
};

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  for (const struct command_t *cmd = commands; cmd->name != NULL; cmd++) {
    if (strcmp(argv[1], cmd->name) == 0)
      return cmd->handler(argc, argv);
  }

  fprintf(stderr, "unsupported command '%s'\n", argv[1]);
  usage(argv[0]);

  return 1;
}
