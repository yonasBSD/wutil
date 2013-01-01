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
  FILE *fp = popen("ifconfig -l", "r");
  if (!fp) {
    perror("popen `ifconfig -l` failed");
    pclose(fp);
    return 1;
  }

  char buffer[256];
  if (!fgets(buffer, sizeof(buffer), fp)) {
    pclose(fp);
    return 1;
  }
  pclose(fp);

  buffer[strcspn(buffer, "\n")] = '\0';
  char **interfaces = split_string(buffer, " ");
  if (interfaces == NULL)
    return 1;

  for (char i = 0; interfaces[i] != NULL; i++)
    puts(interfaces[i]);

  free_string_array(interfaces);
  return 0;
}

static const struct command_t commands[] = {
    {"help", cmd_help},
    {"list", cmd_list},
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

  fprintf(stderr, "'%s' is an unknown command or not supported yet\n", argv[1]);
  usage(argv[0]);

  return 1;
}
