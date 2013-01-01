#include "utils.h"

#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int count_chars(char *string, char *chars) {
  int count = 0;
  while (*string) {
    if (strchr(chars, *string++) != NULL)
      count++;
  }
  return count;
}

char **split_string(char *string, char *separators) {
  const int split_count = count_chars(string, separators) + 1;
  char **splits = (char **)calloc(sizeof(char *), split_count + 1);
  if (splits == NULL)
    return NULL;

  char *string_copy = strdup(string), *to_free = string_copy;
  if (string_copy == NULL) {
    free(splits);
    return NULL;
  }

  for (int i = 0; i < split_count; i++) {
    char *token = strsep(&string_copy, separators);
    splits[i] = strdup(token);
    if (splits[i] == NULL) {
      free_string_array(splits);
      return NULL;
    }
  }
  splits[split_count] = NULL;

  return splits;
}

void free_string_array(char **strings) {
  for (char i = 0; strings[i] != NULL; i++)
    free(strings[i]);
  free(strings);
}

int remove_matching_strings(char **strings, const char *pattern) {
  regex_t regex;
  if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0)
    return 1;

  int new_end = 0;
  for (int i = 0; strings[i] != NULL; i++) {
    if (regexec(&regex, strings[i], 0, NULL, 0) == 0)
      free(strings[i]);
    else
      strings[new_end++] = strings[i];
  }
  strings[new_end] = NULL;

  regfree(&regex);
  return 0;
}

bool string_array_contains(char **strings, char *pattern) {
  for (int i = 0; strings[i] != NULL; i++) {
    if (strcmp(strings[i], pattern) == 0)
      return true;
  }
  return false;
}
