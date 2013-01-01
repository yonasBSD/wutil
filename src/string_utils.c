#include "string_utils.h"

#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
