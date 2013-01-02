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
  char **splits = calloc(split_count + 1, sizeof(char *));
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

char **file_read_lines(FILE *fp) {
  int capacity = 10;
  char **lines = calloc(capacity + 1, sizeof(char *));
  if (lines == NULL)
    return NULL;

  char buffer[1024];
  int line_count = 0;
  while (fgets(buffer, sizeof(buffer), fp) != NULL) {
    if (line_count == capacity) {
      capacity *= 2;
      char **new_lines = realloc(lines, (capacity + 1) * sizeof(char *));
      if (new_lines == NULL) {
        free_string_array(lines);
        return NULL;
      }
      lines = new_lines;
    }

    lines[line_count] = strdup(buffer);
    if (lines[line_count] == NULL) {
      free_string_array(lines);
      return NULL;
    }
    line_count++;
  }
  lines[line_count] = NULL;

  return lines;
}

char *strcatdup(char *s1, char *s2) {
  if (s1 == NULL && s2 == NULL)
    return NULL;
  if (s1 == NULL)
    return strdup(s2);
  if (s2 == NULL)
    return strdup(s1);

  char *new_s = malloc(strlen(s1) + strlen(s2) + 1);
  if (new_s == NULL)
    return NULL;

  strcpy(new_s, s1);
  strcat(new_s, s2);

  return new_s;
}

char *lines_to_string(char **lines) {
  if (lines == NULL)
    return NULL;
  char *string = strdup(*lines);
  if (string == NULL)
    return NULL;
  for (int i = 1; lines[i] != NULL; i++) {
    char *concatenated = strcatdup(string, lines[i]);
    if (concatenated == NULL) {
      free(string);
      return NULL;
    }
    free(string);
    string = concatenated;
  }
  return string;
}

int string_array_length(char **strings) {
  int count = 0;
  while (*strings++ != NULL) {
    count++;
  }
  return count;
}
