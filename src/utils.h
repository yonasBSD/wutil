#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

void usage(char *program_name);

int count_chars(char *string, char *chars);
char **split_string(char *string, char *separators);
void free_string_array(char **strings);
int remove_matching_strings(char **strings, const char *pattern);
bool string_array_contains(char **strings, char *pattern);

#endif
