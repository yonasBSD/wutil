#ifndef STRING_UTILS_H
#define STRING_UTILS_H

#include <stdbool.h>
#include <stdio.h>

int count_chars(char *string, char *chars);
char **split_string(char *string, char *separators);
void free_string_array(char **strings);
int remove_matching_strings(char **strings, const char *pattern);
bool string_array_contains(char **strings, char *pattern);
int string_array_length(char **strings);
char **file_read_lines(FILE *fp);
char *strcatdup(char *s1, char *s2);
char *lines_to_string(char **lines);
int strncatf(char *dest, size_t dest_size, const char *format, ...);

#endif
