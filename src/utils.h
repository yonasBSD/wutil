#ifndef UTILS_H
#define UTILS_H

void usage(char *program_name);

int count_chars(char *string, char *chars);
char **split_string(char *string, char *separators);
void free_string_array(char **strings);

#endif
