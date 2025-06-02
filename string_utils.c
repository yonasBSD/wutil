/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string_utils.h"

int
count_chars(char *string, const char *chars)
{
	int count = 0;

	while (*string) {
		if (strchr(chars, *string++) != NULL)
			count++;
	}

	return (count);
}

char **
split_string(char *string, const char *separators)
{
	const int split_count = count_chars(string, separators) + 1;
	char *string_copy, *to_free;
	char **splits = calloc(split_count + 1, sizeof(char *));

	if (splits == NULL)
		return (NULL);

	string_copy = strdup(string);
	to_free = string_copy;
	if (string_copy == NULL) {
		free(splits);
		return (NULL);
	}

	for (int i = 0; i < split_count; i++) {
		char *token = strsep(&string_copy, separators);

		splits[i] = strdup(token);
		if (splits[i] == NULL) {
			free(to_free);
			free_string_array(splits);
			return (NULL);
		}
	}
	splits[split_count] = NULL;

	free(to_free);
	return (splits);
}

void
free_string_array(char **strings)
{
	for (int i = 0; strings[i] != NULL; i++)
		free(strings[i]);
	free(strings);
}

int
remove_matching_strings(char **strings, const char *pattern)
{
	int new_end;
	regex_t regex;

	if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0)
		return 1;

	new_end = 0;
	for (int i = 0; strings[i] != NULL; i++) {
		if (regexec(&regex, strings[i], 0, NULL, 0) == 0)
			free(strings[i]);
		else
			strings[new_end++] = strings[i];
	}
	strings[new_end] = NULL;

	regfree(&regex);
	return (0);
}

bool
string_array_contains(char **strings, char *pattern)
{
	for (int i = 0; strings[i] != NULL; i++) {
		if (strcmp(strings[i], pattern) == 0)
			return true;
	}
	return (false);
}

char **
file_read_lines(FILE *fp)
{
	int capacity = 10, line_count = 0;
	char buffer[1024];
	char **lines = calloc(capacity + 1, sizeof(char *));

	if (lines == NULL)
		return (NULL);

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (line_count == capacity) {
			char **new_lines;

			capacity *= 2;
			new_lines = realloc(lines,
			    (capacity + 1) * sizeof(char *));

			if (new_lines == NULL) {
				free_string_array(lines);
				return (NULL);
			}
			lines = new_lines;
		}

		lines[line_count] = strdup(buffer);
		if (lines[line_count] == NULL) {
			free_string_array(lines);
			return (NULL);
		}
		line_count++;
	}
	lines[line_count] = NULL;

	return (lines);
}

char *
strcatdup(char *s1, char *s2)
{
	char *new_s;

	if (s1 == NULL && s2 == NULL)
		return (NULL);
	if (s1 == NULL)
		return (strdup(s2));
	if (s2 == NULL)
		return (strdup(s1));

	new_s = malloc(strlen(s1) + strlen(s2) + 1);
	if (new_s == NULL)
		return (NULL);

	strcpy(new_s, s1);
	strcat(new_s, s2);

	return (new_s);
}

char *
lines_to_string(char **lines)
{
	char *string;

	if (lines == NULL)
		return (NULL);

	string = strdup(*lines);
	if (string == NULL)
		return (NULL);

	for (int i = 1; lines[i] != NULL; i++) {
		char *concatenated = strcatdup(string, lines[i]);

		if (concatenated == NULL) {
			free(string);
			return (NULL);
		}
		free(string);

		string = concatenated;
	}
	return (string);
}

int
string_array_length(char **strings)
{
	int count = 0;

	while (*strings++ != NULL)
		count++;

	return (count);
}

int
strncatf(char *dest, size_t dest_size, const char *format, ...)
{
	int write_size;
	char *tmp;
	size_t catable_size;

	va_list args, args_copy;
	va_start(args, format);

	va_copy(args_copy, args);
	write_size = vsnprintf(NULL, 0, format, args_copy);
	va_end(args_copy);

	if (write_size < 0)
		return (write_size);
	write_size++; /* \0 terminator */

	tmp = malloc(write_size);
	if (tmp == NULL) {
		va_end(args);
		return (-1);
	}
	vsnprintf(tmp, write_size, format, args);
	va_end(args);

	catable_size = dest_size - strlen(dest) - 1;
	if (catable_size > 0)
		strncat(dest, tmp, catable_size);
	else
		write_size = -1;

	free(tmp);
	return (write_size);
}
