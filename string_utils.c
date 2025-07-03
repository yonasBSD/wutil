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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string_utils.h"

void
free_string_array(char **strings)
{
	for (int i = 0; strings[i] != NULL; i++)
		free(strings[i]);
	free(strings);
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
