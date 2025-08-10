/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef USAGE_H
#define USAGE_H

#include <stdbool.h>
#include <stdio.h>

void usage(FILE *fout);
void usage_tui(FILE *fout);

typedef void(usage_f)(FILE *, bool);

#endif
