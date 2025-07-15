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

#ifndef CTL_SEQ_H
#define CTL_SEQ_H

#define ESC "\x1B"
#define CSI ESC "["
#define ON  "h"
#define OFF "l"

static const char ALT_BUFFER_ON[] = CSI "?1049" ON;
static const char ALT_BUFFER_OFF[] = CSI "?1049" OFF;
static const char CLEAR_SCREEN[] = CSI "2J";
static const char CURSOR_HOME[] = CSI "H";
static const char CURSOR_SHOW[] = CSI "?25" ON;
static const char CURSOR_HIDE[] = CSI "?25" OFF;
static const char BOLD[] = CSI "1m";
static const char RESET[] = CSI "0m";
static const char FG_GREEN[] = CSI "32m";
static const char FG_WHITE[] = CSI "37m";
static const char FG_YELLOW[] = CSI "33m";
static const char BG_BLACK[] = CSI "40m";
static const char BG_GRAY[] = CSI "100m";
static const char UNDERLINE[] = CSI "4m";
static const char NO_UNDERLINE[] = CSI "24m";

#endif /* !CTL_SEQ_H */
