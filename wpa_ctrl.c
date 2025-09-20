/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 *
 * wpa_supplicant/hostapd control interface library
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * NOTE: This contains code taken as is or modified from
 * wpa_supplicant's src/common/wpa_ctrl.c
 */

#include <stdlib.h>

#include "wpa_ctrl.h"

struct wpa_ctrl *
wpa_ctrl_open(const char *ctrl_path)
{
	return (wpa_ctrl_open2(ctrl_path, NULL));
}


struct wpa_ctrl *
wpa_ctrl_open2(const char *ctrl_path, const char *cli_path)
{
	(void)ctrl_path;
	(void)cli_path;

	return (NULL);
}

void
wpa_ctrl_close(struct wpa_ctrl *ctrl)
{
	(void)ctrl;
}

int
wpa_ctrl_request(struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len,
    char *reply, size_t *reply_len, void (*msg_cb)(char *msg, size_t len))
{
	(void)ctrl;
	(void)cmd;
	(void)cmd_len;
	(void)reply;
	(void)reply_len;
	(void)msg_cb;
	return (0);
}

int
wpa_ctrl_attach(struct wpa_ctrl *ctrl)
{
	(void)ctrl;
	return (0);
}

int
wpa_ctrl_detach(struct wpa_ctrl *ctrl)
{
	(void)ctrl;
	return (0);
}

int
wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len)
{
	(void)ctrl;
	(void)reply;
	(void)reply_len;
	return (0);
}

int
wpa_ctrl_pending(struct wpa_ctrl *ctrl)
{
	(void)ctrl;
	return (0);
}

int
wpa_ctrl_get_fd(struct wpa_ctrl *ctrl)
{
	(void)ctrl;
	return (0);
}
