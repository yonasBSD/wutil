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

#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wpa_ctrl.h"

struct wpa_ctrl {
	int s;
	char *sock_dir;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

struct wpa_ctrl *
wpa_ctrl_open(const char *ctrl_path)
{
	return (wpa_ctrl_open2(ctrl_path, NULL));
}

struct wpa_ctrl *
wpa_ctrl_open2(const char *ctrl_path, const char *cli_path)
{
	struct wpa_ctrl *ctrl = NULL;

	if (ctrl_path == NULL)
		return (NULL);

	ctrl = calloc(1, sizeof(*ctrl));
	if (ctrl == NULL)
		return (NULL);

	ctrl->s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    0);
	if (ctrl->s == -1)
		goto failure;

	asprintf(&ctrl->sock_dir, "%s/wpa_ctrl_XXXXXX",
	    cli_path == NULL ? "/tmp" : cli_path);
	if (ctrl->sock_dir == NULL)
		goto failure;

	if (mkdtemp(ctrl->sock_dir) == NULL)
		goto failure;

	ctrl->local.sun_family = AF_UNIX;
	if (snprintf(ctrl->local.sun_path, SUNPATHLEN, "%s/sock",
		ctrl->sock_dir) >= SUNPATHLEN)
		goto failure;
	ctrl->local.sun_len = SUN_LEN(&ctrl->local);

	if (bind(ctrl->s, (struct sockaddr *)&ctrl->local,
		ctrl->local.sun_len) == -1)
		goto failure;

	ctrl->dest.sun_family = AF_UNIX;
	if (strlcpy(ctrl->dest.sun_path, ctrl_path, SUNPATHLEN) >= SUNPATHLEN)
		goto failure;
	ctrl->dest.sun_len = SUN_LEN(&ctrl->dest);

	if (connect(ctrl->s, (struct sockaddr *)&ctrl->dest,
		ctrl->dest.sun_len) == -1)
		goto failure;

	return (ctrl);

failure:
	wpa_ctrl_close(ctrl);

	return (NULL);
}

void
wpa_ctrl_close(struct wpa_ctrl *ctrl)
{
	if (ctrl == NULL)
		return;

	close(ctrl->s);

	if (ctrl->local.sun_path[0] != '\0')
		unlink(ctrl->local.sun_path);

	if (ctrl->sock_dir != NULL) {
		rmdir(ctrl->sock_dir);
		free(ctrl->sock_dir);
	}

	free(ctrl);
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
