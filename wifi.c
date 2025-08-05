/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/ioccom.h>
#include <sys/queue.h>
#include <sys/queue_mergesort.h>
#include <sys/sockio.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_freebsd.h>
#include <net80211/ieee80211_ioctl.h>

#include <dirent.h>
#include <err.h>
#include <getopt.h>
#include <lib80211/lib80211_ioctl.h>
#include <readpassphrase.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wpa_ctrl.h>

#include "usage.h"
#include "wifi.h"

static int wpa_ctrl_requestf(struct wpa_ctrl *ctrl, char *reply,
    size_t *reply_len, const char *fmt, ...);
static int wpa_ctrl_ack_request(struct wpa_ctrl *ctrl, char *reply,
    size_t *reply_len, const char *fmt, ...);
static int configure_ssid(struct wpa_ctrl *ctrl, int nwid, const char *ssid,
    const char *identity, const char *password);
static int configure_hidden_ssid(struct wpa_ctrl *ctrl, int nwid,
    const char *identity, const char *password);
static int known_networks_cmp(struct known_network *a, struct known_network *b,
    void *thunk);
static int scan_result_cmp(const struct scan_result *a,
    const struct scan_result *b, void *thunk);

#define WPA_MAX_REPLY_SIZE   4096
#define WPA_BIN_REPLY_SIZE   2	/* sizeof("0") or sizeof("1") */
#define WPA_ACK_REPLY_SIZE   4	/* sizeof("FAIL") for OK or FAIL reply */
#define WPA_INT32_REPLY_SIZE 13 /* snprintf(NULL, 0, "%d\n", INT32_MIN) + 1 */

const char *security_to_string[] = {
	[SEC_OPEN] = "Open",
	[SEC_EAP] = "EAP",
	[SEC_PSK] = "PSK",
	[SEC_NA] = "N/A",
};

struct wpa_command station_cmds[5] = {
	{ "scan", cmd_wpa_scan },
	{ "networks", cmd_wpa_networks },
	{ "status", cmd_wpa_status },
	{ "disconnect", cmd_wpa_disconnect },
	{ "connect", cmd_wpa_connect },
};

struct wpa_command known_network_cmds[4] = {
	{ "list", cmd_known_network_list },
	{ "show", cmd_known_network_show },
	{ "forget", cmd_known_network_forget },
	{ "set", cmd_known_network_set },
};

int
wpa_ctrl_wait(int wpa_fd, const char *wpa_event, struct timespec *timeout)
{
	char buf[4096];
	struct kevent event;
	int kq = kqueue();
	int ret = 0;

	if (kq == -1) {
		warn("kqueue() failed");
		return (1);
	}

	EV_SET(&event, wpa_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &event, 1, NULL, 0, NULL) == -1) {
		warn("kevent register");
		close(kq);
		return (1);
	}

	for (;;) {
		struct kevent tevent;
		int len;

		ret = kevent(kq, NULL, 0, &tevent, 1, timeout);
		if (ret == -1) {
			warn("kevent wait");
			break;
		} else if (ret == 0) {
			warnx("timeout waiting for %s", wpa_event);
			ret = 1;
			break;
		}

		if (tevent.flags & EV_ERROR) {
			warnx("kevent error: %s", strerror(tevent.data));
			ret = 1;
			break;
		}

		len = recv(wpa_fd, buf, sizeof(buf) - 1, 0);
		if (len == -1) {
			warn("recv(wpa_fd)");
			ret = 1;
			break;
		} else if (len == 0) {
			warnx("wpa ctrl_interface socket closed");
			ret = 1;
			break;
		}

		buf[len] = '\0';
		if (strstr(buf, wpa_event) != NULL) {
			ret = 0;
			break;
		}
	}

	close(kq);
	return (ret);
}

int
scan(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "SCAN") != 0) {
		warnx("failed to initiate scan");
		return (1);
	}

	return (0);
}

int
scan_and_wait(struct wpa_ctrl *ctrl)
{
	int wpa_fd = wpa_ctrl_get_fd(ctrl);
	int ret = 0;
	struct timespec timeout = { .tv_sec = 5, .tv_nsec = 0 };

	if (scan(ctrl) != 0) {
		warnx("failed to initiate scan");
		return (1);
	}

	if (wpa_fd == -1) {
		warnx("invalid wpa_ctrl socket");
		return (1);
	}

	if (wpa_ctrl_attach(ctrl) != 0) {
		warnx("failed to register to wpa_ctrl event monitor");
		return (1);
	}

	ret = wpa_ctrl_wait(wpa_fd, WPA_EVENT_SCAN_RESULTS, &timeout);

	wpa_ctrl_detach(ctrl);

	return (ret);
}

char *
wpa_ctrl_default_path(void)
{
	static char path[128];
	char *ret = NULL;
	const char *run_dir = "/var/run/wpa_supplicant";
	DIR *dirp = opendir(run_dir);

	if (dirp == NULL)
		return (NULL);

	for (struct dirent *entry = readdir(dirp); entry != NULL;
	    entry = readdir(dirp)) {
		if (entry->d_type == DT_SOCK) {
			snprintf(path, sizeof(path), "%s/%s", run_dir,
			    entry->d_name);
			ret = path;
			break;
		}
	}

	closedir(dirp);

	return (ret);
}

int
add_network(struct wpa_ctrl *ctrl, const char *ssid)
{
	char reply[WPA_INT32_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	int nwid = -1;
	char *nl;
	const char *errstr;

	if (wpa_ctrl_request(ctrl, "ADD_NETWORK", sizeof("ADD_NETWORK") - 1,
		reply, &reply_len, NULL) != 0)
		return (-1);

	reply[reply_len] = '\0';
	nl = strchr(reply, '\n');
	if (nl != NULL)
		*nl = '\0';
	nwid = strtonum(reply, 0, INT_MAX, &errstr);

	if (errstr != NULL) {
		warnx("(wpa_ctrl) failed to add network");
		return (-1);
	}

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d ssid \"%s\"", nwid, ssid) != 0) {
		warnx("(wpa_ctrl) failed to set ssid(%s) on network id(%d)",
		    ssid, nwid);
		return (-1);
	}

	return (nwid);
}

int
select_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	char req[32] = "SELECT_NETWORK any";

	if (nwid != -1)
		snprintf(req, sizeof(req), "SELECT_NETWORK %d", nwid);

	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, &reply_len, NULL) !=
	    0)
		return (1);

	reply[reply_len] = '\0';

	return (strncmp(reply, "OK", sizeof("OK") - 1) != 0);
}

struct known_networks *
get_known_networks(struct wpa_ctrl *ctrl)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	struct known_networks *nws = NULL;

	if (wpa_ctrl_request(ctrl, "LIST_NETWORKS", strlen("LIST_NETWORKS"),
		reply, &reply_len, NULL) != 0)
		return (NULL);

	nws = malloc(sizeof(*nws));
	if (nws == NULL) {
		warn("malloc");
		return (NULL);
	}

	TAILQ_INIT(nws);

	reply[reply_len] = '\0';

	for (char *brkn,
	    *line = (strtok_r(reply, "\n", &brkn), strtok_r(NULL, "\n", &brkn));
	    line != NULL; line = strtok_r(NULL, "\n", &brkn)) {
		char *brkt;
		/* network id / ssid / bssid / flags */
		char *id_str = strtok_r(line, "\t", &brkt);
		int id = id_str != NULL ? strtol(id_str, NULL, 10) : -1;
		char *ssid = strtok_r(NULL, "\t", &brkt);
		char *bssid = strtok_r(NULL, "\t", &brkt);
		char *flags = strtok_r(NULL, "\t", &brkt);
		struct known_network *nw = calloc(1, sizeof(*nw));

		if (nw == NULL) {
			warn("calloc");
			free_known_networks(nws);
			return (NULL);
		}

		nw->id = id;
		nw->priority = get_network_priority(ctrl, nw->id);
		nw->hidden = is_hidden_network(ctrl, nw->id);
		nw->security = known_network_security(ctrl, nw->id);

		if (ssid != NULL)
			strlcpy(nw->ssid, ssid, sizeof(nw->ssid));

		if (bssid != NULL && ether_aton_r(bssid, &nw->bssid) == NULL)
			nw->bssid = (struct ether_addr) { 0 };

		nw->state = KN_ENABLED;

		if (flags != NULL) {
			if (strstr(flags, "CURRENT") != NULL)
				nw->state = KN_CURRENT;
			else if (strstr(flags, "DISABLED") != NULL)
				nw->state = KN_DISABLED;
		}

		TAILQ_INSERT_TAIL(nws, nw, next);
	}

	TAILQ_MERGESORT(nws, NULL, known_networks_cmp, known_network, next);

	return (nws);
}

static int
known_networks_cmp(struct known_network *a, struct known_network *b,
    void *thunk)
{
	(void)thunk;
	return (b->priority - a->priority);
}

int
known_networks_len(struct known_networks *kns)
{
	int len = 0;
	struct known_network *kn, *kn_tmp;

	TAILQ_FOREACH_SAFE(kn, kns, next, kn_tmp)
		len++;

	return (len);
}

void
free_known_networks(struct known_networks *nws)
{
	struct known_network *nw, *tmp;

	if (nws == NULL)
		return;

	TAILQ_FOREACH_SAFE(nw, nws, next, tmp)
		free(nw);

	free(nws);
}

struct scan_results *
get_scan_results(struct wpa_ctrl *ctrl)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	struct scan_results *srs = NULL;

	if (wpa_ctrl_request(ctrl, "SCAN_RESULTS", strlen("SCAN_RESULTS"),
		reply, &reply_len, NULL) != 0)
		return (NULL);

	srs = malloc(sizeof(*srs));
	if (srs == NULL) {
		warn("malloc");
		return (NULL);
	}

	TAILQ_INIT(srs);

	reply[reply_len] = '\0';

	for (char *brkn,
	    *line = (strtok_r(reply, "\n", &brkn), strtok_r(NULL, "\n", &brkn));
	    line != NULL; line = strtok_r(NULL, "\n", &brkn)) {
		char *brkt;
		/* bssid / frequency / signal level / flags / ssid */
		char *bssid = strtok_r(line, "\t", &brkt);
		char *freq_str = strtok_r(NULL, "\t", &brkt);
		int freq = freq_str != NULL ? strtol(freq_str, NULL, 10) : 0;
		char *signal_str = strtok_r(NULL, "\t", &brkt);
		int signal = signal_str != NULL ? strtol(signal_str, NULL, 10) :
						  0;
		char *flags = strtok_r(NULL, "\t", &brkt);
		char *ssid = strtok_r(NULL, "\t", &brkt);
		struct scan_result *sr = calloc(1, sizeof(*sr));

		if (sr == NULL) {
			warn("calloc");
			free_scan_results(srs);
			return (NULL);
		}

		sr->freq = freq;
		sr->signal = signal;

		if (ssid != NULL)
			strlcpy(sr->ssid, ssid, sizeof(sr->ssid));

		if (bssid != NULL && ether_aton_r(bssid, &sr->bssid) == NULL)
			sr->bssid = (struct ether_addr) { 0 };

		if (flags != NULL) {
			sr->security = strstr(flags, "PSK") != NULL ? SEC_PSK :
			    strstr(flags, "EAP") != NULL	    ? SEC_EAP :
								      SEC_OPEN;
		}

		TAILQ_INSERT_TAIL(srs, sr, next);
	}

	TAILQ_MERGESORT(srs, NULL, scan_result_cmp, scan_result, next);

	return (srs);
}

static int
scan_result_cmp(const struct scan_result *a, const struct scan_result *b,
    void *thunk)
{
	(void)thunk;
	return (b->signal - a->signal);
}

void
remove_hidden_networks(struct scan_results *srs)
{
	struct scan_result *sr, *sr_tmp;

	TAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
		if (sr->ssid[0] == '\0') {
			TAILQ_REMOVE(srs, sr, next);
			free(sr);
		}
	}
}

int
scan_results_len(struct scan_results *srs)
{
	int len = 0;
	struct scan_result *sr, *sr_tmp;

	TAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp)
		len++;

	return (len);
}

void
free_scan_results(struct scan_results *srs)
{
	struct scan_result *sr, *tmp;

	if (srs == NULL)
		return;

	TAILQ_FOREACH_SAFE(sr, srs, next, tmp)
		free(sr);

	free(srs);
}

int
configure_psk(struct wpa_ctrl *ctrl, int nwid, const char *psk)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
	    "SET_NETWORK %d psk \"%s\"", nwid, psk));
}

int
configure_eap(struct wpa_ctrl *ctrl, int nwid, const char *identity,
    const char *password)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d password \"%s\"", nwid, password) != 0)
		return (1);

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d identity \"%s\"", nwid, identity) != 0)
		return (1);

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d key_mgmt WPA-EAP", nwid) != 0)
		return (1);

	return (0);
}

int
configure_ess(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
	    "SET_NETWORK %d key_mgmt NONE", nwid));
}

int
update_config(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET update_config 1") != 0) {
		warnx("(wpa_ctrl) failed to set update_config=1");
		return (1);
	}

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "SAVE_CONFIG") != 0) {
		warnx("(wpa_ctrl) failed to save config");
		return (1);
	}

	return (0);
}

int
cmd_wpa_scan(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if (scan_and_wait(ctrl) != 0) {
		warnx("scan failed");
		return (1);
	}

	return (0);
}

int
cmd_wpa_networks(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	struct scan_results *srs = NULL;
	struct scan_result *sr, *sr_tmp;

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if ((srs = get_scan_results(ctrl)) == NULL) {
		warnx("failed to retrieve scan results");
		return (1);
	}

	remove_hidden_networks(srs);

	printf("%-*s %-8s %-9s %-8s\n", IEEE80211_NWID_LEN, "SSID", "Signal",
	    "Frequency", "Security");
	TAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
		printf("%-*s %4d dBm %5d MHz %-8s\n", IEEE80211_NWID_LEN,
		    sr->ssid, sr->signal, sr->freq,
		    security_to_string[sr->security]);
	}

	free_scan_results(srs);

	return (0);
}

int
reconnect(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "RECONNECT"));
}

int
disconnect(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "DISCONNECT"));
}

int
cmd_wpa_disconnect(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if (disconnect(ctrl) != 0) {
		warnx("failed to disconnect");
		return (1);
	}

	return (0);
}

static int
configure_ssid(struct wpa_ctrl *ctrl, int nwid, const char *ssid,
    const char *identity, const char *password)
{
	struct scan_results *srs = NULL;
	struct scan_result *sr, *sr_tmp;
	char identity_buf[254], password_buf[256];
	int ret = 0;

	if (scan_and_wait(ctrl) != 0) {
		warnx("scan failed");
		ret = 1;
		goto cleanup;
	}

	if ((srs = get_scan_results(ctrl)) == NULL) {
		warnx("failed to retrieve scan results");
		ret = 1;
		goto cleanup;
	}

	TAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
		if (strcmp(sr->ssid, ssid) == 0)
			break;
	}

	if (sr == NULL) {
		warnx("SSID unavailable");
		ret = 1;
		goto cleanup;
	}

	if (sr->security == SEC_PSK) {
		int psk_len;

		if (password == NULL &&
		    (password = readpassphrase("network password: ",
			 password_buf, sizeof(password_buf),
			 RPP_REQUIRE_TTY)) == NULL) {
			warn("failed to read password");
			goto cleanup;
		}

		psk_len = strlen(password);
		if (psk_len < 8 || psk_len > 63) {
			warnx("password must be 8–63 characters");
			goto cleanup;
		}

		ret = configure_psk(ctrl, nwid, password);
	} else if (sr->security == SEC_EAP) {
		if (identity == NULL) {
			printf("network EAP identity: ");
			if (fgets(identity_buf, sizeof(identity_buf), stdin) ==
			    NULL) {
				warnx("failed to read identity");
				goto cleanup;
			}
			identity_buf[strcspn(identity_buf, "\n")] = '\0';
			identity = identity_buf;
		}

		if (password == NULL &&
		    (password = readpassphrase("network EAP password: ",
			 password_buf, sizeof(password_buf),
			 RPP_REQUIRE_TTY)) == NULL) {
			warn("failed to read password");
			goto cleanup;
		}

		ret = configure_eap(ctrl, nwid, identity, password);
	} else {
		ret = configure_ess(ctrl, nwid);
	}

	if (ret != 0) {
		warnx("failed to configure key_mgmt");
		goto cleanup;
	}

cleanup:
	free_scan_results(srs);

	return (ret);
}

static int
configure_hidden_ssid(struct wpa_ctrl *ctrl, int nwid, const char *identity,
    const char *password)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	int ret = 0;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d scan_ssid 1", nwid) != 0)
		return (1);

	if (identity != NULL) {
		char password_buf[256];

		if (password == NULL &&
		    (password = readpassphrase("network EAP password: ",
			 password_buf, sizeof(password_buf),
			 RPP_REQUIRE_TTY)) == NULL) {
			warn("failed to read password");
			return (1);
		}

		ret = configure_eap(ctrl, nwid, identity, password);
	} else if (password != NULL) {
		ret = configure_psk(ctrl, nwid, password);
	} else {
		ret = configure_ess(ctrl, nwid);
	}

	return (ret);
}

int
cmd_wpa_connect(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	int nwid = -1;
	struct known_networks *nws = NULL;
	struct known_network *nw, *nw_tmp;
	const char *ssid;
	const char *identity = NULL, *password = NULL;
	bool hidden = false;
	int opt;
	struct option options[] = {
		{ "identity", required_argument, NULL, 'i' },
		{ "password", required_argument, NULL, 'p' },
		{ "hidden", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "i:p:h", options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			identity = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 'h':
			hidden = true;
			break;
		case '?':
			break;
		default:
			break;
		}
	}

	(void)hidden;

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		warnx("<ssid> not provided");
		return (1);
	}
	ssid = argv[0];

	if (argc == 2 && password == NULL) {
		password = argv[1];
	} else if (argc >= 2) {
		warnx("bad value %s", argv[password != NULL ? 1 : 2]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	TAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0) {
			nwid = nw->id;
			break;
		}
	}

	free_known_networks(nws);

	if (nwid == -1) {
		int config_ret;

		if ((nwid = add_network(ctrl, ssid)) == -1) {
			warnx("failed to create new network");
			return (1);
		}

		config_ret = hidden ?
		    configure_hidden_ssid(ctrl, nwid, identity, password) :
		    configure_ssid(ctrl, nwid, ssid, identity, password);

		if (config_ret != 0) {
			warnx("failed to configure network: %s", ssid);
			remove_network(ctrl, nwid);
			return (1);
		}
	}

	if (select_network(ctrl, nwid) != 0) {
		warnx("failed to select network: %s", ssid);
		return (1);
	}

	if (update_config(ctrl) != 0) {
		warnx("failed to update wpa_supplicant config");
		return (1);
	}

	return (0);
}

int
get_bss_freq(struct wpa_ctrl *ctrl, const char *bssid)
{
	char reply[sizeof("freq=") + WPA_INT32_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	int freq = 0;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len, "BSS %s MASK=%x", bssid,
		WPA_BSS_MASK_FREQ) != 0) {
		warnx("failed to disconnect");
		return (0);
	}

	if (sscanf(reply, "freq=%d", &freq) != 1)
		return (0);

	return (freq);
}

struct supplicant_status *
get_supplicant_status(struct wpa_ctrl *ctrl)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	struct supplicant_status *status;

	if (wpa_ctrl_request(ctrl, "STATUS", strlen("STATUS"), reply,
		&reply_len, NULL) != 0) {
		warnx("failed to disconnect");
		return (NULL);
	}
	reply[reply_len] = '\0';

	if ((status = calloc(1, sizeof(*status))) == NULL)
		return (NULL);

	for (char *brkn, *line = strtok_r(reply, "\n", &brkn); line != NULL;
	    line = strtok_r(NULL, "\n", &brkn)) {
		char *brkt;
		/* key=value */
		char *key = strtok_r(line, "=", &brkt);
		char *value = strtok_r(NULL, "=", &brkt);
		char **status_key = strcmp(key, "bssid") == 0 ? &status->bssid :
		    strcmp(key, "ssid") == 0		      ? &status->ssid :
		    strcmp(key, "ip_address") == 0 ? &status->ip_address :
		    strcmp(key, "wpa_state") == 0  ? &status->state :
		    strcmp(key, "key_mgmt") == 0   ? &status->security :
						     NULL;

		if (status_key != NULL &&
		    (*status_key = strdup(value)) == NULL) {
			free_supplicant_status(status);
			return (NULL);
		}
	}

	status->freq = 0;
	if (status->bssid != NULL)
		status->freq = get_bss_freq(ctrl, status->bssid);

	return (status);
}

void
free_supplicant_status(struct supplicant_status *status)
{
	if (status == NULL)
		return;

	free(status->state);
	free(status->bssid);
	free(status->ssid);
	free(status->ip_address);
	free(status->security);
	free(status);
}

int
cmd_wpa_status(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	struct supplicant_status *status = NULL;

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if ((status = get_supplicant_status(ctrl)) == NULL) {
		warnx("failed retrieve wpa_supplicant status");
		return (1);
	}

	printf("%15s: %s\n", "WPA State", status->state);
	if (status->ssid != NULL)
		printf("%15s: %s\n", "Connected SSID", status->ssid);
	if (status->bssid != NULL) {
		printf("%15s: %s\n", "Connected BSSID", status->bssid);
		printf("%15s: %d MHz\n", "Frequency", status->freq);
	}
	if (status->ip_address != NULL)
		printf("%15s: %s\n", "IP Address", status->ip_address);
	if (status->security != NULL)
		printf("%15s: %s\n", "Security", status->security);

	free_supplicant_status(status);

	return (0);
}

static int
wpa_ctrl_requestf(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len,
    const char *fmt, ...)
{
	char req[128];
	va_list ap;

	va_start(ap, fmt);
	if ((size_t)vsnprintf(req, sizeof(req), fmt, ap) >= sizeof(req)) {
		va_end(ap);
		warnx("wpa_ctrl request too long: %s", req);
		return (1);
	}
	va_end(ap);

	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, reply_len, NULL) !=
	    0)
		return (1);
	reply[*reply_len] = '\0';

	return (0);
}

static int
wpa_ctrl_ack_request(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len,
    const char *fmt, ...)
{
	char req[128];
	va_list ap;

	va_start(ap, fmt);
	if ((size_t)vsnprintf(req, sizeof(req), fmt, ap) >= sizeof(req)) {
		va_end(ap);
		warnx("wpa_ctrl request too long: %s", req);
		return (1);
	}
	va_end(ap);

	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, reply_len, NULL) !=
	    0)
		return (1);
	reply[*reply_len] = '\0';

	if (strncmp(reply, "OK", 2) != 0) {
		warnx("wpa_ctrl request failed: %s", req);
		return (1);
	}

	return (0);
}

int
template_cmd_wpa(int argc, char *argv[], struct wpa_command *cmds,
    size_t cmds_len, usage_f usage_handler)
{
	int ret = 0;
	struct wpa_command *cmd = NULL;
	const char *wpa_ctrl_path = wpa_ctrl_default_path();
	struct wpa_ctrl *ctrl;
	int opt;
	struct option opts[] = {
		{ "ctrl-interface", required_argument, NULL, 'c' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "+c:", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			wpa_ctrl_path = optarg;
			break;
		default:
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		warnx("wrong number of arguments");
		if (usage_handler != NULL)
			usage_handler(stderr, true);
		return (1);
	}

	if (wpa_ctrl_path == NULL) {
		warn(
		    "no wpa ctrl interface on default path, provide --ctrl-interface");
		return (1);
	}

	for (size_t i = 0; i < cmds_len; i++) {
		if (strcmp(argv[0], cmds[i].name) == 0) {
			cmd = &cmds[i];
			break;
		}
	}

	if (cmd == NULL) {
		warnx("Unknown subcommand: %s", argv[0]);
		usage_handler(stderr, true);
		return (1);
	}

	if ((ctrl = wpa_ctrl_open(wpa_ctrl_path)) == NULL) {
		warn("failed to open wpa_supplicant control interface, %s",
		    wpa_ctrl_path);
		return (1);
	}

	ret = cmd->handler(ctrl, argc, argv);

	wpa_ctrl_close(ctrl);

	return (ret);
}

enum security
known_network_security(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len,
		"GET_NETWORK %d key_mgmt", nwid) != 0)
		return (SEC_NA);

	return (strstr(reply, "PSK") != NULL  ? SEC_PSK :
		strstr(reply, "EAP") != NULL  ? SEC_EAP :
		strstr(reply, "NONE") != NULL ? SEC_OPEN :
						SEC_NA);
}

bool
is_hidden_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_BIN_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len,
		"GET_NETWORK %d scan_ssid", nwid) != 0)
		return (false);

	return (reply[0] == '1');
}

int
get_network_priority(struct wpa_ctrl *ctrl, int nwid)
{
	int priority;
	char *endptr;
	char reply[WPA_INT32_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len,
		"GET_NETWORK %d priority", nwid) != 0)
		return (SEC_NA);

	priority = strtol(reply, &endptr, 10);

	if (*endptr != '\0')
		return (-1);

	return (priority);
}

int
cmd_known_network_list(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	struct known_network *nw, *nw_tmp;
	struct known_networks *nws = get_known_networks(ctrl);

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if (nws == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	printf("  %-*s %-8s %-6s %-8s\n", IEEE80211_NWID_LEN, "SSID",
	    "Security", "Hidden", "Priority");
	TAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		printf("%c %-*s %-8s %-6s %8d\n",
		    nw->state == KN_CURRENT ? '>' : ' ', IEEE80211_NWID_LEN,
		    nw->ssid, security_to_string[nw->security],
		    nw->hidden ? "Yes" : "", nw->priority);
	}

	free_known_networks(nws);

	return (0);
}

int
cmd_known_network_show(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	struct known_network *nw, *nw_tmp;
	struct known_networks *nws = NULL;
	const char *ssid;

	if (argc < 2) {
		warnx("<network> not provided");
		return (1);
	}
	ssid = argv[1];

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	TAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0)
			break;
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	printf("%12s: %s\n", "Network SSID", nw->ssid);
	printf("%12s: %s\n", "Security", security_to_string[nw->security]);
	printf("%12s: %s\n", "Hidden", nw->hidden ? "Yes" : "No");
	printf("%12s: %d\n", "Priority", nw->priority);
	printf("%12s: %s\n", "Autoconnect",
	    nw->state == KN_CURRENT	? "Current" :
		nw->state == KN_ENABLED ? "Yes" :
					  "No");

	free_known_networks(nws);

	return (0);
}

int
remove_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "REMOVE_NETWORK %d",
		nwid) != 0)
		return (1);

	return (0);
}

int
cmd_known_network_forget(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	struct known_network *nw, *nw_tmp;
	struct known_networks *nws = NULL;
	const char *ssid;

	if (argc < 2) {
		warnx("<network> not provided");
		return (1);
	}
	ssid = argv[1];

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	TAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0)
			break;
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	if (remove_network(ctrl, nw->id) != 0) {
		warnx("failed to forget network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	free_known_networks(nws);

	return (0);
}

int
set_autoconnect(struct wpa_ctrl *ctrl, int nwid, bool enable)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "%s_NETWORK %d",
	    enable ? "ENABLE" : "DISABLE", nwid));
}

int
set_priority(struct wpa_ctrl *ctrl, int nwid, int priority)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
	    "SET_NETWORK %d priority %d", nwid, priority));
}

int
cmd_known_network_set(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	int opt, ret = 0;
	int priority = 0;
	bool change_priority = false;
	enum { UNCHANGED, YES, NO } autoconnect = UNCHANGED;
	char *endptr;
	const char *ssid;
	struct known_network *nw, *nw_tmp;
	struct known_networks *nws = NULL;

	struct option options[] = {
		{ "priority", required_argument, NULL, 'p' },
		{ "autoconnect", required_argument, NULL, 'a' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "p:a:", options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			if (strcmp(optarg, "y") == 0 ||
			    strcmp(optarg, "yes") == 0) {
				autoconnect = YES;
			} else if (strcmp(optarg, "n") == 0 ||
			    strcmp(optarg, "no") == 0) {
				autoconnect = NO;
			} else {
				warnx("invalid value '%s' for --autoconnect",
				    optarg);
				return (1);
			}
			break;
		case 'p':
			priority = strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				warnx("invalid value '%s' for --priority",
				    optarg);
				return (-1);
			}
			change_priority = true;
			break;
		case '?':
		default:
			return (1);
		}
	}

	if (optind == 1) {
		warnx("no options were provided");
		usage_known_networks(stderr, true);
		return (1);
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		warnx("<network> not provided");
		return (1);
	}
	ssid = argv[0];

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	TAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0)
			break;
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		ret = 1;
		goto cleanup;
	}

	if (autoconnect != UNCHANGED &&
	    set_autoconnect(ctrl, autoconnect, nw->id) != 0) {
		warnx("failed to set priority");
		ret = 1;
		goto cleanup;
	}

	if (change_priority && set_priority(ctrl, nw->id, priority) != 0) {
		warnx("failed to set priority");
		ret = 1;
		goto cleanup;
	}

cleanup:
	free_known_networks(nws);

	return (ret);
}
