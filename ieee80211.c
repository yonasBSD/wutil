/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/ioccom.h>
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

#include "ieee80211.h"
#include "usage.h"
#include "utils.h"

static char *caps_to_str(int capinfo, char *capstr);
static int map_gsm_freq(uint16_t freq, uint16_t flags);
static int freq_to_chan(uint16_t freq, uint16_t flags);
static int lib80211_set_ssid(int sockfd, const char *ifname, const char *ssid);
static int get_bss_freq(struct wpa_ctrl *ctrl, const char *bssid);
static int wpa_ctrl_requestf(struct wpa_ctrl *ctrl, char *reply,
    size_t *reply_len, const char *fmt, ...);
static int wpa_ctrl_ack_request(struct wpa_ctrl *ctrl, char *reply,
    size_t *reply_len, const char *fmt, ...);
static int configure_ssid(struct wpa_ctrl *ctrl, int nwid, const char *ssid,
    const char *identity, const char *password);
static int configure_hidden_ssid(struct wpa_ctrl *ctrl, int nwid,
    const char *identity, const char *password);
static enum security known_network_security(struct wpa_ctrl *ctrl, int nwid);
static bool is_hidden_network(struct wpa_ctrl *ctrl, int nwid);
static int get_network_priority(struct wpa_ctrl *ctrl, int nwid);

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

void
scan_and_wait_ioctl(int rt_sockfd, const char *ifname)
{
	struct ieee80211_scan_req req = { 0 };
	int kq;
	struct kevent event;
	struct kevent tevent;
	char hdr[2048];
	struct rt_msghdr *rt_hdr;

	req.sr_flags = IEEE80211_IOC_SCAN_ACTIVE | IEEE80211_IOC_SCAN_BGSCAN |
	    IEEE80211_IOC_SCAN_NOPICK | IEEE80211_IOC_SCAN_ONCE |
	    IEEE80211_IOC_SCAN_FLUSH;
	req.sr_duration = IEEE80211_IOC_SCAN_FOREVER;

	if (lib80211_set80211(rt_sockfd, ifname, IEEE80211_IOC_SCAN_REQ, 0,
		sizeof(req), &req) == -1)
		return;

	kq = kqueue();
	if (kq == -1) {
		perror("kqueue() failed");
		return;
	}

	EV_SET(&event, rt_sockfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &event, 1, NULL, 0, NULL) == -1) {
		perror("kevent registeration failed");
		close(kq);
		return;
	}

	do {
		int ret = kevent(kq, NULL, 0, &tevent, 1, NULL);
		if (ret == -1) {
			perror("kevent wait failed");
			break;
		}

		if (tevent.flags & EV_ERROR) {
			perror("event error");
			break;
		}

		if (read(rt_sockfd, hdr, sizeof(hdr)) < 0) {
			perror("read(PF_ROUTE)");
			break;
		}

		rt_hdr = (void *)hdr;
		if (rt_hdr->rtm_version != RTM_VERSION)
			break;
	} while (!(rt_hdr->rtm_type == RTM_IEEE80211 &&
	    ((struct if_announcemsghdr *)hdr)->ifan_what ==
		RTM_IEEE80211_SCAN));

	close(kq);
}

struct wifi_network_list *
get_scan_results_ioctl(int rt_sockfd, const char *ifname)
{
	int len;
	char buf[24 * 1024];
	struct wifi_network *entry;
	struct wifi_network_list *head = NULL;

	if (lib80211_get80211len(rt_sockfd, ifname, IEEE80211_IOC_SCAN_RESULTS,
		buf, sizeof(buf), &len) != 0) {
		perror("IEEE80211_IOC_SCAN_RESULTS failed");
		return (NULL);
	}

	head = malloc(sizeof(*head));
	if (head == NULL) {
		perror("malloc failed");
		return (NULL);
	}
	STAILQ_INIT(head);

	for (int i = 0; i < len;) {
		struct ieee80211req_scan_result *result = (void *)&buf[i];

		entry = malloc(sizeof(struct wifi_network));
		if (entry == NULL) {
			perror("malloc failed");
			free_wifi_network_list(head);
			break;
		}

		entry->ssid = calloc(result->isr_ssid_len + 1, sizeof(char));
		if (entry->ssid == NULL) {
			perror("calloc failed");
			free(entry);
			free_wifi_network_list(head);
			break;
		}
		strncpy(entry->ssid, (char *)result + result->isr_ie_off,
		    result->isr_ssid_len);

		entry->bssid = calloc(18, sizeof(char));
		if (entry->bssid == NULL) {
			perror("calloc failed");
			free(entry->ssid);
			free(entry);
			free_wifi_network_list(head);
			break;
		}
		ether_ntoa_r((const struct ether_addr *)result->isr_bssid,
		    entry->bssid);

		entry->channel = freq_to_chan(result->isr_freq,
		    result->isr_flags);

		entry->data_rate = -1;
		for (size_t j = 0; j < result->isr_nrates; j++) {
			int rate = IEEE80211_RV(result->isr_rates[j]) / 2;
			if (rate > entry->data_rate)
				entry->data_rate = rate;
		}

		entry->signal_dbm = (result->isr_rssi / 2) + result->isr_noise;
		entry->noise_dbm = result->isr_noise;
		entry->beacon_interval = result->isr_intval;

		entry->capabilities = calloc(12, sizeof(char));
		if (entry->capabilities == NULL) {
			perror("calloc failed");
			free(entry->bssid);
			free(entry->ssid);
			free(entry);
			free_wifi_network_list(head);
			break;
		}
		if (caps_to_str(result->isr_capinfo, entry->capabilities) ==
		    NULL)
			free(entry->capabilities);

		STAILQ_INSERT_TAIL(head, entry, next);

		i += result->isr_len;
	}

	return (head);
}

void
free_wifi_network(struct wifi_network *network)
{
	if (network == NULL)
		return;
	free(network->capabilities);
	free(network->bssid);
	free(network->ssid);
	free(network);
}

void
free_wifi_network_list(struct wifi_network_list *head)
{
	struct wifi_network *entry, *tmp;
	STAILQ_FOREACH_SAFE(entry, head, next, tmp)
		free(entry);
	free(head);
}

static char *
caps_to_str(int capinfo, char *capstr)
{
	struct {
		int bit;
		char c;
	} caps[] = {
		{ IEEE80211_CAPINFO_ESS, 'E' },
		{ IEEE80211_CAPINFO_IBSS, 'I' },
		{ IEEE80211_CAPINFO_CF_POLLABLE, 'c' },
		{ IEEE80211_CAPINFO_CF_POLLREQ, 'C' },
		{ IEEE80211_CAPINFO_PRIVACY, 'P' },
		{ IEEE80211_CAPINFO_SHORT_PREAMBLE, 'S' },
		{ IEEE80211_CAPINFO_PBCC, 'B' },
		{ IEEE80211_CAPINFO_CHNL_AGILITY, 'A' },
		{ IEEE80211_CAPINFO_SHORT_SLOTTIME, 's' },
		{ IEEE80211_CAPINFO_RSN, 'R' },
		{ IEEE80211_CAPINFO_DSSSOFDM, 'D' },
	};
	char *cp = capstr;

	for (size_t i = 0; cp != NULL && i < nitems(caps); i++) {
		if (capinfo & caps[i].bit)
			*cp++ += caps[i].c;
	}
	if (cp == NULL)
		return (NULL);
	*cp = '\0';

	return (capstr);
}

static int
map_gsm_freq(uint16_t freq, uint16_t flags)
{
	freq *= 10;
	if (flags & IEEE80211_CHAN_QUARTER)
		freq += 5;
	else if (flags & IEEE80211_CHAN_HALF)
		freq += 10;
	else
		freq += 20;
	/* NB: there is no 907/20 wide but leave room */
	return (freq - 906 * 10) / 5;
}

static int
freq_to_chan(uint16_t freq, uint16_t flags)
{
#define IS_FREQ_IN_PSB(_freq) ((_freq) > 4940 && (_freq) < 4990)
#define MAPPSB(_freq) \
	(37 + ((freq * 10) + ((freq % 5) == 2 ? 5 : 0) - 49400) / 5)

	if (flags & IEEE80211_CHAN_GSM)
		return (map_gsm_freq(freq, flags));
	if (flags & IEEE80211_CHAN_2GHZ) { /* 2GHz band */
		if (freq == 2484)
			return (14);
		if (freq < 2484)
			return ((int)freq - 2407) / 5;
		else
			return (15 + ((freq - 2512) / 20));
	} else if (flags & IEEE80211_CHAN_5GHZ) { /* 5Ghz band */
		if (freq <= 5000) {
			/* XXX check regdomain? */
			if (IS_FREQ_IN_PSB(freq))
				return (MAPPSB(freq));
			return ((freq - 4000) / 5);
		} else
			return ((freq - 5000) / 5);
	} else { /* either, guess */
		if (freq == 2484)
			return (14);
		if (freq < 2484) {
			if (907 <= freq && freq <= 922)
				return (map_gsm_freq(freq, flags));
			return (((int)freq - 2407) / 5);
		}
		if (freq < 5000) {
			if (IS_FREQ_IN_PSB(freq))
				return (MAPPSB(freq));
			else if (freq > 4900)
				return ((freq - 4000) / 5);
			else
				return (15 + ((freq - 2512) / 20));
		}
		return ((freq - 5000) / 5);
	}
#undef IS_FREQ_IN_PSB
#undef MAPPSB
}

int
get_ssid(const char *ifname, char *ssid, int ssid_len)
{
	int ret;
	int sockfd;

	if (ssid == NULL || ssid_len < IEEE80211_NWID_LEN)
		return (-1);

	sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return (-1);

	ret = lib80211_get80211(sockfd, ifname, IEEE80211_IOC_SSID, ssid,
	    ssid_len);

	close(sockfd);

	return (ret);
}

static int
lib80211_set_ssid(int sockfd, const char *ifname, const char *ssid)
{
	uint8_t im_ssid[IEEE80211_NWID_LEN] = { 0 };
	int len = ssid == NULL ? 0 : strlen(ssid);

	if (len > IEEE80211_NWID_LEN) {
		warn("SSID too long");
		return (-1);
	}

	if (len != 0)
		memcpy(im_ssid, ssid, len);

	return (lib80211_set80211(sockfd, ifname, IEEE80211_IOC_SSID, 0, len,
	    (void *)im_ssid));
}

int
set_ssid(const char *ifname, const char *ssid)
{
	int ret = 0;
	int sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0);

	if (sockfd < 0)
		return (-1);

	ret = modify_if_flags(sockfd, ifname, 0, IFF_UP);
	if (ret != 0) {
		warnx("failed to bring %s down", ifname);
		goto cleanup;
	}

	ret = lib80211_set_ssid(sockfd, ifname, ssid);
	if (ret == -1) {
		warnx("failed to clear SSID on %s", ifname);
	}

	ret = modify_if_flags(sockfd, ifname, IFF_UP, 0);
	if (ret != 0) {
		warnx("failed to bring %s up", ifname);
		goto cleanup;
	}

cleanup:
	close(sockfd);
	return (ret);
}

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
scan_and_wait(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	int wpa_fd = wpa_ctrl_get_fd(ctrl);
	int ret = 0;
	struct timespec timeout = { .tv_sec = 5, .tv_nsec = 0 };

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "SCAN") != 0) {
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

	STAILQ_INIT(nws);

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

		STAILQ_INSERT_TAIL(nws, nw, next);
	}

	return (nws);
}

void
free_known_networks(struct known_networks *nws)
{
	struct known_network *nw, *tmp;

	if (nws == NULL)
		return;

	STAILQ_FOREACH_SAFE(nw, nws, next, tmp)
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

	STAILQ_INIT(srs);

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

		STAILQ_INSERT_TAIL(srs, sr, next);
	}

	return (srs);
}

void
free_scan_results(struct scan_results *srs)
{
	struct scan_result *sr, *tmp;

	if (srs == NULL)
		return;

	STAILQ_FOREACH_SAFE(sr, srs, next, tmp)
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

	printf("%-*s %-8s %-9s %-8s\n", IEEE80211_NWID_LEN, "SSID", "Signal",
	    "Frequency", "Security");
	STAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
		printf("%-*s %4d dBm %5d MHz %-8s\n", IEEE80211_NWID_LEN,
		    sr->ssid, sr->signal, sr->freq,
		    security_to_string[sr->security]);
	}

	free_scan_results(srs);

	return (0);
}

int
cmd_wpa_disconnect(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "DISCONNECT") != 0) {
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

	STAILQ_FOREACH_SAFE(sr, srs, next, sr_tmp) {
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

	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
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
			warnx("failed to configure SSID");
			return (1);
		}
	}

	if (select_network(ctrl, nwid) != 0) {
		warnx("failed to select network");
		return (1);
	}

	if (update_config(ctrl) != 0) {
		warnx("failed to update wpa_supplicant config");
		return (1);
	}

	return (0);
}

static int
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

int
cmd_wpa_status(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	const char *ssid = NULL;
	const char *bssid = NULL;
	const char *ip_address = NULL;
	const char *supplicant_state = NULL;
	const char *security = NULL;

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if (wpa_ctrl_request(ctrl, "STATUS", strlen("STATUS"), reply,
		&reply_len, NULL) != 0) {
		warnx("failed to disconnect");
		return (1);
	}

	reply[reply_len] = '\0';

	for (char *brkn, *line = strtok_r(reply, "\n", &brkn); line != NULL;
	    line = strtok_r(NULL, "\n", &brkn)) {
		char *brkt;
		/* key=value */
		char *key = strtok_r(line, "=", &brkt);
		char *value = strtok_r(NULL, "=", &brkt);

		if (strcmp(key, "bssid") == 0)
			bssid = value;
		else if (strcmp(key, "ssid") == 0)
			ssid = value;
		else if (strcmp(key, "ip_address") == 0)
			ip_address = value;
		else if (strcmp(key, "wpa_state") == 0)
			supplicant_state = value;
	}

	printf("%21s: %s\n", "wpa_supplicant Status", supplicant_state);
	if (bssid != NULL) {
		printf("%21s: %s\n", "Connected BSSID", bssid);
		printf("%21s: %d\n", "Frequency", get_bss_freq(ctrl, bssid));
	}
	if (ssid != NULL)
		printf("%21s: %s\n", "Connected SSID", ssid);
	if (ip_address != NULL)
		printf("%21s: %s\n", "IP Address", ip_address);
	if (security != NULL)
		printf("%21s: %s\n", "Security", security);

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
		    "no ctrl interfaces on default paths, provide --ctrl-interface");
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
		warn("failed to open wpa_supplicant ctrl_interface, %s",
		    wpa_ctrl_path);
		return (1);
	}

	ret = cmd->handler(ctrl, argc, argv);

	wpa_ctrl_close(ctrl);

	return (ret);
}

static enum security
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

static bool
is_hidden_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_BIN_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len,
		"GET_NETWORK %d scan_ssid", nwid) != 0)
		return (false);

	return (reply[0] == '1');
}

static int
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
	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		printf("%c %-*s %-8s %-6s %8d\n",
		    nw->state == KN_CURRENT ? '>' : ' ', IEEE80211_NWID_LEN,
		    nw->ssid,
		    security_to_string[known_network_security(ctrl, nw->id)],
		    is_hidden_network(ctrl, nw->id) ? "Yes" : "",
		    get_network_priority(ctrl, nw->id));
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

	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0)
			break;
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	printf("%12s: %s\n", "Network SSID", nw->ssid);
	printf("%12s: %s\n", "Security",
	    security_to_string[known_network_security(ctrl, nw->id)]);
	printf("%12s: %s\n", "Hidden",
	    is_hidden_network(ctrl, nw->id) ? "Yes" : "No");
	printf("%12s: %d\n", "Priority", get_network_priority(ctrl, nw->id));
	printf("%12s: %s\n", "Autoconnect",
	    nw->state == KN_DISABLED ? "No" : "Yes");

	free_known_networks(nws);

	return (0);
}

int
cmd_known_network_forget(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	struct known_network *nw, *nw_tmp;
	struct known_networks *nws = NULL;
	const char *ssid;
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

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

	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0)
			break;
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "REMOVE_NETWORK %d",
		nw->id) != 0) {
		warnx("failed to forget network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	free_known_networks(nws);

	return (0);
}

int
cmd_known_network_set(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	int opt, ret = 0;
	int priority = 0;
	bool set_priority = false;
	enum { UNCHANGED, YES, NO } autoconnect = UNCHANGED;
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
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
			set_priority = true;
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

	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0)
			break;
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		ret = 1;
		goto cleanup;
	}

	if (autoconnect != UNCHANGED &&
	    wpa_ctrl_ack_request(ctrl, reply, &reply_len, "%s_NETWORK %d",
		autoconnect == YES ? "ENABLE" : "DISABLE", nw->id) != 0) {
		warnx("failed to set priority");
		ret = 1;
		goto cleanup;
	}

	if (set_priority &&
	    wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d priority %d", nw->id, priority) != 0) {
		warnx("failed to set priority");
		ret = 1;
		goto cleanup;
	}

cleanup:
	free_known_networks(nws);

	return (ret);
}
