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
#include <lib80211/lib80211_ioctl.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ieee80211.h"
#include "utils.h"

static char *caps_to_str(int capinfo, char *capstr);
static int map_gsm_freq(uint16_t freq, uint16_t flags);
static int freq_to_chan(uint16_t freq, uint16_t flags);
static int lib80211_set_ssid(int sockfd, const char *ifname, const char *ssid);

const char *security_to_string[] = {
	[OPEN] = "Open",
	[EAP] = "EAP",
	[PSK] = "PSK",
};

struct wpa_command station_cmds[5] = {
	{ "scan", cmd_wpa_scan },
	{ "networks", cmd_wpa_networks },
	{ "status", cmd_wpa_status },
	{ "disconnect", cmd_wpa_disconnect },
	{ "connect", cmd_wpa_connect },
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
		return NULL;
	*cp = '\0';

	return capstr;
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
		return map_gsm_freq(freq, flags);
	if (flags & IEEE80211_CHAN_2GHZ) { /* 2GHz band */
		if (freq == 2484)
			return 14;
		if (freq < 2484)
			return ((int)freq - 2407) / 5;
		else
			return 15 + ((freq - 2512) / 20);
	} else if (flags & IEEE80211_CHAN_5GHZ) { /* 5Ghz band */
		if (freq <= 5000) {
			/* XXX check regdomain? */
			if (IS_FREQ_IN_PSB(freq))
				return MAPPSB(freq);
			return (freq - 4000) / 5;
		} else
			return (freq - 5000) / 5;
	} else { /* either, guess */
		if (freq == 2484)
			return 14;
		if (freq < 2484) {
			if (907 <= freq && freq <= 922)
				return map_gsm_freq(freq, flags);
			return ((int)freq - 2407) / 5;
		}
		if (freq < 5000) {
			if (IS_FREQ_IN_PSB(freq))
				return MAPPSB(freq);
			else if (freq > 4900)
				return (freq - 4000) / 5;
			else
				return 15 + ((freq - 2512) / 20);
		}
		return (freq - 5000) / 5;
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
	char buf[4096];
	size_t len = sizeof(buf) - 1;
	int wpa_fd = wpa_ctrl_get_fd(ctrl);
	int ret = 0;
	struct timespec timeout = { .tv_sec = 5, .tv_nsec = 0 };

	if (wpa_ctrl_request(ctrl, "SCAN", sizeof("SCAN") - 1, buf, &len,
		NULL) != 0) {
		warnx("failed to request wpa_ctrl SCAN");
		return (1);
	}
	buf[len] = '\0';

	if (strncmp(buf, "OK", sizeof("OK") - 1) != 0) {
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
		return NULL;

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
add_network(struct wpa_ctrl *ctrl, struct scan_result *sr)
{
	char reply[4096], req[64];
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

	if ((size_t)snprintf(req, sizeof(req), "SET_NETWORK %d ssid \"%s\"",
		nwid, sr->ssid) >= sizeof(req)) {
		warnx("wpa_ctrl request too long (SET_NETWORK %d ssid %s)",
		    nwid, sr->ssid);
		return (-1);
	}

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, &reply_len, NULL) !=
	    0)
		return (-1);

	reply[reply_len] = '\0';
	if (strncmp(reply, "OK", sizeof("OK") - 1) != 0) {
		warnx("(wpa_ctrl) failed to set ssid(%s) on network id(%d)",
		    sr->ssid, nwid);
		return (-1);
	}

	return (nwid);
}

int
select_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[4096];
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
	char reply[4096];
	size_t reply_len = sizeof(reply);
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
	char reply[4096];
	size_t reply_len = sizeof(reply);
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
			sr->security = strstr(flags, "PSK") != NULL ? PSK :
			    strstr(flags, "EAP") != NULL	    ? EAP :
								      OPEN;
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
	char reply[4096], req[128];
	size_t reply_len = sizeof(reply) - 1;

	if ((size_t)snprintf(req, sizeof(req), "SET_NETWORK %d psk \"%s\"",
		nwid, psk) >= sizeof(req)) {
		warnx(
		    "wpa_ctrl request too long (SET_NETWORK %d psk [REDACTED])",
		    nwid);
		return (1);
	}

	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, &reply_len, NULL) !=
	    0)
		return (1);

	reply[reply_len] = '\0';
	if (strncmp(reply, "OK", sizeof("OK") - 1) != 0) {
		warnx("(wpa_ctrl) failed to set PSK on network id(%d)", nwid);
		return (1);
	}

	return (0);
}

int
configure_ess(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[4096], req[64];
	size_t reply_len = sizeof(reply) - 1;

	snprintf(req, sizeof(req), "SET_NETWORK %d key_mgmt NONE", nwid);
	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, &reply_len, NULL) !=
	    0)
		return (1);

	reply[reply_len] = '\0';
	if (strncmp(reply, "OK", sizeof("OK") - 1) != 0) {
		warnx("(wpa_ctrl) failed to set key_mgmt on network id(%d)",
		    nwid);
		return (1);
	}

	return (0);
}

int
update_config(struct wpa_ctrl *ctrl)
{
	char reply[4096];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_request(ctrl, "SET update_config 1",
		sizeof("SET update_config 1") - 1, reply, &reply_len,
		NULL) != 0)
		return (1);

	reply[reply_len] = '\0';
	if (strncmp(reply, "OK", sizeof("OK") - 1) != 0) {
		warnx("(wpa_ctrl) failed to set update_config=1");
		return (1);
	}

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_request(ctrl, "SAVE_CONFIG", sizeof("SAVE_CONFIG") - 1,
		reply, &reply_len, NULL) != 0)
		return (1);

	reply[reply_len] = '\0';
	if (strncmp(reply, "OK", sizeof("OK") - 1) != 0) {
		warnx("(wpa_ctrl) failed to save config");
		return (1);
	}

	return (0);
}

int
cmd_wpa_scan(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	(void)argc;
	(void)argv;

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

	(void)argc;
	(void)argv;

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
	char reply[4096];
	size_t reply_len = sizeof(reply);

	(void)argc;
	(void)argv;

	if (wpa_ctrl_request(ctrl, "DISCONNECT", strlen("DISCONNECT"), reply,
		&reply_len, NULL) != 0) {
		warnx("failed to disconnect");
		return (1);
	}

	return (0);
}

int
cmd_wpa_connect(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	int ret = 0;
	int nwid = -1;
	struct scan_results *srs = NULL;
	struct scan_result *sr, *sr_tmp;
	struct known_networks *nws = NULL;
	struct known_network *nw, *nw_tmp;
	char *ssid;

	if (argc < 4) {
		warnx("<ssid> not provided");
		return (1);
	}
	ssid = argv[3];

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

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		goto cleanup;
	}

	STAILQ_FOREACH_SAFE(nw, nws, next, nw_tmp) {
		if (strcmp(nw->ssid, ssid) == 0) {
			nwid = nw->id;
			break;
		}
	}

	if (nwid == -1) {
		if ((nwid = add_network(ctrl, sr)) == -1) {
			warnx("failed to create new network");
			goto cleanup;
		}

		if (sr->security ==
		    PSK) { /* TODO: cleanup & check psk length */
			char psk[256] = "";

			if (argc == 5)
				strlcpy(psk, argv[4], sizeof(psk));
			else
				readpassphrase("network password: ", psk,
				    sizeof(psk), RPP_REQUIRE_TTY);

			ret = configure_psk(ctrl, nwid, psk);
		} else {
			ret = configure_ess(ctrl, nwid);
		}

		if (ret != 0) {
			warnx("failed to configure key_mgmt");
			goto cleanup;
		}
	}

	if ((ret = select_network(ctrl, nwid)) != 0) {
		warnx("failed to select network");
	} else {
		ret = update_config(ctrl);
	}

cleanup:
	free_scan_results(srs);
	free_known_networks(nws);

	return (ret);
}

/* TODO: implement */
int
cmd_wpa_status(struct wpa_ctrl *ctrl, int argc, char **argv)
{
	(void)ctrl;
	(void)argc;
	(void)argv;

	return (0);
}
