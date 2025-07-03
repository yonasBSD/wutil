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

#include <err.h>
#include <lib80211/lib80211_ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "string_utils.h"
#include "utils.h"

static char *caps_to_str(int capinfo, char *capstr);
static int map_gsm_freq(uint16_t freq, uint16_t flags);
static int freq_to_chan(uint16_t freq, uint16_t flags);
static int lib80211_set_ssid(int sockfd, const char *ifname, const char *ssid);

void
scan_and_wait(int rt_sockfd, const char *ifname)
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
get_scan_results(int rt_sockfd, const char *ifname)
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
connect_with_wpa(const char *ifname, const char *ssid)
{
	int ret = 0;
	char command[256];

	guard_root_access();

	ret = system("killall wpa_supplicant > /dev/null 2>&1");
	if (ret != 0)
		return (1);

	if (set_ssid(ifname, ssid) != 0)
		return (1);

	snprintf(command, sizeof(command),
	    "wpa_supplicant -B -i %s -c /etc/wpa_supplicant.conf > /dev/null 2>&1",
	    ifname);
	return (system(command));
}

bool
is_ssid_configured(const char *ssid)
{
	bool is_configured;
	char *wpa_supplicant_conf, **conf_lines;
	FILE *conf_file = fopen("/etc/wpa_supplicant.conf", "r");

	if (conf_file == NULL)
		return (false);

	conf_lines = file_read_lines(conf_file);
	wpa_supplicant_conf = lines_to_string(conf_lines);
	free_string_array(conf_lines);

	is_configured = strstr(wpa_supplicant_conf, ssid);

	free(wpa_supplicant_conf);
	return (is_configured);
}

int
configure_wifi_network(struct wifi_network *network, const char *password)
{
	FILE *conf_file;
	char security[256];

	guard_root_access();

	if (password == NULL)
		password = "";

	if (strstr(network->capabilities, "RSN")) {
		snprintf(security, sizeof(security),
		    "\n key_mgmt=WPA-PSK"
		    "\n proto=RSN"
		    "\n psk=\"%s\"",
		    password);
	} else if (strstr(network->capabilities, "WPA")) {
		snprintf(security, sizeof(security),
		    "\n key_mgmt=WPA-PSK"
		    "\n proto=WPA"
		    "\n psk=\"%s\"",
		    password);
	} else {
		snprintf(security, sizeof(security),
		    "\n key_mgmt=NONE"
		    "\n wep_tx_keyidx=0"
		    "\n wep_key0=%s",
		    password);
	}

	conf_file = fopen("/etc/wpa_supplicant.conf", "a");
	if (conf_file == NULL) {
		perror("failed to open /etc/wpa_supplicant.conf");
		return (1);
	}

	fprintf(conf_file,
	    "\nnetwork={"
	    "\n ssid=\"%s\""
	    "%s"
	    "\n}"
	    "\n",
	    network->ssid, security);

	fclose(conf_file);
	return (0);
}

bool
is_wifi_network_secured(struct wifi_network *network)
{
	if (strstr(network->capabilities, "RSN") ||
	    strstr(network->capabilities, "WPA"))
		return (true);
	return (false);
}
