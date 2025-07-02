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
#include <getopt.h>
#include <ifaddrs.h>
#include <lib80211/lib80211_ioctl.h>
#include <libifconfig.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "string_utils.h"
#include "utils.h"

static void guard_root_access(void);

static int restart_networking(void);

static int configure_ip(char *interface_name,
    struct network_configuration *config);
static int configure_resolvd(struct network_configuration *config);

static int modify_if_flags(int sockfd, const char *ifname, int set_flag,
    int clear_flag);

static void is_ifaddr_af_inet(ifconfig_handle_t *lifh, struct ifaddrs *ifa,
    void *udata);

static enum connection_state get_connection_state(struct ifconfig_handle *lifh,
    struct ifaddrs *ifa);

static char *caps_to_str(int capinfo, char *capstr);

static int map_gsm_freq(uint16_t freq, uint16_t flags);
static int freq_to_chan(uint16_t freq, uint16_t flags);

static int lib80211_set_ssid(int sockfd, const char *ifname, const char *ssid);

const char *connection_state_to_string[] = {
	[CONNECTED] = "Connected",
	[DISCONNECTED] = "Disconnected",
	[UNPLUGGED] = "Unplugged",
	[DISABLED] = "Disabled",
	[NA] = "N/A",
};

enum connection_state
get_interface_connection_state(char *interface_name)
{
	enum connection_state state;
	char command[256];
	FILE *fp;
	char *output, **lines;

	snprintf(command, sizeof(command), "ifconfig %s", interface_name);
	fp = popen(command, "r");
	if (fp == NULL) {
		perror("popen failed");
		exit(1);
	}

	lines = file_read_lines(fp);
	pclose(fp);
	if (lines == NULL)
		exit(1);

	output = lines_to_string(lines);
	free_string_array(lines);
	if (lines == NULL)
		exit(1);

	state = strstr(output, "inet ")	     ? CONNECTED :
	    strstr(output, "status: active") ? DISCONNECTED :
					       UNPLUGGED;
	free(output);
	return (state);
}

char **
get_network_interface_names(void)
{
	FILE *fp = popen("ifconfig -l", "r");
	char **interface_names;
	char buffer[256];
	const char pattern[] =
	    "(enc|lo|fwe|fwip|tap|plip|pfsync|pflog|ipfw|tun|sl|faith|ppp|bridge|wg)"
	    "[0-9]+([[:space:]]*)|vm-[a-z]+([[:space:]]*)";

	if (fp == NULL) {
		perror("popen `ifconfig -l` failed");
		return (NULL);
	}

	if (fgets(buffer, sizeof(buffer), fp) == 0) {
		pclose(fp);
		return (NULL);
	}
	pclose(fp);

	buffer[strcspn(buffer, "\n")] = '\0';
	interface_names = split_string(buffer, " ");
	if (interface_names == NULL)
		return (NULL);

	if (remove_matching_strings(interface_names, pattern) != 0) {
		free_string_array(interface_names);
		return (NULL);
	}

	return (interface_names);
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

struct network_interface **
get_network_interfaces(void)
{
	int interfaces_count = 0;
	char **interface_names = get_network_interface_names();
	struct network_interface **interfaces;

	while (interface_names[interfaces_count] != NULL)
		interfaces_count++;

	interfaces = calloc(sizeof(struct network_interface *),
	    interfaces_count + 1);
	for (int i = 0; interface_names[i] != NULL; i++) {
		interfaces[i] = malloc(sizeof(struct network_interface));
		interfaces[i]->name = interface_names[i];

		memset(interfaces[i]->connected_ssid, 0,
		    IEEE80211_NWID_LEN + 1);
		if (get_ssid(interfaces[i]->name, interfaces[i]->connected_ssid,
			IEEE80211_NWID_LEN) != 0)
			interfaces[i]->connected_ssid[0] = '\0';

		interfaces[i]->state = get_interface_connection_state(
		    interfaces[i]->name);
	}
	interfaces[interfaces_count] = NULL;
	free(interface_names);

	return (interfaces);
}

void
free_network_interface(struct network_interface *interface)
{
	free(interface->name);
	free(interface);
}

static void
guard_root_access(void)
{
	if (geteuid() != 0) {
		warnx("insufficient permissions");
		exit(EXIT_FAILURE);
	}
}

static int
modify_if_flags(int sockfd, const char *ifname, int set_flag, int clear_flag)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl SIOCGIFFLAGS failed");
		return (-1);
	}

	ifr.ifr_flags |= set_flag;
	ifr.ifr_flags &= ~clear_flag;

	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
		perror("ioctl SIOCSIFFLAGS failed");

	return (0);
}

int
enable_interface(const char *ifname)
{
	int ret = 0;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0)
		return (-1);

	ret = modify_if_flags(sockfd, ifname, IFF_UP, 0);

	close(sockfd);

	return (ret);
}

int
disable_interface(const char *ifname)
{
	int ret = 0;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0)
		return (-1);

	ret = modify_if_flags(sockfd, ifname, 0, IFF_UP);

	close(sockfd);

	return (ret);
}

int
restart_interface(char *interface_name)
{
	char command[256];

	guard_root_access();

	snprintf(command, sizeof(command),
	    "service netif restart %s > /dev/null 2>&1", interface_name);
	return (system(command));
}

bool
is_valid_interface(const char *ifname)
{
	bool is_valid;
	regex_t ignored_ifaces;

	if (ifname == NULL)
		return (false);

	is_valid = if_nametoindex(ifname); /* returns 0 if invalid i.e false */

	regcomp_ignored_ifaces(&ignored_ifaces);
	if (regexec(&ignored_ifaces, ifname, 0, NULL, 0) == 0)
		is_valid = false;
	regfree(&ignored_ifaces);

	return (is_valid);
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
free_wifi_networks_list(struct wifi_network_list *head)
{
	struct wifi_network *entry, *tmp;
	STAILQ_FOREACH_SAFE(entry, head, next, tmp)
		free(entry);
	free(head);
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
is_ssid_configured(char *ssid)
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

void
free_network_configuration(struct network_configuration *configuration)
{
	if (configuration == NULL)
		return;

	free(configuration->ip);
	free(configuration->netmask);
	free(configuration->gateway);
	free(configuration->dns1);
	free(configuration->dns2);
	free(configuration->search_domain);

	free(configuration);
}

struct network_configuration *
generate_network_configuration(int argc, char **argv)
{
	int opt;
	struct network_configuration *config;
	struct option options[] = {
		{ "method", required_argument, NULL, 'm' },
		{ "ip", required_argument, NULL, 'i' },
		{ "netmask", required_argument, NULL, 'n' },
		{ "gateway", required_argument, NULL, 'g' },
		{ "dns1", required_argument, NULL, 'd' },
		{ "dns2", required_argument, NULL, 's' },
		{ "search", required_argument, NULL, 'r' },
		{ NULL, 0, NULL, 0 },
	};

	config = calloc(1, sizeof(struct network_configuration));
	if (config == NULL)
		return (NULL);

	while ((opt = getopt_long(argc, argv, "m:i:n:g:d:s:r:", options,
		    NULL)) != -1) {
		switch (opt) {
		case 'm':
			if (strcasecmp(optarg, "dhcp") == 0) {
				config->method = DHCP;
			} else if (strcasecmp(optarg, "manual") == 0) {
				config->method = MANUAL;
			} else {
				warnx("invalid method: %s", optarg);
				free_network_configuration(config);
				return (NULL);
			}
			break;
		case 'i':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				warnx(
				    "use --method=manual for manually setting the IP");
				free_network_configuration(config);
				return (NULL);
			}
			config->ip = strdup(optarg);
			break;
		case 'n':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				warnx(
				    "use --method=manual for manually setting the netmask");
				free_network_configuration(config);
				return (NULL);
			}
			config->netmask = strdup(optarg);
			break;
		case 'g':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				warnx(
				    "use --method=manual for manually setting the gateway");
				free_network_configuration(config);
				return (NULL);
			}
			config->gateway = strdup(optarg);
			break;
		case 'd':
			config->dns1 = strdup(optarg);
			break;
		case 's':
			config->dns2 = strdup(optarg);
			break;
		case 'r':
			config->search_domain = strdup(optarg);
			break;
		default:
			warnx("unknown option '%s'",
			    optarg == NULL ? "" : optarg);
			free_network_configuration(config);
			return (NULL);
		}
	}

	if (config->method == MANUAL) {
		if (config->ip == NULL || config->netmask == NULL) {
			warnx(
			    "provide both ip address and netmask for manual configuration");
			free_network_configuration(config);
			return (NULL);
		}
	}

	return (config);
}

static int
restart_networking(void)
{
	int status_code = system("service netif restart");

	if (status_code != 0)
		return (status_code);
	return (system("service routing restart"));
}

/* TODO: properly do it */
static int
configure_ip(char *interface_name, struct network_configuration *config)
{
	int status_code;
	char ip_rc[256] = "sysrc ";

	strncatf(ip_rc, sizeof(ip_rc), "ifconfig_%s=\"%s", interface_name,
	    strstr(interface_name, "wlan") ? "WPA " : "");

	if (config->method == MANUAL)
		strncatf(ip_rc, sizeof(ip_rc), "inet %s netmask %s\"",
		    config->ip, config->netmask);
	else
		strncat(ip_rc, "DHCP\"", sizeof(ip_rc) - strlen(ip_rc) - 1);

	status_code = system(ip_rc);
	if (status_code != 0)
		return (status_code);

	if (config->method == MANUAL) {
		char gateway_rc[256];

		snprintf(gateway_rc, sizeof(gateway_rc),
		    "sysrc defaultrouter=\"%s\"", config->gateway);
		status_code = system(gateway_rc);
	}

	return (status_code);
}

static int
configure_resolvd(struct network_configuration *config)
{
	FILE *config_file = fopen("/etc/resolv.conf", "w");

	if (config_file == NULL) {
		perror("failed to open /etc/resolv.conf");
		return (1);
	}

	fprintf(config_file, "# Generated by wutil\n");
	if (config->search_domain != NULL)
		fprintf(config_file, "search %s\n", config->search_domain);

	if (config->dns1 != NULL)
		fprintf(config_file, "nameserver %s\n", config->dns1);

	if (config->dns2 != NULL)
		fprintf(config_file, "nameserver %s\n", config->dns2);

	fclose(config_file);
	return (0);
}

int
configure_nic(char *interface_name, struct network_configuration *config)
{
	int status_code;

	guard_root_access();

	if (config->method != UNCHANGED &&
	    (status_code = configure_ip(interface_name, config)) != 0)
		return (status_code);

	if (config->dns1 != NULL || config->dns2 != NULL ||
	    config->search_domain != NULL) {
		printf("configuring resolvd...\n");
		status_code = configure_resolvd(config);
	}

	restart_networking();
	return (status_code);
}

static void
is_ifaddr_af_inet(ifconfig_handle_t *lifh, struct ifaddrs *ifa, void *udata)
{
	bool *is_af_inet = udata;

	(void)lifh;

	if (is_af_inet == NULL)
		return;

	if (ifa->ifa_addr->sa_family == AF_INET ||
	    ifa->ifa_addr->sa_family == AF_INET6) {
		*is_af_inet = true;
	}
}

static enum connection_state
get_connection_state(struct ifconfig_handle *lifh, struct ifaddrs *ifa)
{
	bool is_interface_online = false;
	struct ifmediareq *ifmr;
	enum connection_state state = NA;
	const char *status;

	if (lifh == NULL || ifa == NULL)
		return (NA);

	ifconfig_foreach_ifaddr(lifh, ifa, is_ifaddr_af_inet,
	    &is_interface_online);

	if (ifconfig_media_get_mediareq(lifh, ifa->ifa_name, &ifmr) != 0)
		return (NA);

	status = ifconfig_media_get_status(ifmr);
	if (strncmp("wlan", ifa->ifa_name, strlen("wlan")) == 0) {
		state = (ifa->ifa_flags & IFF_UP) == 0 ? DISABLED :
		    strcmp(status, "associated") == 0 && is_interface_online ?
							 CONNECTED :
							 DISCONNECTED;
	} else if (strcmp(status, "active") == 0) {
		state = is_interface_online ? CONNECTED : DISCONNECTED;
	} else {
		state = UNPLUGGED;
	}

	free(ifmr);
	return (state);
}

void
print_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa, void *udata)
{
	regex_t *ignore = udata;
	enum connection_state state;
	char ssid[IEEE80211_NWID_LEN + 1] = { 0 };

	if (ignore != NULL && regexec(ignore, ifa->ifa_name, 0, NULL, 0) == 0)
		return;

	state = get_connection_state(lifh, ifa);
	if (get_ssid(ifa->ifa_name, ssid, IEEE80211_NWID_LEN) != 0)
		ssid[0] = '\0';

	printf("%-10s %-12s %-20s\n", ifa->ifa_name,
	    connection_state_to_string[state], ssid);
}

void
retrieve_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata)
{
	struct network_interface *iface = udata;

	if (iface == NULL || iface->name == NULL ||
	    strcmp(ifa->ifa_name, iface->name) != 0)
		return;

	iface->state = get_connection_state(lifh, ifa);

	memset(iface->connected_ssid, 0, IEEE80211_NWID_LEN + 1);
	if (get_ssid(ifa->ifa_name, iface->connected_ssid,
		IEEE80211_NWID_LEN) != 0)
		iface->connected_ssid[0] = '\0';
}

int
regcomp_ignored_ifaces(regex_t *re)
{
	const char not_nics[] =
	    "(enc|lo|fwe|fwip|tap|plip|pfsync|pflog|ipfw|tun|sl|faith|ppp|bridge|wg)"
	    "[0-9]+([[:space:]]*)|vm-[a-z]+([[:space:]]*)";
	return (regcomp(re, not_nics, REG_EXTENDED | REG_NOSUB) != 0);
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
			free_wifi_networks_list(head);
			break;
		}

		entry->ssid = calloc(result->isr_ssid_len + 1, sizeof(char));
		if (entry->ssid == NULL) {
			perror("calloc failed");
			free(entry);
			free_wifi_networks_list(head);
			break;
		}
		strncpy(entry->ssid, (char *)result + result->isr_ie_off,
		    result->isr_ssid_len);

		entry->bssid = calloc(18, sizeof(char));
		if (entry->bssid == NULL) {
			perror("calloc failed");
			free(entry->ssid);
			free(entry);
			free_wifi_networks_list(head);
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
			free_wifi_networks_list(head);
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
