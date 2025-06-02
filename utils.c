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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "string_utils.h"
#include "utils.h"

static void guard_root_access(void);

static struct wifi_network *extract_wifi_network(char *network_info);

static int restart_networking(void);

static int configure_ip(char *interface_name,
    struct network_configuration *config);
static int configure_resolvd(struct network_configuration *config);

const char *connection_state_to_string[] = {
	[CONNECTED] = "Connected",
	[DISCONNECTED] = "Disconnected",
	[UNPLUGGED] = "Unplugged",
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

struct network_interface *
get_network_interface_by_name(char *interface_name)
{
	int count;
	struct network_interface *interface, **interfaces;

	if (interface_name == NULL)
		return (NULL);

	interfaces = get_network_interfaces();
	count = 0;
	while (interfaces[count] != NULL)
		count++;

	interface = NULL;
	for (int i = 0; interfaces[i] != NULL; i++) {
		if (strcmp(interfaces[i]->name, interface_name) == 0) {
			interface = interfaces[i];
			interfaces[i] = interfaces[count - 1];
			interfaces[count - 1] = NULL;
			break;
		}
	}

	free_network_interfaces(interfaces);
	return (interface);
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

char *
retrieve_network_interface_connected_ssid(char *interface_name)
{
	FILE *fp;
	char *ssid, **lines;
	char command[256];

	snprintf(command, sizeof(command), "ifconfig %s", interface_name);
	fp = popen(command, "r");
	if (fp == NULL) {
		perror("popen failed");
		return (NULL);
	}

	lines = file_read_lines(fp);
	pclose(fp);
	if (lines == NULL)
		return (NULL);

	ssid = NULL;
	for (int i = 0; lines[i] != NULL; i++) {
		char *ssid_index = strstr(lines[i], "ssid ");

		if (ssid_index != NULL) {
			char *ssid_start = ssid_index + strlen("ssid ");
			char *ssid_end = strstr(lines[i], " channel");

			ssid = strndup(ssid_start, ssid_end - ssid_start);
			break;
		}
	}

	free_string_array(lines);
	return (ssid);
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
		interfaces[i]->connected_ssid =
		    retrieve_network_interface_connected_ssid(
			interfaces[i]->name);
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
	free(interface->connected_ssid);
	free(interface);
}

void
free_network_interfaces(struct network_interface **interfaces)
{
	for (int i = 0; interfaces[i] != NULL; i++)
		free_network_interface(interfaces[i]);
	free(interfaces);
}

static void
guard_root_access(void)
{
	if (geteuid() != 0) {
		fprintf(stderr, "insufficient permissions\n");
		exit(EXIT_FAILURE);
	}
}

int
enable_interface(char *interface_name)
{
	char command[256];

	guard_root_access();

	snprintf(command, sizeof(command), "ifconfig %s up", interface_name);
	return (system(command));
}

int
disable_interface(char *interface_name)
{
	char command[256];

	guard_root_access();

	snprintf(command, sizeof(command), "ifconfig %s down", interface_name);
	return (system(command));
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
is_valid_interface(char *interface_name)
{
	char **interface_names = get_network_interface_names();
	bool is_valid = string_array_contains(interface_names, interface_name);

	free_string_array(interface_names);
	return (is_valid);
}

static struct wifi_network *
extract_wifi_network(char *network_info)
{
	int signal, noise;
	char beacon_interval[4], bssid[18], channel[5], capabilities[256];
	char date_rate[5], ssid[256], sn[8];
	struct wifi_network *network;

	if (sscanf(network_info, "%255s %17s %4s %4s %7s %3s %[^\n]", ssid,
		bssid, channel, date_rate, sn, beacon_interval,
		capabilities) != 7)
		return (NULL);
	if (sscanf(sn, "%d:%d", &signal, &noise) != 2)
		return (NULL);

	network = malloc(sizeof(struct wifi_network));
	if (network == NULL)
		return (NULL);

	network->ssid = strdup(ssid);
	if (network->ssid == NULL) {
		free(network);
		return (NULL);
	}

	network->bssid = strdup(bssid);
	if (network->bssid == NULL) {
		free(network->ssid);
		free(network);
		return (NULL);
	}

	network->channel = atoi(channel);
	network->data_rate = atoi(date_rate);
	network->signal_dbm = signal;
	network->noise_dbm = noise;
	network->beacon_interval = atoi(beacon_interval);

	network->capabilities = strdup(capabilities);
	if (network->capabilities == NULL) {
		free(network->bssid);
		free(network->ssid);
		free(network);
		return (NULL);
	}

	return (network);
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
free_wifi_networks(struct wifi_network **networks)
{
	for (int i = 0; networks[i] != NULL; i++)
		free_wifi_network(networks[i]);
	free(networks);
}

struct wifi_network **
scan_network_interface(char *interface_name)
{
	int line_count;
	FILE *fp;
	char *output, **lines;
	struct wifi_network **wifi_networks;
	char command[256];

	snprintf(command, sizeof(command), "ifconfig %s scan", interface_name);
	fp = popen(command, "r");
	if (fp == NULL) {
		perror("popen failed");
		return (NULL);
	}

	lines = file_read_lines(fp);
	pclose(fp);
	if (lines == NULL)
		return (NULL);
	line_count = string_array_length(lines);
	if (line_count == 0) {
		free_string_array(lines);
		return (NULL);
	}

	output = lines_to_string(lines);
	if (strstr(output, "unable to get scan results"))
		return (NULL);

	wifi_networks = calloc(line_count, sizeof(struct wifi_network **));
	for (int i = 1; lines[i] != NULL; i++) {
		wifi_networks[i - 1] = extract_wifi_network(lines[i]);
		if (wifi_networks[i - 1] == NULL) {
			free_wifi_networks(wifi_networks);
			return (NULL);
		}
	}
	wifi_networks[line_count - 1] = NULL;

	free(output);
	free_string_array(lines);
	return (wifi_networks);
}

struct wifi_network *
get_wifi_network_by_ssid(char *network_interface, char *ssid)
{
	int count;
	struct wifi_network *network, **networks;

	if (ssid == NULL)
		return (NULL);

	networks = scan_network_interface(network_interface);
	if (networks == NULL)
		return (NULL);

	count = 0;
	while (networks[count] != NULL)
		count++;

	network = NULL;
	for (int i = 0; networks[i] != NULL; i++) {
		if (strcmp(networks[i]->ssid, ssid) == 0) {
			network = networks[i];
			networks[i] = networks[count - 1];
			networks[count - 1] = NULL;
			break;
		}
	}

	free_wifi_networks(networks);
	return (network);
}

int
disconnect_network_interface(char *interface_name)
{
	char command[256];

	guard_root_access();

	snprintf(command, sizeof(command), "ifconfig %s down", interface_name);
	if (system(command) != 0) {
		fprintf(stderr, "failed to bring %s down\n", interface_name);
		return (1);
	}

	snprintf(command, sizeof(command), "ifconfig %s ssid 'none'",
	    interface_name);
	if (system(command) != 0) {
		fprintf(stderr, "failed to clear SSID on %s\n", interface_name);
		return (1);
	}

	snprintf(command, sizeof(command), "ifconfig %s up", interface_name);
	if (system(command) != 0) {
		fprintf(stderr, "failed to bring %s up\n", interface_name);
		return (1);
	}

	return (0);
}

int
connect_to_ssid(char *network_interface, char *ssid)
{
	char command[256];

	guard_root_access();

	if (system("killall wpa_supplicant > /dev/null 2>&1") != 0)
		return (1);

	snprintf(command, sizeof(command),
	    "ifconfig %s ssid '%s' > /dev/null 2>&1", network_interface, ssid);
	if (system(command) != 0)
		return (1);

	snprintf(command, sizeof(command),
	    "wpa_supplicant -B -i %s -c /etc/wpa_supplicant.conf > /dev/null 2>&1",
	    network_interface);
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

	config = malloc(sizeof(struct network_configuration));
	if (config == NULL)
		return (NULL);
	memset(config, 0, sizeof(struct network_configuration));

	while ((opt = getopt_long(argc, argv, "m:i:n:g:d:s:r:", options,
		    NULL)) != -1) {
		switch (opt) {
		case 'm':
			if (strcasecmp(optarg, "dhcp") == 0) {
				config->method = DHCP;
			} else if (strcasecmp(optarg, "manual") == 0) {
				config->method = MANUAL;
			} else {
				fprintf(stderr, "invalid method: %s", optarg);
				free_network_configuration(config);
				return (NULL);
			}
			break;
		case 'i':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				fprintf(stderr,
				    "use --method=manual for manually setting the IP\n");
				free_network_configuration(config);
				return (NULL);
			}
			config->ip = strdup(optarg);
			break;
		case 'n':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				fprintf(stderr,
				    "use --method=manual for manually setting the netmask\n");
				free_network_configuration(config);
				return (NULL);
			}
			config->netmask = strdup(optarg);
			break;
		case 'g':
			if (config->method == UNCHANGED ||
			    config->method != MANUAL) {
				fprintf(stderr,
				    "use --method=manual for manually setting the gateway\n");
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
			fprintf(stderr, "unknown option '%s'\n",
			    optarg == NULL ? "" : optarg);
			free_network_configuration(config);
			return (NULL);
		}
	}

	if (config->method == MANUAL) {
		if (config->ip == NULL || config->netmask == NULL) {
			fprintf(stderr,
			    "provide both ip address and netmask for manual configuration\n");
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
