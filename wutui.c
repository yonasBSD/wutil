/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/queue_mergesort.h>
#include <sys/sbuf.h>
#include <sys/socket.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <wpa_ctrl.h>

#include "ctrl_seq.h"
#include "usage.h"
#include "wifi.h"

#define WRAPPED_INCR(var, max)	   ((var) = ((var) + 1) % (max))
#define WRAPPED_DECR(var, max)	   ((var) = ((var) - 1 + (max)) % (max))

#define CLAMP(val, minval, maxval) MAX((minval), MIN((val), (maxval)))
#define SUB_CLAMP_ZERO(a, b)	   ((a) < (b) ? 0 : (a) - (b))

enum handler_return { HANDLER_CONTINUE, HANDLER_BREAK };

typedef enum handler_return (*handler_f)(void *udata);

struct event_handler {
	uintptr_t ident;
	handler_f handler;
	void *udata;
	SLIST_ENTRY(event_handler) next;
};

SLIST_HEAD(event_handlers, event_handler);

struct notification {
	char *msg;
	TAILQ_ENTRY(notification) next;
};

TAILQ_HEAD(notifications, notification);

struct wutui {
	int tty, wpa_fd, kq;
	bool show_help, is_window_small, show_dialog, hide_dialog_text;
	const char *dialog_title, *dialog_text;
	struct termios cooked;
	struct wpa_ctrl *ctrl;
	struct winsize winsize;
	enum { SECTION_KN = 0, SECTION_NS } section;
	size_t selected_kn, selected_sr;
	size_t kn_offset, sr_offset;
	struct supplicant_status *status;
	struct scan_results *srs;
	struct known_networks *kns;
	struct event_handlers *handlers;
	struct notifications *notifications;
};

enum wutui_key {
	BACKSPACE = 127,
	DEL_KEY = 1000,
	ARROW_UP,
	ARROW_DOWN,
	HOME_KEY,
	END_KEY,
	PAGE_UP,
	PAGE_DOWN
};

enum kqueue_timer { TIMER_NOTIFICATION_CLEANUP, TIMER_PERIODIC_SCAN };

struct keybinding {
	const char *keys;
	const char *desc;
};

static const int timers[] = {
	[TIMER_NOTIFICATION_CLEANUP] = 5 /* seconds */,
	[TIMER_PERIODIC_SCAN] = 30,
};

static struct wutui wutui;

static const int MAX_COLS = 80;
static const int MAX_ROWS = 34;
static const int KN_ENTRIES = 13;
static const size_t SR_ENTRIES = 13;

#define MARGIN (MAX((wutui.winsize.ws_col - MAX_COLS) / 2, 0))

static void parse_args(int argc, char *argv[], const char **ctrl_path);

void register_handler(struct event_handlers *ehs, int ident, handler_f handler,
    void *udata);
void free_handlers(struct event_handlers *ehs);

void register_events(void);

void pop_notification(struct notifications *ns);
void push_notification(struct notifications *ns, const char *msg);
void clear_notifactions(struct notifications *);
void free_notifactions(struct notifications *);

static void init_wutui(const char *ctrl_path);
static void deinit_wutui(void);
static void event_loop(void);
static void wait_kq(struct kevent *tevent);

static void render_tui(void);
static void render_wifi_info(struct sbuf *sb);
static void render_known_networks(struct sbuf *sb);
static void render_network_scan(struct sbuf *sb);
static void render_help(struct sbuf *sb);
static void render_dialog(struct sbuf *sb);

static int render_notification(struct sbuf *sb, const char *msg, int pos);
static void render_notifications(struct sbuf *sb);

static char *input_dialog(const char *title, int min, int max, bool hide_text);

static void heading(struct sbuf *sb, const char *text, bool rounded, int margin,
    int max_cols);
int word_wrap(struct sbuf *sb, const char *text, int width, int start_col,
    int pos);
static void divider(struct sbuf *sb, bool rounded, int margin, int max_cols);
static void draw_margin(struct sbuf *sb, int margin);

static const char *signal_bars(int dbm);

static const char *right_corner_block(int pos, int max_entries, int scrollbar);
static int get_scrollbar_pos(int offset, int entries, int max_entries);

static int fetch_cursor_position(unsigned short *row, unsigned short *col);
static int fetch_winsize(void);

static void disable_raw_mode(void);
static void enter_raw_mode(void);
static void enter_alt_buffer(void);
static void leave_alt_buffer(void);
static void quit(void);

static int wutui_configure_network(struct scan_result *selected_sr);

static void connect_scan_result(void);

void die(const char *, ...);
void diex(const char *, ...);

static int read_key(void);
static enum handler_return handle_notification_cleanup(void *);
static enum handler_return handle_periodic_scan(void *);
static enum handler_return handle_input(void *);
static enum handler_return handle_wpa_event(void *);
static enum handler_return handle_sigwinch(void *);

static void update_scan_results(void);
static void update_known_networks(void);
static void update_supplicant_status(void);

int
main(int argc, char *argv[])
{
	const char *ctrl_path = wpa_ctrl_default_path();

	if (!isatty(STDIN_FILENO))
		errx(EXIT_FAILURE, "not a TTY");

	parse_args(argc, argv, &ctrl_path);
	if (ctrl_path == NULL) {
		errx(EXIT_FAILURE,
		    "no wpa ctrl interface on default path, provide --ctrl-interface");
	}

	init_wutui(ctrl_path);
	enter_raw_mode();
	enter_alt_buffer();

	event_loop();

	return (EXIT_SUCCESS);
}

static void
parse_args(int argc, char *argv[], const char **ctrl_path)
{
	int opt;
	struct option opts[] = {
		{ "ctrl-interface", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "+c:h", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			*ctrl_path = optarg;
			break;
		case 'h':
			usage_tui(stdout);
			exit(EXIT_SUCCESS);
		case '?':
		default:
			usage_tui(stderr);
			exit(EXIT_FAILURE);
		}
	}

	if (argc - optind != 0) {
		warnx("wrong number of arguments");
		usage_tui(stderr);
		exit(EXIT_FAILURE);
	}
}

void
register_handler(struct event_handlers *ehs, int ident, handler_f handler,
    void *udata)
{
	struct event_handler *eh = malloc(sizeof(*eh));

	if (eh == NULL)
		err(EXIT_FAILURE, "malloc");
	eh->ident = ident;
	eh->handler = handler;
	eh->udata = udata;

	SLIST_INSERT_HEAD(ehs, eh, next);
}

void
free_handlers(struct event_handlers *ehs)
{
	struct event_handler *eh, *eh_tmp;

	SLIST_FOREACH_SAFE(eh, ehs, next, eh_tmp)
		free(eh);
	free(ehs);
}

void
register_events(void)
{
	struct kevent events[5];

	EV_SET(&events[0], wutui.tty, EVFILT_READ, EV_ADD, 0, 0, NULL);
	register_handler(wutui.handlers, wutui.tty, handle_input, NULL);

	EV_SET(&events[1], wutui.wpa_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	register_handler(wutui.handlers, wutui.wpa_fd, handle_wpa_event, NULL);

	EV_SET(&events[2], SIGWINCH, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	register_handler(wutui.handlers, SIGWINCH, handle_sigwinch, NULL);

	EV_SET(&events[3], TIMER_NOTIFICATION_CLEANUP, EVFILT_TIMER, EV_ADD,
	    NOTE_SECONDS, timers[TIMER_NOTIFICATION_CLEANUP], NULL);
	register_handler(wutui.handlers, TIMER_NOTIFICATION_CLEANUP,
	    handle_notification_cleanup, NULL);

	EV_SET(&events[4], TIMER_PERIODIC_SCAN, EVFILT_TIMER, EV_ADD,
	    NOTE_SECONDS, timers[TIMER_PERIODIC_SCAN], NULL);
	register_handler(wutui.handlers, TIMER_PERIODIC_SCAN,
	    handle_periodic_scan, NULL);

	if (kevent(wutui.kq, events, nitems(events), NULL, 0, NULL) == -1)
		err(EXIT_FAILURE, "kevent register");
}

void
pop_notification(struct notifications *ns)
{
	struct notification *first = TAILQ_FIRST(ns);

	if (first == NULL)
		return;

	TAILQ_REMOVE_HEAD(ns, next);
	free(first->msg);
	free(first);
}

void
push_notification(struct notifications *ns, const char *msg)
{
	struct notification *notification = NULL;

	if ((notification = malloc(sizeof(*notification))) == NULL)
		die("malloc");

	if ((notification->msg = strdup(msg)) == NULL) {
		free(notification);
		die("strdup");
	}

	TAILQ_INSERT_TAIL(ns, notification, next);
}

void
clear_notifactions(struct notifications *ns)
{
	struct notification *n, *n_tmp;

	TAILQ_FOREACH_SAFE(n, ns, next, n_tmp) {
		TAILQ_REMOVE(ns, n, next);
		free(n->msg);
		free(n);
	}
}

void
free_notifactions(struct notifications *ns)
{
	if (ns == NULL)
		return;

	clear_notifactions(ns);
	free(ns);
}

static void
init_wutui(const char *ctrl_path)
{
	wutui.wpa_fd = wutui.tty = wutui.kq = -1;

	if (atexit(deinit_wutui) != 0)
		err(EXIT_FAILURE, "atexit");

	wutui.notifications = malloc(sizeof(struct notifications));
	if (wutui.notifications == NULL)
		err(EXIT_FAILURE, "malloc");
	TAILQ_INIT(wutui.notifications);

	if ((wutui.ctrl = wpa_ctrl_open(ctrl_path)) == NULL) {
		err(EXIT_FAILURE,
		    "failed to open wpa_supplicant ctrl_interface, %s",
		    ctrl_path);
	}

	if ((wutui.status = get_supplicant_status(wutui.ctrl)) == NULL)
		errx(EXIT_FAILURE, "failed retrieve wpa_supplicant status");

	if ((wutui.kns = get_known_networks(wutui.ctrl)) == NULL)
		errx(EXIT_FAILURE, "failed to retrieve known networks");

	if ((wutui.srs = get_scan_results(wutui.ctrl)) == NULL)
		errx(EXIT_FAILURE, "failed to retrieve scan results");

	if (wpa_ctrl_attach(wutui.ctrl) != 0) {
		err(EXIT_FAILURE,
		    "failed to register to wpa_ctrl event monitor");
	}

	if ((wutui.wpa_fd = wpa_ctrl_get_fd(wutui.ctrl)) == -1)
		err(EXIT_FAILURE, "invalid wpa_ctrl socket");

	if ((wutui.tty = open("/dev/tty", O_RDWR)) == -1)
		err(EXIT_FAILURE, "open(/dev/tty)");

	if (tcgetattr(wutui.tty, &wutui.cooked) == -1)
		err(EXIT_FAILURE, "tcgetattr()");

	if (fetch_winsize() == -1)
		err(EXIT_FAILURE, "failed to fetch terminal winsize");

	if ((wutui.kq = kqueue()) == -1)
		err(EXIT_FAILURE, "kqueue()");

	wutui.handlers = malloc(sizeof(struct event_handlers));
	if (wutui.handlers == NULL)
		err(EXIT_FAILURE, "malloc");
	SLIST_INIT(wutui.handlers);

	register_events();
}

static void
deinit_wutui(void)
{
	if (wutui.tty != -1)
		disable_raw_mode();

	free_handlers(wutui.handlers);
	free_notifactions(wutui.notifications);

	close(wutui.tty);
	close(wutui.kq);

	free_supplicant_status(wutui.status);
	free_known_networks(wutui.kns);
	free_scan_results(wutui.srs);

	wpa_ctrl_detach(wutui.ctrl);
	wpa_ctrl_close(wutui.ctrl);
}

static void
event_loop(void)
{
	struct kevent tevent;

	for (;;) {
		struct event_handler *eh;

		render_tui();
		wait_kq(&tevent);

		SLIST_FOREACH(eh, wutui.handlers, next) {
			if (tevent.ident == eh->ident) {
				if (eh->handler(NULL) == HANDLER_BREAK)
					return;
				break;
			}
		}
	}
}

static void
wait_kq(struct kevent *tevent)
{
	int nev = kevent(wutui.kq, NULL, 0, tevent, 1, NULL);

	if (nev == -1)
		die("kevent wait");

	if (nev > 0 && tevent->flags & EV_ERROR)
		diex("event error: %s", strerror(tevent->data));
}

static void
render_tui(void)
{
	struct sbuf *sb = sbuf_new_auto();

	sbuf_cat(sb, ERASE_IN_DISPLAY(ERASE_ENTIRE) CURSOR_MOVE(1, 1));

	if (wutui.is_window_small) {
		const char msg[] = "Terminal size too small";
		int msg_len = sizeof(msg) - 1;
		int vertical_offset = MAX((wutui.winsize.ws_row - 1) / 2, 0);
		int msg_offset = MAX((wutui.winsize.ws_col - msg_len) / 2, 0);

		sbuf_printf(sb, CURSOR_DOWN_FMT, vertical_offset);
		sbuf_printf(sb, "%*s" BOLD "%s" NORMAL_INTENSITY, msg_offset,
		    "", msg);
	} else {
		int vertical_offset = (wutui.winsize.ws_row - MAX_ROWS) / 2;

		vertical_offset = MAX(vertical_offset, 0);
		sbuf_printf(sb, CURSOR_DOWN_FMT, vertical_offset);

		render_wifi_info(sb);
		render_known_networks(sb);
		render_network_scan(sb);

		divider(sb, true, MARGIN, MAX_COLS);

		render_notifications(sb);

		if (wutui.show_help)
			render_help(sb);

		if (wutui.dialog_title != NULL)
			render_dialog(sb);
	}

	if (sbuf_finish(sb) != 0)
		die("sbuf failed");

	if (write(wutui.tty, sbuf_data(sb), sbuf_len(sb)) != sbuf_len(sb))
		die("write");

	sbuf_delete(sb);
}

static void
render_wifi_info(struct sbuf *sb)
{
	const int FREQ_LEN = sizeof("5180") - 1;
	/* wpa state with max len*/
	const int WPA_STATE_LEN = sizeof("INTERFACE_DISABLED") - 1;
	const int IP_LEN = sizeof("255.255.255.255") - 1;

	heading(sb, "WiFi Info", true, MARGIN, MAX_COLS);
	sbuf_printf(sb,
	    "%*s│  SSID:      %-*s    Frequency:  %*d MHz         │\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN,
	    wutui.status->ssid == NULL ? "N/A" : wutui.status->ssid, FREQ_LEN,
	    wutui.status->freq);
	sbuf_printf(sb,
	    "%*s│  WPA State: %-*s                  IP Address: %-*s  │\r\n",
	    MARGIN, "", WPA_STATE_LEN,
	    wutui.status->state == NULL ? "N/A" : wutui.status->state, IP_LEN,
	    wutui.status->ip_address == NULL ? "N/A" :
					       wutui.status->ip_address);
}

static void
render_known_networks(struct sbuf *sb)
{
	size_t i = 0;
	int scrollbar = -1;
	const int SECURITY_LEN = sizeof("Security") - 1;
	const int HIDDEN_LEN = sizeof("Hidden") - 1;
	const int PRIORITY_LEN = sizeof("Priority") - 1;
	const int AUTO_CONNECT_LEN = sizeof("Auto Connect") - 1;

	if (wutui.selected_kn < wutui.kn_offset)
		wutui.kn_offset = wutui.selected_kn;
	if (wutui.selected_kn >= wutui.kn_offset + KN_ENTRIES)
		wutui.kn_offset = wutui.selected_kn - KN_ENTRIES + 1;

	scrollbar = get_scrollbar_pos(wutui.kn_offset, wutui.kns->len,
	    KN_ENTRIES);

	heading(sb, "Known Networks", false, MARGIN, MAX_COLS);

	sbuf_printf(sb,
	    "%*s│  " BOLD COLOR(FG,
		BLUE) "%-*s  Security  Hidden  Priority  Auto Connect" NORMAL_INTENSITY
		COLOR(FG, DEFAULT_COLOR) "  %s\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN, "SSID",
	    right_corner_block(-1, KN_ENTRIES, scrollbar));

	for (i = wutui.kn_offset;
	    i < wutui.kns->len && i < KN_ENTRIES + wutui.kn_offset; i++) {
		struct known_network *kn = &wutui.kns->items[i];

		sbuf_printf(sb,
		    "%*s│ %s%s%-*s  %-*s  %-*s  %*d  %-*s " REMOVE_INVERT
		    " %s\r\n",
		    MARGIN, "",
		    wutui.section == SECTION_KN && i == wutui.selected_kn ?
			INVERT :
			"",
		    kn->state == KN_CURRENT ? ">" : " ", IEEE80211_NWID_LEN,
		    kn->ssid, SECURITY_LEN, security_to_string[kn->security],
		    HIDDEN_LEN, kn->hidden ? "Yes" : "No", PRIORITY_LEN,
		    kn->priority, AUTO_CONNECT_LEN,
		    kn->state == KN_ENABLED	? "Yes" :
			kn->state == KN_CURRENT ? "Current" :
						  "No",
		    right_corner_block(i - wutui.kn_offset, KN_ENTRIES,
			scrollbar));
	}

	for (; i < KN_ENTRIES + wutui.kn_offset; i++)
		sbuf_printf(sb, "%*s│%*s%s\r\n", MARGIN, "", MAX_COLS - 2, "",
		    right_corner_block(i - wutui.kn_offset, KN_ENTRIES,
			scrollbar));
}

static void
render_network_scan(struct sbuf *sb)
{
	size_t i = 0;
	int scrollbar = -1;
	const int SECURITY_LEN = sizeof("Security") - 1;
	const int SIGNAL_LEN = sizeof("Signal") - 1;
	const int FREQ_LEN = sizeof("5180") - 1;

	if (wutui.selected_sr < wutui.sr_offset)
		wutui.sr_offset = wutui.selected_sr;
	if (wutui.selected_sr >= wutui.sr_offset + SR_ENTRIES)
		wutui.sr_offset = wutui.selected_sr - SR_ENTRIES + 1;

	scrollbar = get_scrollbar_pos(wutui.sr_offset, wutui.srs->len,
	    SR_ENTRIES);

	heading(sb, "Network Scan", false, MARGIN, MAX_COLS);
	sbuf_printf(sb,
	    "%*s│  " BOLD COLOR(FG,
		BLUE) "%-*s      Security      Signal      Frequency" NORMAL_INTENSITY
		COLOR(FG, DEFAULT_COLOR) "   %s\r\n",
	    MARGIN, "", IEEE80211_NWID_LEN, "SSID",
	    right_corner_block(-1, SR_ENTRIES, scrollbar));

	for (i = wutui.sr_offset;
	    i < wutui.srs->len && i < SR_ENTRIES + wutui.sr_offset; i++) {
		struct scan_result *sr = &wutui.srs->items[i];

		sbuf_printf(sb,
		    "%*s│ %s %-*s      %-*s       %-*s       %-*d MHz   " REMOVE_INVERT
		    " %s\r\n",
		    MARGIN, "",
		    wutui.section == SECTION_NS && i == wutui.selected_sr ?
			INVERT :
			"",
		    IEEE80211_NWID_LEN, sr->ssid, SECURITY_LEN,
		    security_to_string[sr->security], SIGNAL_LEN,
		    signal_bars(sr->signal), FREQ_LEN, sr->freq,
		    right_corner_block(i - wutui.sr_offset, SR_ENTRIES,
			scrollbar));
	}

	for (; i < SR_ENTRIES + wutui.sr_offset; i++)
		sbuf_printf(sb, "%*s│%*s%s\r\n", MARGIN, "", MAX_COLS - 2, "",
		    right_corner_block(i - wutui.sr_offset, SR_ENTRIES,
			scrollbar));
}

static void
render_help(struct sbuf *sb)
{
	struct keybinding general_keys[] = {
		{ "d", "Disconnect current AP" },
		{ "h", "Toggle help" },
		{ "j/<Down>", "Move down" },
		{ "k/<Up>", "Move up" },
		{ "q", "Quit" },
		{ "r", "Reconnect to known AP" },
		{ "s", "Trigger Scan" },
		{ "Tab", "Switch between sections" },
		{ "<C-l>", "Clear notifications" },
	};
	struct keybinding kn_keys[] = {
		{ "a", "Toggle auto connect" },
		{ "f", "Forget network" },
		{ "<C-a>", "Increase priority" },
		{ "<C-x>", "Decrease priority" },
	};
	struct keybinding ns_keys[] = {
		{ "c", "Connect to network" },
	};
	int max_key_len = sizeof("j/<Down>") - 1;
	int max_desc_len = sizeof("Switch between sections") - 1;
	int max_help_rows = nitems(general_keys) + nitems(kn_keys) +
	    nitems(ns_keys) + 2 /* top and bottom */ + 2 /* section headers*/;
	int max_help_cols = max_key_len + 1 /* space */ + max_desc_len +
	    6 /* 2 * strlen("│  ") */;
	int vertical_offset = MAX((wutui.winsize.ws_row - max_help_rows) / 2,
	    0);
	int help_margin = MAX((wutui.winsize.ws_col - max_help_cols) / 2, 0);

	sbuf_cat(sb, CURSOR_MOVE(1, 1));
	sbuf_printf(sb, CURSOR_DOWN_FMT, vertical_offset);
	sbuf_cat(sb, COLOR(FG, MAGENTA));

	heading(sb, "Help", true, help_margin, max_help_cols);
	for (size_t i = 0; i < nitems(general_keys); i++) {
		draw_margin(sb, help_margin);
		sbuf_printf(sb, "│  %-*s %-*s  │\r\n", max_key_len,
		    general_keys[i].keys, max_desc_len, general_keys[i].desc);
	}

	heading(sb, "Known Networks", false, help_margin, max_help_cols);
	for (size_t i = 0; i < nitems(kn_keys); i++) {
		draw_margin(sb, help_margin);
		sbuf_printf(sb, "│  %-*s %-*s  │\r\n", max_key_len,
		    kn_keys[i].keys, max_desc_len, kn_keys[i].desc);
	}

	heading(sb, "Network Scan", false, help_margin, max_help_cols);
	for (size_t i = 0; i < nitems(ns_keys); i++) {
		draw_margin(sb, help_margin);
		sbuf_printf(sb, "│  %-*s %-*s  │\r\n", max_key_len,
		    ns_keys[i].keys, max_desc_len, ns_keys[i].desc);
	}

	divider(sb, true, help_margin, max_help_cols);
	sbuf_cat(sb, COLOR(FG, DEFAULT_COLOR));
}

static void
render_dialog(struct sbuf *sb)
{
	int dialog_rows = 3 + 2;
	int dialog_cols = MAX_COLS / 2;
	int vertical_offset = MAX((wutui.winsize.ws_row - dialog_rows) / 2, 0);
	int dialog_margin = MAX((wutui.winsize.ws_col - dialog_cols) / 2, 0);
	int text_width = MAX(dialog_cols - 4, 1);
	int text_len = wutui.dialog_text != NULL ? strlen(wutui.dialog_text) :
						   0;
	char stars[text_width];
	const char *text = wutui.dialog_text == NULL || wutui.hide_dialog_text ?
	    stars :
	    (wutui.dialog_text + MAX(0, text_len - text_width));

	memset(stars, 0, text_width);
	if (wutui.dialog_text != NULL && wutui.hide_dialog_text)
		memset(stars, '*', MIN(text_width, text_len));

	sbuf_cat(sb, CURSOR_MOVE(1, 1));
	sbuf_printf(sb, CURSOR_DOWN_FMT, vertical_offset);
	sbuf_cat(sb, COLOR(FG, GREEN));

	heading(sb, wutui.dialog_title, true, dialog_margin, dialog_cols);

	draw_margin(sb, dialog_margin);
	sbuf_printf(sb, "│ %*s │\r\n", text_width, "");

	draw_margin(sb, dialog_margin);
	sbuf_printf(sb,
	    "│ " COLOR(BG_BRIGHT, BLACK) "%-*.*s" COLOR(BG,
		DEFAULT_COLOR) " │\r\n",
	    text_width, text_width, text);

	draw_margin(sb, dialog_margin);
	sbuf_printf(sb, "│ %*s │\r\n", text_width, "");

	divider(sb, true, dialog_margin, dialog_cols);

	sbuf_cat(sb, COLOR(FG, DEFAULT_COLOR));
}

static int
render_notification(struct sbuf *sb, const char *msg, int pos)
{
	int len = strlen(msg);
	int box_width = MIN(len + 4, MAX_COLS / 2);
	int start_col = wutui.winsize.ws_col - box_width + 1;

	sbuf_cat(sb, COLOR(FG, YELLOW));
	sbuf_cat(sb, CURSOR_MOVE(2, 1));
	sbuf_printf(sb, CURSOR_MOVE_FMT "╭", pos, start_col);
	for (int i = 0; i < box_width - 2; i++)
		sbuf_cat(sb, "─");
	sbuf_cat(sb, "╮\r\n");

	pos = word_wrap(sb, msg, box_width - 4, start_col, pos);

	sbuf_printf(sb, CURSOR_MOVE_FMT "╰", ++pos, start_col);
	for (int i = 0; i < box_width - 2; i++)
		sbuf_cat(sb, "─");
	sbuf_cat(sb, "╯\r\n");
	sbuf_cat(sb, COLOR(FG, DEFAULT_COLOR));

	return (pos + 1);
}

static void
render_notifications(struct sbuf *sb)
{
	struct notification *notif, *notif_tmp;
	int pos = 1;

	TAILQ_FOREACH_REVERSE_SAFE(notif, wutui.notifications, notifications,
	    next, notif_tmp) {
		pos = render_notification(sb, notif->msg, pos);
		if (pos * 3 >= MAX_ROWS * 2)
			break;
	}
}

static char *
input_dialog(const char *title, int min, int max, bool hide_text)
{
	struct kevent tevent;
	struct sbuf *input_sb = sbuf_new_auto();
	char *input = NULL;

	wutui.dialog_title = title;
	wutui.hide_dialog_text = hide_text;

	for (;;) {
		render_tui();

		wait_kq(&tevent);

		if (tevent.ident == TIMER_NOTIFICATION_CLEANUP)
			handle_notification_cleanup(NULL);
		else if (tevent.ident == TIMER_PERIODIC_SCAN)
			handle_periodic_scan(NULL);
		else if (tevent.ident == SIGWINCH)
			handle_sigwinch(NULL);
		else if (tevent.ident == (uintptr_t)wutui.wpa_fd)
			handle_wpa_event(NULL);
		else if (tevent.ident == (uintptr_t)wutui.tty) {
			int key = read_key();

			if (key == ESC_CHAR)
				break;
			else if ((key == DEL_KEY || key == BACKSPACE ||
				     key == CTRL('h')) &&
			    input_sb->s_len != 0)
				input_sb->s_len--;
			else if (!iscntrl(key) && key < 128)
				sbuf_putc(input_sb, key);
			else if (key == '\r' && sbuf_len(input_sb) >= min) {
				if (sbuf_len(input_sb) > max) {
					char msg[64];

					snprintf(msg, sizeof(msg),
					    "Input must not exceed %d characters",
					    max);
					push_notification(wutui.notifications,
					    msg);
					break;
				}

				input = strdup(sbuf_data(input_sb));
				if (input == NULL)
					die("strdup");
				break;
			}

			if (sbuf_finish(input_sb) != 0)
				die("sbuf failed");
			wutui.dialog_text = sbuf_data(input_sb);
		}
	}

	wutui.dialog_title = wutui.dialog_text = NULL;
	wutui.hide_dialog_text = false;

	sbuf_delete(input_sb);

	return (input);
}

static void
heading(struct sbuf *sb, const char *text, bool rounded, int margin,
    int max_cols)
{
	int len = strlen(text) + 3; /* == len(─┐%s┌) */
	const char *left_corner = rounded ? "╭" : "├";
	const char *right_corner = rounded ? "╮" : "┤";

	draw_margin(sb, margin);
	sbuf_printf(sb, "%s", left_corner);
	sbuf_printf(sb, "─┐" BOLD "%s" NORMAL_INTENSITY "┌", text);
	for (int i = 0; i < max_cols - 2 - len; i++)
		sbuf_cat(sb, "─");
	sbuf_printf(sb, "%s\r\n", right_corner);
}

static void
divider(struct sbuf *sb, bool rounded, int margin, int max_cols)
{
	const char *left_corner = rounded ? "╰" : "├";
	const char *right_corner = rounded ? "╯" : "┤";

	draw_margin(sb, margin);
	sbuf_printf(sb, "%s", left_corner);
	for (int i = 0; i < max_cols - 2; i++)
		sbuf_cat(sb, "─");
	sbuf_printf(sb, "%s", right_corner);
}

int
word_wrap(struct sbuf *sb, const char *text, int width, int start_col, int pos)
{
	int text_len = strlen(text);
	int i = 0;

	while (i < text_len) {
		int segment = MIN(text_len - i, width);
		char *space = memrchr(text + i, ' ', segment);
		int step = space == NULL ? segment : space - (text + i) + 1;

		if (i + segment == text_len)
			step = segment;

		sbuf_printf(sb, CURSOR_MOVE_FMT, ++pos, start_col);
		sbuf_printf(sb, "│ %-*.*s │\r\n", width, step, text + i);

		i += step;
	}

	return (pos);
}

static void
draw_margin(struct sbuf *sb, int margin)
{
	if (margin > 0)
		sbuf_printf(sb, CURSOR_FORWARD_FMT, margin);
}

static const char *
signal_bars(int dbm)
{
	if (dbm >= -50)
		return ("▂▄▆█");
	if (dbm >= -60)
		return ("▂▄▆▁");
	if (dbm >= -70)
		return ("▂▄▁▁");
	if (dbm >= -80)
		return ("▂▁▁▁");
	return ("▁▁▁▁");
}

static const char *
right_corner_block(int pos, int max_entries, int scrollbar)
{
	return (scrollbar == -1	       ? "│" :
		pos == -1	       ? "↑" :
		pos == max_entries - 1 ? "↓" :
		pos == scrollbar       ? "█" :
					 " ");
}

static int
get_scrollbar_pos(int offset, int entries, int max_entries)
{
	int pos;
	double scroll_ratio;

	if (entries <= max_entries)
		return (-1);

	scroll_ratio = (double)offset / (entries - max_entries);
	pos = round(scroll_ratio * max_entries);

	return (CLAMP(pos, 0, max_entries - 1 /* down arrow */ - 1));
}

static int
fetch_cursor_position(unsigned short *row, unsigned short *col)
{
	char buf[32] = "";

	if (dprintf(wutui.tty, CURSOR_POS) < 0)
		return (-1);

	/* Reply: ESC[<row>;<col>R */
	for (size_t i = 0; i < sizeof(buf) - 1; i++) {
		if (read(wutui.tty, &buf[i], 1) != 1 || buf[i] == 'R')
			break;
	}

	if (buf[0] != CSI[0] || buf[1] != CSI[1] ||
	    sscanf(&buf[2], "%hd;%hd", row, col) != 2)
		return (-1);

	return (0);
}

static int
fetch_winsize(void)
{
	if (ioctl(wutui.tty, TIOCGWINSZ, &wutui.winsize) == -1 ||
	    wutui.winsize.ws_col == 0) {
		if (dprintf(wutui.tty, CURSOR_FORWARD(999) CURSOR_DOWN(999)) <
		    0)
			return (-1);
		return (fetch_cursor_position(&wutui.winsize.ws_row,
		    &wutui.winsize.ws_col));
	}

	wutui.is_window_small = wutui.winsize.ws_col < MAX_COLS ||
	    wutui.winsize.ws_row < MAX_ROWS;

	return (0);
}

static void
disable_raw_mode(void)
{
	if (tcsetattr(wutui.tty, TCSAFLUSH, &wutui.cooked) == -1)
		err(EXIT_FAILURE, "tcsetattr()");
}

static void
enter_raw_mode(void)
{
	struct termios raw = wutui.cooked;

	raw.c_iflag &= ~(BRKINT | INPCK | ISTRIP | ICRNL | IXON);
	raw.c_oflag &= ~(OPOST);
	raw.c_cflag |= CS8;
	raw.c_lflag &= ~(ECHO | ISIG | ICANON | IEXTEN);
	raw.c_cc[VTIME] = raw.c_cc[VMIN] = 0;

	if (tcsetattr(wutui.tty, TCSAFLUSH, &raw) == -1)
		err(EXIT_FAILURE, "tcsetattr()");
}

static void
enter_alt_buffer(void)
{
	if (dprintf(wutui.tty, ALT_BUF_ON CURSOR_HIDE) < 0)
		die("dprintf");
}

static void
leave_alt_buffer(void)
{
	dprintf(wutui.tty, ALT_BUF_OFF CURSOR_SHOW);
}

static void
quit(void)
{
	leave_alt_buffer();
	exit(EXIT_SUCCESS);
}

static int
wutui_configure_network(struct scan_result *selected_sr)
{
	char *identity = NULL;
	char *password = NULL;
	int nwid = add_network(wutui.ctrl, selected_sr->ssid);

	if (nwid == -1)
		diex("failed to create new network");

	switch (selected_sr->security) {
	case SEC_PSK:
		password = input_dialog("Enter the password", PSK_MIN, PSK_MAX,
		    true);
		if (password == NULL)
			goto cancel;
		if (configure_psk(wutui.ctrl, nwid, password))
			goto fail;
		break;
	case SEC_EAP:
		identity = input_dialog("Enter the EAP username", EAP_MIN,
		    EAP_MAX, false);
		if (identity == NULL)
			goto cancel;
		password = input_dialog("Enter the password", EAP_MIN, EAP_MAX,
		    true);
		if (password == NULL) {
			free(identity);
			goto cancel;
		}
		if (configure_eap(wutui.ctrl, nwid, identity, password) != 0)
			goto fail;
		break;
	default:
		if (configure_ess(wutui.ctrl, nwid) != 0)
			goto fail;
		break;
	}

	free(identity);
	free(password);

	return (nwid);

fail:
	remove_network(wutui.ctrl, nwid);
	diex("failed configuring network: %s", selected_sr->ssid);
cancel:
	remove_network(wutui.ctrl, nwid);
	return (-1);
}

static void
connect_scan_result(void)
{
	int nwid = -1;
	struct scan_result *selected_sr = &wutui.srs->items[wutui.selected_sr];

	for (size_t i = 0; i < wutui.kns->len; i++) {
		struct known_network *nw = &wutui.kns->items[i];
		if (strcmp(nw->ssid, selected_sr->ssid) == 0) {
			nwid = nw->id;
			break;
		}
	}

	if (nwid == -1 && (nwid = wutui_configure_network(selected_sr)) == -1)
		return;

	if (select_network(wutui.ctrl, nwid) != 0)
		diex("failed to select network: %s", selected_sr->ssid);

	if (update_config(wutui.ctrl) != 0)
		diex("failed to update config");
}

void
die(const char *fmt, ...)
{
	leave_alt_buffer();

	va_list ap;
	va_start(ap, fmt);
	verr(EXIT_FAILURE, fmt, ap);
	va_end(ap);
}

void
diex(const char *fmt, ...)
{
	leave_alt_buffer();

	va_list ap;
	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
	va_end(ap);
}

static int
read_key(void)
{
	int nread;
	char c;

	while ((nread = read(wutui.tty, &c, 1)) != 1) {
		if (nread == -1 && errno != EAGAIN)
			die("read");
	}

	if (c == ESC_CHAR) {
		char seq[3];

		if (read(wutui.tty, &seq[0], 1) != 1)
			return (c);
		if (read(wutui.tty, &seq[1], 1) != 1)
			return (c);

		if (seq[0] == CSI[1]) {
			if (seq[1] >= '0' && seq[1] <= '9') {
				if (read(wutui.tty, &seq[2], 1) != 1)
					return (ESC_CHAR);

				if (seq[2] == '~') {
					switch (seq[1]) {
					case '1':
					case '7':
						return (HOME_KEY);
					case '3':
						return (DEL_KEY);
					case '4':
					case '8':
						return (END_KEY);
					case '5':
						return (PAGE_UP);
					case '6':
						return (PAGE_DOWN);
					}
				}
			} else {
				switch (seq[1]) {
				case 'A':
					return (ARROW_UP);
				case 'B':
					return (ARROW_DOWN);
				case 'H':
					return (HOME_KEY);
				case 'F':
					return (END_KEY);
				}
			}
		} else if (seq[0] == 'O') {
			switch (seq[1]) {
			case 'H':
				return (HOME_KEY);
			case 'F':
				return (END_KEY);
			}
		}
	}

	return (c);
}

static enum handler_return
handle_notification_cleanup(void *udata)
{
	(void)udata;

	pop_notification(wutui.notifications);
	return (HANDLER_CONTINUE);
}

static enum handler_return
handle_periodic_scan(void *udata)
{
	(void)udata;

	scan(wutui.ctrl);
	return (HANDLER_CONTINUE);
}

static enum handler_return
handle_input(void *udata)
{
	int key = read_key();

	(void)udata;

	if (isalpha(key))
		key = tolower(key);

	if (key == 'q')
		quit();

	if (wutui.is_window_small)
		return (HANDLER_CONTINUE);

	if (wutui.show_help) {
		if (key == 'h')
			wutui.show_help = !wutui.show_help;
		return (HANDLER_CONTINUE);
	}

	switch (key) {
	case 'a':
		if (wutui.section == SECTION_KN && wutui.kns->len != 0) {
			struct known_network *selected =
			    &wutui.kns->items[wutui.selected_kn];

			if (set_autoconnect(wutui.ctrl, selected->id,
				selected->state != KN_ENABLED) != 0)
				diex("failed to set autoconnect");
			update_known_networks();
		}

		if (update_config(wutui.ctrl) != 0)
			diex("failed to update config");
		break;
	case 'c':
		if (wutui.section == SECTION_NS && wutui.srs->len != 0)
			connect_scan_result();
		break;
	case 'd':
		if (disconnect(wutui.ctrl) != 0)
			diex("failed to disconnect");
		update_supplicant_status();
		break;
	case 'f':
		if (wutui.section == SECTION_KN && wutui.kns->len != 0) {
			struct known_network *selected =
			    &wutui.kns->items[wutui.selected_kn];

			if (remove_network(wutui.ctrl, selected->id) != 0) {
				diex("failed to remove network: %s",
				    selected->ssid);
			}

			if (update_config(wutui.ctrl) != 0)
				diex("failed to update config");

			update_known_networks();
		}
		break;
	case 'h':
		wutui.show_help = !wutui.show_help;
		break;
	case ARROW_DOWN:
	case 'j':
		if (wutui.section == SECTION_KN && wutui.kns->len != 0)
			WRAPPED_INCR(wutui.selected_kn, wutui.kns->len);
		else if (wutui.section == SECTION_NS && wutui.srs->len != 0)
			WRAPPED_INCR(wutui.selected_sr, wutui.srs->len);
		break;
	case ARROW_UP:
	case 'k':
		if (wutui.section == SECTION_KN && wutui.kns->len != 0)
			WRAPPED_DECR(wutui.selected_kn, wutui.kns->len);
		else if (wutui.section == SECTION_NS && wutui.srs->len != 0)
			WRAPPED_DECR(wutui.selected_sr, wutui.srs->len);
		break;
	case 'r':
		if (reconnect(wutui.ctrl) != 0)
			diex("failed to reconnect");
		update_supplicant_status();
		break;
	case 's':
		scan(wutui.ctrl);
		break;
	case HOME_KEY:
		if (wutui.section == SECTION_KN)
			wutui.selected_kn = 0;
		else if (wutui.section == SECTION_NS)
			wutui.selected_sr = 0;
		break;
	case END_KEY:
		if (wutui.section == SECTION_KN)
			wutui.selected_kn = SUB_CLAMP_ZERO(wutui.kns->len, 1);
		else if (wutui.section == SECTION_NS)
			wutui.selected_sr = SUB_CLAMP_ZERO(wutui.srs->len, 1);
		break;
	case PAGE_UP:
		if (wutui.section == SECTION_KN) {
			size_t top_kn = SUB_CLAMP_ZERO(wutui.kn_offset,
			    KN_ENTRIES);

			wutui.selected_kn = CLAMP(top_kn, 0, wutui.kn_offset);
		} else if (wutui.section == SECTION_NS) {
			size_t top_sr = SUB_CLAMP_ZERO(wutui.sr_offset,
			    SR_ENTRIES);

			wutui.selected_sr = CLAMP(top_sr, 0, wutui.sr_offset);
		}
		break;
	case PAGE_DOWN:
		if (wutui.section == SECTION_KN && wutui.kns->len != 0) {
			size_t selected_kn = wutui.kn_offset + 2 * KN_ENTRIES -
			    1;
			size_t max_kn = SUB_CLAMP_ZERO(wutui.kns->len, 1);

			wutui.selected_kn = CLAMP(selected_kn, 0, max_kn);
		} else if (wutui.section == SECTION_NS) {
			size_t selected_sr = wutui.sr_offset + 2 * SR_ENTRIES -
			    1;
			size_t max_sr = SUB_CLAMP_ZERO(wutui.srs->len, 1);

			wutui.selected_sr = CLAMP(selected_sr, 0, max_sr);
		}
		break;
	case CTRL('a'):
		if (wutui.section == SECTION_KN && wutui.kns->len != 0) {
			struct known_network *selected =
			    &wutui.kns->items[wutui.selected_kn];

			if (set_priority(wutui.ctrl, selected->id,
				selected->priority + 1) != 0)
				diex("failed to set priority");

			if (update_config(wutui.ctrl) != 0)
				diex("failed to update config");

			update_known_networks();
		}
		break;
	case CTRL('x'):
		if (wutui.section == SECTION_KN && wutui.kns->len != 0) {
			struct known_network *selected =
			    &wutui.kns->items[wutui.selected_kn];

			if (set_priority(wutui.ctrl, selected->id,
				selected->priority - 1) != 0)
				diex("failed to set priority");

			if (update_config(wutui.ctrl) != 0)
				diex("failed to update config");

			update_known_networks();
		}
		break;
	case CTRL('l'):
		clear_notifactions(wutui.notifications);
		break;
	case '\t':
		wutui.section = !wutui.section;
		break;
	default:
		break;
	}

	return (HANDLER_CONTINUE);
}

static enum handler_return
handle_wpa_event(void *udata)
{
	char buf[4096];
	int len = recv(wutui.wpa_fd, buf, sizeof(buf) - 1, 0);

	(void)udata;

	if (len == -1)
		die("recv(wpa_fd)");
	else if (len == 0)
		die("wpa ctrl interface socket closed");
	buf[len] = '\0';

	if (strstr(buf, WPA_EVENT_SCAN_RESULTS) != NULL ||
	    strstr(buf, WPA_EVENT_BSS_ADDED) != NULL ||
	    strstr(buf, WPA_EVENT_BSS_REMOVED) != NULL ||
	    strstr(buf, WPA_EVENT_NETWORK_NOT_FOUND) != NULL) {
		update_scan_results();
	} else if (strstr(buf, WPA_EVENT_NETWORK_ADDED) != NULL ||
	    strstr(buf, WPA_EVENT_NETWORK_REMOVED) != NULL ||
	    strstr(buf, WPA_EVENT_NETWORK_NOT_FOUND) != NULL ||
	    strstr(buf, WPA_EVENT_ASSOCIATED) != NULL) {
		update_known_networks();
	} else {
		update_supplicant_status();
	}

	push_notification(wutui.notifications, buf);
	return (HANDLER_CONTINUE);
}

static enum handler_return
handle_sigwinch(void *udata)
{
	(void)udata;

	if (fetch_winsize() == -1)
		die("failed to fetch terminal winsize");
	return (HANDLER_CONTINUE);
}

static void
update_scan_results(void)
{
	free_scan_results(wutui.srs);
	if ((wutui.srs = get_scan_results(wutui.ctrl)) == NULL)
		diex("failed to retrieve scan results");
	wutui.selected_sr = 0;
}

static void
update_known_networks(void)
{
	free_known_networks(wutui.kns);
	if ((wutui.kns = get_known_networks(wutui.ctrl)) == NULL)
		diex("failed to retrieve known networks");
	wutui.selected_kn = 0;
}

static void
update_supplicant_status(void)
{
	free_supplicant_status(wutui.status);
	if ((wutui.status = get_supplicant_status(wutui.ctrl)) == NULL)
		diex("failed retrieve wpa_supplicant status");
}
