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
