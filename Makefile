PROGS=	wutil wutui

LDFLAGS+=	-L/usr/local/lib
CFLAGS+=	-I/usr/local/include

SRCS.wutil=	wutil.c usage.c wifi.c interface.c
SRCS.wutui=	wutui.c usage.c wifi.c interface.c

LDADD=	-lifconfig -l80211 -lwpa_client -lsbuf -lm

MAN.wutil=	wutil.8
MAN.wutui=	wutui.8

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

.include <bsd.progs.mk>
