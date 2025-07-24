PROGS=	wutil wutui

SRCS.wutil=	wutil.c usage.c wifi.c interface.c
SRCS.wutui=	wutui.c usage.c wifi.c interface.c

LDADD=	-lifconfig -l80211 -lwpa_client

MAN=	wutil.1

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

.include <bsd.progs.mk>
