PROGS=	wutil wutui

SRCS.wutil=	wutil.c usage.c utils.c ieee80211.c
SRCS.wutui=	wutui.c utils.c ieee80211.c

LDADD=	-lifconfig -l80211 -lucl -lwpa_client

MAN=	wutil.1

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

.include <bsd.progs.mk>
