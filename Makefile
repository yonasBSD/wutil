PROGS=	wutil wutui

SRCS.wutil=	wutil.c usage.c string_utils.c utils.c
SRCS.wutui=	wutui.c string_utils.c utils.c

LDADD+=	-lifconfig
LDADD+=	-l80211

MAN=	wutil.1

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

.include <bsd.progs.mk>
