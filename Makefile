PROGS=	wutil wutui

SRCS.wutil= wutil.c usage.c
SRCS.wutui= wutui.c
SRCS+= string_utils.c utils.c

LDADD+= -lifconfig

MAN=	wutil.1

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

.include <bsd.progs.mk>
