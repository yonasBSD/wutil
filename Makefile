PROGS=	wutil wutui

SRCS.wutil= src/cli.c src/usage.c
SRCS.wutui= src/tui.c
SRCS+= src/lib/string_utils.c src/lib/utils.c

MAN=	man/wutil.1

WARNS?=		6

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

.include <bsd.progs.mk>
