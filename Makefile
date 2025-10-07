PROGS=	wutil wutui

LDFLAGS+=	-L/usr/local/lib
CFLAGS+=	-I/usr/local/include

_COMMON_SRCS=	 usage.c wifi.c interface.c wpa_ctrl.c utils.c

SRCS.wutil=	wutil.c $(_COMMON_SRCS)
SRCS.wutui=	wutui.c $(_COMMON_SRCS)

LDADD=	-lifconfig -lsbuf -lm

MAN.wutil=	wutil.8
MAN.wutui=	wutui.8

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

.include <bsd.progs.mk>
