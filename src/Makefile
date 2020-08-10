#	$OpenBSD$

NOMAN=	1
PROG=	rrdp
SRCS=	delta.c fetch_util.c file_util.c log.c main.c notification.c \
	snapshot.c util.c

LDADD+= -lcrypto -lexpat
#LDADD+= -L/usr/local/lib -lcurl
DPADD+= ${LIBCRYPTO} ${LIBEXPAT}

#CFLAGS+= -DRRDP_CURL
CFLAGS+= -I/usr/local/include
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith
#CFLAGS+= -Wcast-qual
CFLAGS+= -Wsign-compare

.include <bsd.prog.mk>
