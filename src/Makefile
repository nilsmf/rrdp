CC=gcc
INCLUDES=-I /usr/local/opt/curl/include
LINKS=-L /usr/local/opt/curl/lib
CFLAGS=-Wall -c

obj: rrpd.c
	${CC} ${INCLUDES} ${CFLAGS} $^

all: rrpd.o
	${CC} ${INCLUDES} -o rrpd $^

clean:
	rm -rf *.o
	rm -rf rrpd
