CC=gcc
INCLUDES=-I/usr/local/opt/curl/include -I/usr/local/opt/libxml2/include/libxml2/
LINKS=-L/usr/local/opt/curl/lib -L/usr/local/opt/libxml2/lib/
LINKS2=-lxml2
CFLAGS=-Wall -c

obj: rrpd.c
	${CC} ${INCLUDES} ${CFLAGS} $^

all: rrpd.o
	${CC} ${LINKS} ${LINKS2} -o rrpd $^

clean:
	rm -rf *.o
	rm -rf rrpd
