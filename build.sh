#!/bin/bash

CC=gcc

CC=gcc
INCLUDES="-I/usr/local/opt/curl/include"
INCLUDES+=" -I/usr/local/opt/expat/include"
INCLUDES+=" -I/usr/local/opt/openssl/include"
INCLUDES+=" -I./"
LINKS="-L/usr/local/opt/curl/lib"
LINKS+=" -L/usr/local/opt/expat/lib"
LINKS+=" -L/usr/local/opt/openssl/lib"
LINKS2="-lexpat"
LINKS2+=" -lcurl"
LINKS2+=" -lcrypto"
LINKS2+=" -lresolv"
CFLAGS="-Wall"
CFLAGS+=" -c"

set -o xtrace

${CC} ${CFLAGS} ${INCLUDES} src/main.c src/notification.c src/snapshot.c src/delta.c src/util.c src/fetch_util.c src/file_util.c src/log.c
${CC} ${LINKS} ${LINKS2} main.o notification.o snapshot.o delta.o util.o fetch_util.o file_util.o log.o -o rrdp

