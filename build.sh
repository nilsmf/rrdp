#!/bin/bash

CC=gcc

CC=gcc
INCLUDES="-I/usr/local/opt/curl/include"
INCLUDES+=" -I/usr/local/opt/expat/include"
INCLUDES+=" -I./"
LINKS="-L/usr/local/opt/curl/lib"
LINKS+=" -L/usr/local/opt/expat/lib"
LINKS2="-lexpat"
LINKS2+=" -lcurl"
CFLAGS="-Wall"
CFLAGS+=" -c"

set -o xtrace

${CC} ${CFLAGS} ${INCLUDES} src/rrpd.c src/util.c
${CC} ${LINKS} ${LINKS2} rrpd.o util.o -o rrpd

