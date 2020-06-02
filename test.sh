#!/bin/bash

. ./build.sh

set -o xtrace

${CC} ${CFLAGS} ${INCLUDES} regress/test_util.c
${CC} ${LINKS} ${LINKS2} util.o test_util.o -o test

./test

${CC} ${CFLAGS} ${INCLUDES} regress/test_fetch_util.c
${CC} ${LINKS} ${LINKS2} fetch_util.o test_fetch_util.o -o test_fetch

#./test_fetch

${CC} ${CFLAGS} ${INCLUDES} regress/test_notification.c
${CC} ${LINKS} ${LINKS2} notification.o test_notification.o fetch_util.o -o test_notification

./test_notification
