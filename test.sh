#!/bin/bash

. ./build.sh

set -o xtrace

${CC} ${CFLAGS} ${INCLUDES} regress/test_util.c
${CC} ${LINKS} ${LINKS2} util.o test_util.o -o test

./test
