#! /bin/sh -x

CC=gcc
CFLAGS="-g -O0"
#CFLAGS="-O2"
CFLAGS="-I/opt/local/include"
LIBS="-L/opt/local/lib -lcrypto"

$CC $CFLAGS -o minisecsrv minisecsrv.c utils.c config.c $LIBS
