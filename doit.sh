#! /bin/sh -x

CC=gcc
CFLAGS="-g -O0"
#CFLAGS="-O2"
LIBS="-lcrypto"

case `uname -o` in
  GNU/Linux)
    ;;
  Darwin)
    INCLUDEPATH="-I/opt/local/include"
    LIBSPATH="-L/opt/local/lib"
esac

$CC $CFLAGS $INCLUDEPATH $LIBSPATH -o minisecsrv minisecsrv.c utils.c config.c getpassword.c $LIBS
