#! /bin/sh

VERSION=`grep ^VERSION README | head -1 | sed 's/^VERSION //'`

tar cvfz minisecsrv_v$VERSION.tgz *.c *.h minisecsrv.cfg doit.sh README ChangeLog TODO
