#!/bin/sh
set -e
set -x
rm -fv /run/*.pid /var/run/*.pid /run/*/*.pid /var/run/*/*.pid
sleep 10
$@
AUTHORITY=$3
test -f /etc/certidude/authority/$AUTHORITY/host_cert.pem
/usr/sbin/ipsec stop
/usr/sbin/ipsec start --nofork
