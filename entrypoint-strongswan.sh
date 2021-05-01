#!/bin/sh
rm -fv /run/certidude/*.pid
sleep 10
set -e
$@
AUTHORITY=$3
test -f /etc/certidude/authority/ca5.dev.lan/host_cert.pem
/usr/sbin/ipsec start --nofork
