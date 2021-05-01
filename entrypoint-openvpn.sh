#!/bin/sh
rm -fv /run/certidude/*.pid
sleep 10
set -e
$@
AUTHORITY=$3
test -f /etc/certidude/authority/$AUTHORITY/host_cert.pem
openvpn --config /etc/openvpn/$AUTHORITY.conf
