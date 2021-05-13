#!/bin/sh
set -e
sleep 10
$@
AUTHORITY=$3
test -f /etc/certidude/authority/$AUTHORITY/host_cert.pem
openvpn --config /etc/openvpn/$AUTHORITY.conf
