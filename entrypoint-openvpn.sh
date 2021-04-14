#!/bin/sh
sleep 10
set -e
$@
AUTHORITY=$3
test -f /etc/certidude/authority/ca5.dev.lan/host_cert.pem
openvpn --config /etc/openvpn/$AUTHORITY.conf
