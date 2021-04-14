#!/bin/sh
sleep 10
set -e
$@
AUTHORITY=$3
echo "Client config:"
cat /etc/certidude/client.conf
echo
echo "Generated VPN config:"
cat /etc/openvpn/$AUTHORITY.conf
echo
openvpn --config /etc/openvpn/$AUTHORITY.conf
