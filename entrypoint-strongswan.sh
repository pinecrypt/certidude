#!/bin/sh
sleep 10
set -e
$@
AUTHORITY=$3
echo "Client config:"
cat /etc/certidude/client.conf
echo
echo "Generated VPN config:"
cat /etc/ipsec.conf
echo
/usr/sbin/ipsec start --nofork
