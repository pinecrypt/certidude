#!/bin/sh
$@
AUTHORITY=$3
cat /etc/openvpn/$AUTHORITY.conf
openvpn --config /etc/openvpn/$AUTHORITY.conf
