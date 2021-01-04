#!/bin/bash

if [ -z "$1" ]; then
	echo "Usage: $0 ip_address
IP Address:
    the ip address on which to get Internet access, e.g. 192.168.56.101"
    exit 1
fi

ip="$1"

dnsmasq_conf=""
dnsmasq_conf="${dnsmasq_conf}server=8.8.8.8\n"
dnsmasq_conf="${dnsmasq_conf}listen-address=127.0.0.1\n"
dnsmasq_conf="${dnsmasq_conf}listen-address=${ip}\n"
dnsmasq_conf="${dnsmasq_conf}no-dhcp-interface=\n"
dnsmasq_conf="${dnsmasq_conf}no-hosts\n"
dnsmasq_conf="${dnsmasq_conf}addn-hosts=/etc/dnsmasq.d/spoof.hosts\n"

dnsmasq_hosts=""
dnsmasq_hosts="${dnsmasq_hosts}${ip} www.example.com example.com\n"
dnsmasq_hosts="${dnsmasq_hosts}${ip} www.example2.com example2.com\n"

printf "$dnsmasq_conf" > /etc/dnsmasq.conf

mkdir -p /etc/dnsmasq.d

printf "$dnsmasq_hosts" > /etc/dnsmasq.d/spoof.hosts

dnsmasq --no-daemon --log-queries
