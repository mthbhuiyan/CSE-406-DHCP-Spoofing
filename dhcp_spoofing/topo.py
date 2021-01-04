#!/usr/bin/python

import os
import shutil
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Host
from mininet.nodelib import LinuxBridge
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from functools import partial


class DHCPTopo(Topo):
	"Custom topo for DHCP spoofing attack"
	def build(self):
		switch = self.addSwitch('s1')
		dhcp = self.addHost('dhcp', ip='10.0.0.50/24')
		evil = self.addHost('evil', ip='10.0.0.150/24')
		client = self.addHost('h1')
		self.addLink(dhcp, switch, delay='100ms')
		self.addLink(evil, switch)
		self.addLink(client, switch)


# We need a separate /etc/resolv.conf for each host so that they can
# resolve DNS names with the DNS server they received from DHCP. Might as
# well also not mess up the real udhcpd or dhclient lease files, especially
# when they might actually be in use on the real host.
def setupPrivateFS(hosts, etc_template, var_template):
	for host in hosts:
		etc = etc_template % host
		var = var_template % host
		os.system('cp -a /etc ' + etc)
		host.cmd('mount --bind ', etc + ' /etc')
		host.cmd('mkdir -p', var + '/lib/misc')
		host.cmd('mkdir -p', var + '/lib/dhclient')
		host.cmd('mkdir -p', var + '/run')
		host.cmd('touch ', var + '/lib/misc/udhcpd.leases')
		host.cmd('touch ', var + '/lib/dhclient/dhclient.leases')


def removePrivateFS(hosts, etc_template, var_template):
	for host in hosts:
		etc = etc_template % host
		var = var_template % host
		host.cmd('umount /etc')
		os.system('rm -r ' + etc)
		shutil.rmtree(var)


# DHCP server functions and data
DHCPTemplate = """
start			10.0.0.10
end				10.0.0.90
option	subnet	255.255.255.0
option	domain	local
option	lease	7  # seconds
"""


# Good DHCP Server
def makeDHCPconfig(filename, intf, gw, dns):
	config = (
		'interface %s' % intf,
		DHCPTemplate,
		'option router %s' % gw,
		'option dns %s' % dns,
		'')
	with open(filename, 'w') as f:
		f.write('\n'.join(config))


def cleanDHCPconfig(host, filename):
	host.cmd('rm ', filename)


def startGoodDHCPserver(host, gw, dns):
	info('* Starting good DHCP server on', host, 'at', host.IP(), '\n')
	dhcpConfig = '/tmp/%s-udhcpd.conf' % host
	makeDHCPconfig(dhcpConfig, host.defaultIntf(), gw, dns)
	host.cmd('busybox udhcpd -f', dhcpConfig,
			  '1>/tmp/%s-dhcp.log 2>&1  &' % host)


def stopGoodDHCPserver(host):
	info('* Stopping good DHCP server on', host, 'at', host.IP(), '\n')
	host.cmd('kill %udhcpd')
	dhcpConfig = '/tmp/%s-udhcpd.conf' % host
	cleanDHCPconfig(host, dhcpConfig)


# Output when we get an IP from the DHCP server
def waitForIP(host):
	info('*', host, 'waiting for IP address')
	while True:
		host.defaultIntf().updateIP()
		if host.IP():
			break
		info('.')
		time.sleep(1)
	info('\n')
	info('*', host, 'is now at',host.IP(),'and is using',
		  host.cmd('grep nameserver /etc/resolv.conf'))
	info('\n')


# DHCP Client
def startDHCPclient(host, etc):
	host.cmd('rm ', etc + '/resolv.conf')
	host.cmd('touch ', etc + '/resolv.conf')
	intf = host.defaultIntf()
	host.cmd('ifconfig', intf, '0')
	host.cmd('touch /tmp/dhclient.conf', intf)
	host.cmd('dhclient -v -d -r', intf)
	host.cmd('dhclient -v -d -cf /tmp/dhclient.conf ' \
			'1> /tmp/dhclient.log 2>&1', intf, '&')


def stopDHCPclient(host):
	host.cmd('kill %dhclient')
	host.cmd('rm /tmp/dhclient.log')
	host.cmd('rm /tmp/dhclient.conf')


def spoofDHCP():
	topo = DHCPTopo()
	privateDirs = [ ( '/var', '/tmp/%(name)s/var' )]
	host = partial( Host,
					privateDirs=privateDirs )
	net = Mininet( topo=topo, switch=LinuxBridge, host=host, link=TCLink, xterms=True)
	net.addNAT().configDefault()
	h1, dhcp, evil, nat, switch = net.get('h1', 'dhcp', 'evil', 'nat0', 's1')
	setupPrivateFS([h1, evil], '/tmp/%s/etc', '/tmp/%s/var')
	net.start()
	raw_input("Press return after you've started dhcp_server on evil and wireshark on s1")
	startGoodDHCPserver(dhcp, gw=nat.IP(), dns='8.8.8.8')
	# Let the client connect
	startDHCPclient(h1, '/tmp/%s/etc' % h1)
	waitForIP(h1)
	CLI(net)
	stopGoodDHCPserver(dhcp)
	stopDHCPclient(h1)
	removePrivateFS([h1, evil], '/tmp/%s/etc', '/tmp/%s/var')
	net.stop()


if __name__ == '__main__':
	setLogLevel('info')
	spoofDHCP()
