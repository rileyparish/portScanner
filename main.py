import sys
import os
import argparse
from scapy.all import*
# os.sys.path.append('/usr/bin/')

class Scanner():
    def __init__(self, hosts, ports, scan_type):
        # hosts is a list of hosts, ports is a list of ports to scan
        self.hosts = hosts
        self.ports = ports
        # this is the type of scan to run; TCP, UDP or ICMP
        self.scan_type = scan_type


    def scanAll(self):
        for host in self.hosts:
            print("Scanning host: {}".format(host))
            for port in self.ports:
                self.scan(host, port)
        pass


    def scan(self, host, port):
        # this method will take a host and a port and determine if the port is active
        # ip = "192.168.207.100"
        # port = 8080

        # if TCP
        # if UDP
        # if ICMP?

        response = sr1(IP(dst=host) / TCP(dport=port, flags="S"), verbose=False, timeout=0.2)
        # response = sr(IP(dst=host, src="192.168.207.102") / UDP(dport=port), verbose=False, timeout=0.2)
        # response is a tuple: (<Results: TCP:1 UDP:0 ICMP:0 Other:0>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)
        # print(response)
        # print("b")
        # print(type(response[0]))
        # print(response[0])    # results
        # print(response[0][0]) # TCP results (tuple of ans/unans?)
        # print(response[0][0][0])   # sent packet; [0][0][1] is the received packet?
        if response:
            # print(response[0][0].summary())    # prints a summary of the response
            # print(6)
            # print(response["TCP"].flags)
            if response["TCP"].flags == "SA":
                print("{} - Open".format(port))
            # print(response.summary())


        # an extra feature could be stealth scanning: https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/
        # I could also spoof packet src as an extra feature, possibly
            # maybe not because I need a response to come back to me
        # include the MAC address of the device if it exists?
        # support IPv6?
        # common ports?



def main():
    # print(os.sys.path)


    arg_parser = argparse.ArgumentParser(description='Run port scans on host(s)')

    arg_parser.add_argument('-host', type=str, help='The host to scan')
    arg_parser.add_argument('-hostFile', type=str, help='A file containing a list of hosts to scan')
    arg_parser.add_argument('-port', type=str, help='A comma-separated list of ports to scan')



    # arg_parser.add_argument('-hostsFile', type=str, help='The host to scan')
    # arg_parser.add_argument('-hostRange', type=str, help='The host to scan')

    # get pycharm working so I can start it from anywhere
    # create a new snapshot

    # without - it becomes required. And I think positional
    # I can make the args mutex

    args = arg_parser.parse_args()

    # generate the list of hosts to scan
    hosts = []
    if args.hostFile != None:
        # the user provided a file of hosts, parse through it and add each host to the list
        file = open(args.hostFile, 'r')
        addresses = file.readlines()

        # add the ip to the list of hosts and remove whitespace
        for ip in addresses:
            hosts.append(ip.strip())
    else:
        # singular host
        hosts.append(args.host)

    # generate the list of ports to scan
    ports = args.port.split(",")
    for i in range(len(ports)):
        ports[i] = int(ports[i])

    scanner = Scanner(hosts, ports, "tmp")
    scanner.scanAll()
    # scanner.scan("192.168.207.100", 22)


main()


# kali@IT567-vm-rparish:/opt/pycharm/bin$ sudo nmap -p- 192.168.207.100
# [sudo] password for kali:
# Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-14 00:05 EDT
# Nmap scan report for dell.veracitynetworks.net (192.168.207.100)
# Host is up (0.0032s latency).
# Not shown: 65531 closed ports
# PORT     STATE SERVICE
# 22/tcp   open  ssh
# 5900/tcp open  vnc
# 6543/tcp open  mythtv
# 8080/tcp open  http-proxy
# MAC Address: B8:CA:3A:78:37:C6 (Dell)
#
# Nmap done: 1 IP address (1 host up) scanned in 16.51 seconds
