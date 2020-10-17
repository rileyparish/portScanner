import sys
import os
import argparse
from scapy.all import*
import string
from fpdf import FPDF
from ipaddress import IPv4Network

class Scanner():
    def __init__(self, hosts, ports, scan_type="TCP"):
        # hosts is a list of hosts, ports is a list of ports to scan
        self.hosts = hosts
        self.ports = ports
        # this is the type of scan to run; TCP, UDP or ICMP
        self.scan_type = scan_type
        self.traceroute = False

        # initialize the pdf object
        self.pdf_file = FPDF()
        self.pdf_file.set_font("Arial", size = 12)
        self.pdf_file.add_page()
        self.pdf_file.cell(200, 10, txt = "Results of Scan:", ln = 1, align = 'C')
        self.pdf_file.cell(200, 10, txt = "", ln = 1, align = 'C')


    def scanAll(self):
        # scans the whole list of provided hosts and ports
        for host in self.hosts:
            print("Scanning host: {}".format(host))
            self.writeToPDF("Scanning host: {}".format(host), False)

            # if it's ICMP we don't scan ports
            if self.traceroute:
                self.trace(host)
            elif self.scan_type == "ICMP":
                self.scan(host, "-")
            else:
                for port in self.ports:
                    self.scan(host, port)

        # the scan is over, output the PDF file
        self.pdf_file.output("scanReport.pdf")
        print("PDF report created at \'scanReport.pdf\'")

    def scan(self, host, port):
        # this method will take a host and a port and determine if the port is active
        if self.scan_type == "TCP":
            response = sr1(IP(dst=host) / TCP(dport=port, flags="S"), verbose=False, timeout=0.2)
            # response is a tuple: (<Results: TCP:1 UDP:0 ICMP:0 Other:0>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)
            if response:
                if response["TCP"].flags == "SA":
                    print("\t{} - Open".format(port))
                    self.writeToPDF("{} - Open".format(port), True, "green")
                    # print(response.summary())
                else:
                    print("\t{} - Closed".format(port))
                    self.writeToPDF("{} - Closed".format(port), True, "red")
            else:
                print("\t{} - Closed".format(port))
                self.writeToPDF("{} - Closed".format(port), True, "red")
        elif self.scan_type == "UDP":
            # these are the types of responses to expect from UDP: https://nmap.org/book/scan-methods-udp-scan.html
            response = sr1(IP(dst=host)/UDP(dport=port), timeout=2, verbose=0)
            if response == None:
                # if we got no response back, the request could be filtered out
                print("\t{} - No response; Open | filtered".format(port))
                self.writeToPDF("{} - No response; Open | filtered".format(port), True)
            else:
                if response.haslayer(ICMP):
                    print("\t{} - Closed".format(port))
                    self.writeToPDF("\t{} - Closed".format(port), True, "red")
                elif response.haslayer(UDP):
                    print("\t{} - Open".format(port))
                    self.writeToPDF("{} - Open".format(port), True, "green")
                else:
                    # pom piim dtag jaag dtua yang
                    print("\t{} - Filtered ".format(port))
                    self.writeToPDF("{} - Filtered ".format(port), True, "red")

        elif self.scan_type == "ICMP":
            response = sr1(IP(dst=host) / ICMP(), verbose=False, timeout=0.2)
            if response != None:
                print("\tHost is up")
                self.writeToPDF("Host is up", True, "green")
            else:
                print("\tHost is not up")
                self.writeToPDF("Host is not up", True, "red")

    def trace(self, host):
        maxttl = 20
        # get the results of the trace, discard unanswered
        trace, _ = traceroute(host, maxttl=maxttl)
        hosts = trace.get_trace()
        # the structure of the returned type is a bit strange. The dictionary of IPs is associated with a key
        key = list(hosts.keys())[0]
        # ips is a dict of tuples of ip addresses that were encountered
        ips = hosts[key]

        self.writeToPDF("Traceroute for {}:".format(key), False)
        # print all the IPs to the pdf. The maximum number we could have is maxttl
        for i in range(1, maxttl):
            if i in ips:
                # get the first element of the tuple (ip address)
                print("{}. {}".format(i, ips[i][0]))
                self.writeToPDF("{}. {}".format(i, ips[i][0]), False)


    def writeToPDF(self, text, indent, color="black"):
        if color == "black":
            self.pdf_file.set_text_color(0, 0, 0)
        elif color=="red":
            self.pdf_file.set_text_color(255, 0, 0)
        elif color=="green":
            self.pdf_file.set_text_color(0, 255, 0)



        # create a cell
        if indent:
            # this creates a leading cell of whitespace
            self.pdf_file.cell(10, 5, txt="", align="L")
        self.pdf_file.multi_cell(0, 5, txt = text, align = 'L')



def main():
    arg_parser = argparse.ArgumentParser(description='Run port scans on host(s). Must run as root.')

    host_group = arg_parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument('-host', type=str, help='The host to scan. A single ip address, or a network represented in cidr notation')
    host_group.add_argument('-hostFile', type=str, help='A file containing a list of hosts to scan')

    trace_group = arg_parser.add_mutually_exclusive_group(required=False)
    trace_group.add_argument('-port', type=str, help='A comma-separated list of ports to scan. Inputting "default" here will scan the most commonly used ports')
    trace_group.add_argument('-trace', action="store_true", help="Traceroute for the specified host(s)")

    arg_parser.add_argument('-type', type=str, help="The type of packets to send (TCP/UDP/ICMP)")

    # todo: make host and hostfile mutex

    # host_group.add_argument('--foo', action='store_true')

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
        # it's not coming from a file, determine if it's in cidr notation or not
        if "/" in args.host:
            addresses = IPv4Network(args.host)
            for host in addresses:
                hosts.append(host.compressed)
        else:
            # just scan the single host that was provided
            hosts.append(args.host)

    # generate the list of ports to scan
    if args.port == None:
        ports = []
    elif args.port == "default":
        ports = [21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 631, 993, 995]
    else:
        ports = args.port.split(",")
        for i in range(len(ports)):
            ports[i] = int(ports[i])

    scan_type = "TCP"
    if args.type != None:
        # verify that the user provided a valid type
        if not args.type.upper() in "TCP UDP ICMP":
            print("Invalid type provided, defaulting to TCP")
        else:
            scan_type = (args.type).upper()
    else:
        print("Scan type not specified, defaulting to TCP")

    scanner = Scanner(hosts, ports, scan_type)
    if args.trace:
        scanner.traceroute = True
    scanner.scanAll()



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


# an extra feature could be stealth scanning: https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/
# I could also spoof packet src as an extra feature, possibly
# maybe not because I need a response to come back to me
# include the MAC address of the device if it exists?
# support IPv6?
# common ports?
# sniffing?
