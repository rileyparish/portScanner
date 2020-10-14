import sys
import os
import argparse
from scapy.all import*
os.sys.path.append('/usr/bin/')

class Scanner():
    def __init__(self):
        pass

    def scan(self, host, port):
        # this method will take a host and a port and determine if the port is active
        # ip = "192.168.207.100"
        # port = 8080

        # if TCP
        # if UDP

        response = sr1(IP(dst=host) / TCP(dport=port, flags="S"), verbose=False, timeout=0.2)
        print(Ether(response))

        # an extra feature could be stealth scanning: https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/



def main():
    # print(os.sys.path)

    scanner = Scanner()
    arg_parser = argparse.ArgumentParser(description='Run port scans on host')

    arg_parser.add_argument('-host', type=str, help='The host to scan')
    arg_parser.add_argument('-port', type=int, help='The port to scan')

    # arg_parser.add_argument('-hostsFile', type=str, help='The host to scan')
    # arg_parser.add_argument('-hostRange', type=str, help='The host to scan')

    # get pycharm working so I can start it from anywhere
    # set up github
    # create a new snapshot

    # without - it becomes required. And I think positional
    # I can make the args mutex


    args = arg_parser.parse_args()
    #
    # print("host: ", args.host)
    # print("Port: ", args.port)

    # scanner.scan("192.168.207.100", 22)
    scanner.scan(args.host, args.port)

main()



#
# def runScan(name):
#     pass
#
#
# if __name__ == '__main__':
#     # init argparse
#     arg_parser = argparse.ArgumentParser(description='Run port scans on host')
#     arg_parser.add_argument('host', metavar='h', type=str, help='The host to scan')
#     arg_parser.add_argument('port', metavar='p', type=str, help='The port to scan')
#
#     args = arg_parser.parse_args()
#
#     print("Host: ", args.path)
#     print("Port: ", args.port)


    # runScan('test')

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
