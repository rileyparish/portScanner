# Port Scanner

This is a script to run port scans on a network. It can scan a single host, a network, or parse through a list of hosts provided in a file. The user can specify what type of scan to run, be it TCP, UDP, or ICMP. A list of multiple ports can also be specified. The user can optionally elect to run traceroute on hosts. The results of each scan are written to a PDF and output to "scanReport.pdf". *It must be run with python3 and with root/sudo permissions!*

## Arguments:

A host or network must be specified. This is done using one of the following arguments:

**-host**
> Provide the IP address of the target in question. This also supports providing a network in CIDR notation such as "192.168.42.0/24"

**-hostFile**
> Provide the path to an existing file of hosts to scan. The file must be formatted with one host on each line.


If you're doing a TCP or UDP scan, you must provide a list of ports to scan using the -port flag:

**-port**
> Provide a list of comma-separated ports: **-port 22,42,8080**. Inputting the string "default" will automatically scan through the most common ports.

**-type**
> Specify the type of scan to run, TCP/UDP/ICMP. If this flag is not provided, the default scan is TCP.

**-trace**
> Optionally run traceroute on a host.


## Examples:

*sudo python3 scanner.py -host 192.168.42.0/24 -port 22,8080,5900*

*sudo python3 scanner.py -hostFile hosts.txt -port 22,8080,5900 -type UDP*

*sudo python3 scanner.py -host www.google.com -trace*

