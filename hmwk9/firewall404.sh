#!/bin/sh

# flushing all previous rules or chains in all of the tables
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t raw -F
sudo iptables -t raw -X

# Changing source IP address of all outgoing packets to my own IP
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Blocking a list of IP addresses
# [confirmed working]
sudo iptables -A INPUT -s 126.1.1.25 -j DROP
sudo iptables -A INPUT -s 52.242.211.89 -j DROP
sudo iptables -A INPUT -s 10.0.0.165 -j DROP

# Blocking my computer from being pinged by other hosts
# [confirmed working]
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT

# Port forwarding from port 9,000 to port 22 (for tcp or udp)
# (to test, need to enable connections to port 9,000)
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 9000 -j REDIRECT --to-port 20
sudo iptables -t nat -A PREROUTING -i eth0 -p udp --dport 9000 -j REDIRECT --to-port 20

# Only allowing SSH access only to machines in the engineering.purdue.edu domain
# blocking all connections first, then allowing those from ^
# [confirmed working]
sudo iptables -A INPUT -p tcp --dport ssh -j DROP
sudo iptables -A INPUT -p tcp --dport ssh -s 128.46.104.5 -j ACCEPT

# Rule for only allowing a single IP address on the internet to access machine
# [confirmed working]
sudo iptables -A INPUT -p tcp --dport http -j DROP
sudo iptables -A INPUT -p tcp --dport http -s 128.46.104.5 -j ACCEPT

# Permit Auth/Ident (port 113) that's used by services like SMTP and IRC
# [confirmed working]
sudo iptables -A INPUT -p tcp --dport 113 -j ACCEPT
