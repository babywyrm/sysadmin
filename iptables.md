##
##
#############################################

Managing network traffic is one of the toughest jobs a system administrators has to deal with. 
Said human must configure the firewall in such a way that it will meet the system and users requirements for both incoming and outgoing connections, without leaving the system vulnerable to attacks.

25 IPtables Firewall Rules for Linux
25 IPtables Firewall Rules for Linux

This is where iptables come in handy. Iptables is a Linux command line firewall that allows system administrators to manage incoming and outgoing traffic via a set of configurable table rules.

Iptables uses a set of tables which have chains that contain set of built-in or user defined rules. Thanks to them a system administrator can properly filter the network traffic of his system.

Per iptables manual, there are currently 3 types of tables:

FILTER – this is the default table, which contains the built in chains for:
INPUT  – packages destined for local sockets
FORWARD – packets routed through the system
OUTPUT – packets generated locally
NAT – a table that is consulted when a packet tries to create a new connection. It has the following built-in:
PREROUTING – used for altering a packet as soon as it’s received
OUTPUT – used for altering locally generated packets
POSTROUTING – used for altering packets as they are about to go out
MANGLE – this table is used for packet altering. Until kernel version 2.4 this table had only two chains, but they are now 5:
PREROUTING – for altering incoming connections
OUTPUT – for altering locally generated  packets
INPUT – for incoming packets
POSTROUTING – for altering packets as they are about to go out
FORWARD – for packets routed through the box

 
In this article, you will see some useful commands that will help you manage your Linux box firewall through iptables. For the purpose of this article, I will start with simpler commands and go to more complex to the end.

1. Start/Stop/Restart Iptables Firewall
First, you should know how to manage iptables service in different Linux distributions. This is fairly easy:

On SystemD based Linux Distributions
------------ On Cent/RHEL 7 and Fedora 22+ ------------
# systemctl start iptables
# systemctl stop iptables
# systemctl restart iptables
On SysVinit based Linux Distributions
------------ On Cent/RHEL 6/5 and Fedora ------------
# /etc/init.d/iptables start 
# /etc/init.d/iptables stop
# /etc/init.d/iptables restart
2. Check all IPtables Firewall Rules
If you want to check your existing rules, use the following command:

# iptables -L -n -v
This should return output similar to the one below:

Chain INPUT (policy ACCEPT 1129K packets, 415M bytes)
pkts bytes target prot opt in out source destination 
0 0 ACCEPT tcp -- lxcbr0 * 0.0.0.0/0 0.0.0.0/0 tcp dpt:53
0 0 ACCEPT udp -- lxcbr0 * 0.0.0.0/0 0.0.0.0/0 udp dpt:53
0 0 ACCEPT tcp -- lxcbr0 * 0.0.0.0/0 0.0.0.0/0 tcp dpt:67
0 0 ACCEPT udp -- lxcbr0 * 0.0.0.0/0 0.0.0.0/0 udp dpt:67
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
pkts bytes target prot opt in out source destination 
0 0 ACCEPT all -- * lxcbr0 0.0.0.0/0 0.0.0.0/0 
0 0 ACCEPT all -- lxcbr0 * 0.0.0.0/0 0.0.0.0/0
Chain OUTPUT (policy ACCEPT 354K packets, 185M bytes)
pkts bytes target prot opt in out source destination
If you prefer to check the rules for a specific table, you can use the -t option followed by the table which you want to check. For example, to check the rules in the NAT table, you can use:

# iptables -t nat -L -v -n
3. Block Specific IP Address in IPtables Firewall
If you find an unusual or abusive activity from an IP address you can block that IP address with the following rule:

# iptables -A INPUT -s xxx.xxx.xxx.xxx -j DROP
Where you need to change "xxx.xxx.xxx.xxx" with the actual IP address. Be very careful when running this command as you can accidentally block your own IP address. The -A option appends the rule in the end of the selected chain.

In case you only want to block TCP traffic from that IP address, you can use the -p option that specifies the protocol. That way the command will look like this:

# iptables -A INPUT -p tcp -s xxx.xxx.xxx.xxx -j DROP
4. Unblock IP Address in IPtables Firewall
If you have decided that you no longer want to block requests from specific IP address, you can delete the blocking rule with the following command:

# iptables -D INPUT -s xxx.xxx.xxx.xxx -j DROP
The -D option deletes one or more rules from the selected chain. If you prefer to use the longer option you can use --delete.

5. Block Specific Port on IPtables Firewall
Sometimes you may want to block incoming or outgoing connections on a specific port. It’s a good security measure and you should really think on that matter when setting up your firewall.

To block outgoing connections on a specific port use:

# iptables -A OUTPUT -p tcp --dport xxx -j DROP
To allow incoming connections use:

# iptables -A INPUT -p tcp --dport xxx -j ACCEPT
In both examples change "xxx" with the actual port you wish to allow. If you want to block UDP traffic instead of TCP, simply change "tcp" with "udp" in the above iptables rule.

6. Allow Multiple Ports on IPtables using Multiport
You can allow multiple ports at once, by using multiport, below you can find such rule for both incoming and outgoing connections:

# iptables -A INPUT  -p tcp -m multiport --dports 22,80,443 -j ACCEPT
# iptables -A OUTPUT -p tcp -m multiport --sports 22,80,443 -j ACCEPT
7. Allow Specific Network Range on Particular Port on IPtables
You may want to limit certain connections on specific port to a given network. Let’s say you want to allow outgoing connections on port 22 to network 192.168.100.0/24.

You can do it with this command:

# iptables -A OUTPUT -p tcp -d 192.168.100.0/24 --dport 22 -j ACCEPT
8. Block Facebook on IPtables Firewall
Some employers like to block access to Facebook to their employees. Below is an example how to block traffic to Facebook.

Note: If you are a system administrator and need to apply these rules, keep in mind that your colleagues may stop talking to you :)

First find the IP addresses used by Facebook:

# host facebook.com 
facebook.com has address 66.220.156.68
# whois 66.220.156.68 | grep CIDR
CIDR: 66.220.144.0/20
You can then block that Facebook network with:

# iptables -A OUTPUT -p tcp -d 66.220.144.0/20 -j DROP
Keep in mind that the IP address range used by Facebook may vary in your country.

9. Setup Port Forwarding in IPtables
Sometimes you may want to forward one service’s traffic to another port. You can achieve this with the following command:

# iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j REDIRECT --to-port 2525
The above command forwards all incoming traffic on network interface eth0, from port 25 to port 2525. You may change the ports with the ones you need.

10. Block Network Flood on Apache Port with IPtables
Sometimes IP addresses may requests too many connections towards web ports on your website. This can cause number of issues and to prevent such problems, you can use the following rule:

# iptables -A INPUT -p tcp --dport 80 -m limit --limit 100/minute --limit-burst 200 -j ACCEPT
The above command limits the incoming connections from per minute to 100 and sets a limit burst to 200. You can edit the limit and limit-burst to your own specific requirements.

11. Block Incoming Ping Requests on IPtables
Some system administrators like to block incoming ping requests due to security concerns. While the threat is not that big, it’s good to know how to block such request:

# iptables -A INPUT -p icmp -i eth0 -j DROP
12. Allow loopback Access
Loopback access (access from 127.0.0.1) is important and you should always leave it active:

# iptables -A INPUT -i lo -j ACCEPT
# iptables -A OUTPUT -o lo -j ACCEPT
13. Keep a Log of Dropped Network Packets on IPtables
If you want to log the dropped packets on network interface eth0, you can use the following command:

# iptables -A INPUT -i eth0 -j LOG --log-prefix "IPtables dropped packets:"
You can change the value after "--log-prefix" with something by your choice. The messages are logged in  /var/log/messages and you can search for them with:

# grep "IPtables dropped packets:" /var/log/messages
14. Block Access to Specific MAC Address on IPtables
You can block access to your system from specific MAC address by using:

# iptables -A INPUT -m mac --mac-source 00:00:00:00:00:00 -j DROP
Of course, you will need to change "00:00:00:00:00:00" with the actual MAC address that you want to block.

15. Limit the Number of Concurrent Connections per IP Address
If you don’t want to have too many concurrent connection established from single IP address on given port you can use the command below:

# iptables -A INPUT -p tcp --syn --dport 22 -m connlimit --connlimit-above 3 -j REJECT
The above command allows no more than 3 connections per client. Of course, you can change the port number to match different service. Also the --connlimit-above should be changed to match your requirement.

16. Search within IPtables Rule
Once you have defined your iptables rules, you will want to search from time to time and may need to alter them. An easy way to search within your rules is to use:

# iptables -L $table -v -n | grep $string
In the above example, you will need to change $table with the actual table within which you wish to search and $string with the actual string for which you are looking for.

Here is an example:

# iptables -L INPUT -v -n | grep 192.168.0.100
17. Define New IPTables Chain
With iptables, you can define your own chain and store custom rules in it. To define a chain, use:

# iptables -N custom-filter
Now you can check if your new filter is there:

# iptables -L
Sample Output
Chain INPUT (policy ACCEPT)
target prot opt source destination
Chain FORWARD (policy ACCEPT)
target prot opt source destination
Chain OUTPUT (policy ACCEPT)
target prot opt source destination
Chain custom-filter (0 references)
target prot opt source destination
18. Flush IPtables Firewall Chains or Rules
If you want to flush your firewall chains, you can use:

# iptables -F
You can flush chains from specific table with:

# iptables -t nat -F
You can change "nat" with the actual table which chains you wish to flush.

19. Save IPtables Rules to a File
If you want to save your firewall rules, you can use the iptables-save command. You can use the following to save and store your rules in a file:

# iptables-save > ~/iptables.rules
It’s up to you where will you store the file and how you will name it.

20. Restore IPtables Rules from a File
If you want to restore a list of iptables rules, you can use iptables-restore. The command looks like this:

# iptables-restore < ~/iptables.rules
Of course the path to your rules file might be different.

21. Setup IPtables Rules for PCI Compliance
Some system administrators might be required to configure their servers to be PCI compiliant. There are many requirements by different PCI compliance vendors, but there are few common ones.

In many of the cases, you will need to have more than one IP address. You will need to apply the rules below for the site’s IP address. Be extra careful when using the rules below and use them only if you are sure what you are doing:

# iptables -I INPUT -d SITE -p tcp -m multiport --dports 21,25,110,143,465,587,993,995 -j DROP
If you use cPanel or similar control panel, you may need to block it’s’ ports as well. Here is an example:

# iptables -I in_sg -d DEDI_IP -p tcp -m multiport --dports  2082,2083,2095,2096,2525,2086,2087 -j DROP
Note: To make sure you meet your PCI vendor’s requirements, check their report carefully and apply the required rules. In some cases you may need to block UDP traffic on certain ports as well.

22. Allow Established and Related Connections
As the network traffic is separate on incoming and outgoing, you will want to allow established and related incoming traffic. For incoming connections do it with:

# iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
For outgoing use:

# iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
23. Drop Invalid Packets in IPtables
It’s possible to have some network packets marked as invalid. Some people may prefer to log those packages, but others prefer to drop them. To drop invalid the packets, you can use:

# iptables -A INPUT -m conntrack --ctstate INVALID -j DROP 
24. Block Connection on Network Interface
Some systems may have more than one network interface. You can limit the access to that network interface or block connections from certain IP address.

For example:

# iptables -A INPUT -i eth0 -s xxx.xxx.xxx.xxx -j DROP
Change “xxx.xxx.xxx.xxx” with the actual IP address (or network) that you wish to block.

25. Disable Outgoing Mails through IPTables
If your system should not be sending any emails, you can block outgoing ports on SMTP ports. For example you can use this:

# iptables -A OUTPUT -p tcp --dports 25,465,587 -j REJECT


#############################################
#############################################
