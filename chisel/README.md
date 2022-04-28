https://hideandsec.sh/books/cheatsheets-82c/page/pivoting


Chisel
Local port forwarding


#Pivot machine

chisel server -p 8080 --host 192.168.2.105 -v

#Our machine

chisel client -v http://192.168.2.105:8080 127.0.0.1:33333:10.42.42.2:80

Local port forwarding + SOCKS proxy

#Pivot machine

chisel server -p 8080 --host 192.168.2.105 --socks5 -v

#Our machine

chisel client -v http://192.168.2.105:8080 127.0.0.1:33333:socks

#Use

curl –head http://10.42.42.2 –proxy socks5://127.0.0.1:33333

Reverse remote port forwarding

#Our machine

chisel server -p 8888 --host 192.168.2.149 --reverse -v

#Pivot machine

chisel client -v http://192.168.2.149:8888 R:127.0.0.1:44444:10.42.42.2:80

Reverse remote port forwarding + proxy SOCKS (auto local port forwarding internal socks proxy)

On our machine :

chisel server -p 8888 --host 192.168.2.149 --reverse -v

Chisel can't be used as a SOCKS proxy server directly :

    Run a SOCKS server
    Connect us with a second client
    Make a local port forwarding to the local Chisel server in order to share the SOCKS proxy server to the first client

On the pivot machine :

chisel client -v http://192.168.2.149:8888 R:127.0.0.1:44444:127.0.0.1:55555

chisel server -p 62000 --host 127.0.0.1 --socks5 -v

chisel client -v http://127.0.0.1:62000 127.0.0.1:55555:socks

To test : curl --head http://10.42.42.2 --proxy socks5://127.0.0.1:44444


Pivot with Chisel
Pivoting With Chisel
Use Chisel to traverse the intranet

Posted on July 1st, 2019
ForewordRecently, when I encountered a target in the project on the intranet, I used Chisel to open a tunnel to the intranet. If I want to do something good, I must first sharpen my tools, so I decided to share this tool with everyone.

What is Chisel

Chisel is a fast TCP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang).

    Https://github.com/jpillora/chisel

The above is the explanation in chisel official GitHub repo

In one sentence, it is: Chisel is a fast TCP tunneling tool for writing open source communication encryption for bypassing firewalls using HTTP? protocol for transmission.

Features:

    Easy to use
    high performance
    Encrypted connection using SSH protocol (via crypto/ssh)
    Support for authentication
    Client automatically reconnects
    Clients can create multiple tunnels over a single TCP connection
    Clients can create an HTTP CONNECT proxy
    Server can choose to double as a reverse proxy
    The server can choose to create a SOCKS5 proxy
    Support reverse port forwarding

Why choose Chisel

Lcx is a well-known port forwarding tool in China. It is very stable but has a shortcoming. For example, using lcx to forward the RDP port of the intranet Windows, the RDP connection cannot be used after it is disconnected once, and the port must be re-executed. Forward

EarthWorm&Termite is really powerful, the file size is only a few tens of KB, but this tool is closed source, and it doesn’t feel good for free but closed source programs, because the tool has been killed and killed.

The author also stopped developing

Also found a tool called frp, a lot of features, but the operation requires a configuration file, not suitable for penetration of network penetration in the test.

There are many similar tools, you can choose according to your own needs.

Choosing to find Chisel is still quite good.
Install Chisel

Chisel is written in Go, so it supports almost all operating systems. It can download executable files for each operating system directly from GitHub, but it is relatively large. The executable file under the downloaded MacOS system is 8M in size, so I Choose to compile from source, customize the configuration to a smaller size

First, prepare the Go runtime environment. For the installation method of each operating system, see the official website:https://golang.org/doc/install

The following operations are performed under the MacOS system.

Need to be set before downloading GOPATH

Download chisel from github

go get -v github.com/jpillora/chisel

Compile

go build github.com/jpillora/chisel

Will generate an executable called Chisel in the current directory, let’s look at the size

▶ go build github.com/jpillora/chisel

▶ du -sh chisel
 11M	chisel

11 M, too large, you can reduce the file content by removing the symbol table (-s)and relocating information at compile time (-w).

▶ go build -ldflags "-s -w" github.com/jpillora/chisel

~/MyTools/Pivot
▶ du -sh chisel
8.8M	chisel

It’s 8M now, it’s still a bit big, try adding a UPX shell.

▶ upx -9 chisel
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   9258820 ->   3399696   36.72%   macho/amd64   chisel

Packed 1 file.

▶ du -sh chisel
4.0M	chisel

Now it’s 4M, it’s still a bit bigger than other tools, but it’s good to compress from 11M to 4M. The executable file compiled by go is very large because go compiles by default using static compilation, does not depend on any dynamic links. Library, so you can deploy to any running environment, don’t worry about dependency

Compile the Windows version on MacOS using the following command

▶ env GOOS=windows GOARCH=amd64 go build -o chisel-x64.exe -ldflags "-s -w" github.com/jpillora/chisel

▶ file chisel-x64.exe
chisel-x64.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows

Compress with UPX

▶ du -sh chisel-x64.exe
8.0M	chisel-x64.exe

▶ upx chisel-x64.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   8342528 ->   3173376   38.04%    win64/pe     chisel-x64.exe

Packed 1 file.

▶ du -sh chisel-x64.exe
3.0M	chisel-x64.exe

If desired the compiled executable file in the other operating system, go buildprovided compile time GOOSand GOARCHis a value corresponding to the specific value Seeing GitHub Gist
Use Chisel to bounce Socks5 proxy

Chisel can use the Chisel to bounce a socks5 agent from the target network when it encounters a target in the penetration test or is blocked by the firewall.

The principle of Chisel’s rebound Socks5 agent is roughly as follows

The specific steps are as follows:

Executed in a host with a public IP address

chisel server -p 1111 --reverse  

The above command will listen to the local (0.0.0.0) port 1111 and allow the far end to specify the forwarding port.

chisel client 0.0.0.0:2222 socks 

The above command will start the socks5 service on the local 1080 port of 127.0.0.1 and forward the request to the local port 2222.

Executed in the host of the target network that needs to be accessed or in the host in the LAN environment

chisel client WANIP:1111 R:2222:127.0.0.1:3333 

The above command opens a tunnel on port 1111 of WANIP and maps the 2222 port of WANIP to the local 3333 port in this tunnel.

chisel server -p 3333 --socks5 

The above command starts the Socks5 service on the local 3333 port.

At this time, the Socks5 proxy of the public network host 1080 port leads to the other network through the tunnel of the 1111 port.

Conditional students can go to see Ippsec video demo
Port mapping using Chisel

Chisel can implement the same functions as lcx, as follows:

Start the Chisel server on the public network host:

chisel server -p 1337 --reverse

Start the Chisel client on the intranet host:

chisel client WANIP:1337 R:1234:LANIP:3389  

WANIP is the public network IP of the public network host, and LANIP is the internal network IP of the internal network host.

If the client mode of Chisel is started on server1 and the LANIP is the IP of server1, the port 3389 of server1 is mapped to port 1234 of the public network host.

If the client mode of Chisel is running on server1, but the LANIP is the IP of server2, the 3389 port of server2 is mapped to the port 1234 of the public network through server1.

From the second usage, Chisel’s port forwarding function is more powerful than lcx.

After mastering the above port forwarding skills, Ma Ma no longer has to![68747470733a2f2f646f63732e676f6f676c652e636f6d2f64726177696e67732f642f317035335657787a474e667938726a722d6d5738707669734a6d686b6f4c6c383276416763744f5f366631772f7075623f773d39363026683d373230](https://user-images.githubusercontent.com/55672787/165667055-f9811955-5791-4082-9aa6-8a370a60c261.png)
![2019-04-12-074113](https://user-images.githubusercontent.com/55672787/165667058-e4b09fcb-4e89-44f2-9e19-ceb30092d8f5.jpg)
![2019-04-17-143105](https://user-images.githubusercontent.com/55672787/165667059-52987548-4eca-496a-aa31-aafc7b006368.jpg)
 worry that I can’t access my fragrant broiler because of the firewall or internal and external network restrictions!
Reference link


