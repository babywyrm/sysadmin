Local port forwarding
---------------------

```
ssh -nNT -L LOCALPORT:DESTINATION:DESTPORT SSHACCOUNT
```

To forward localhost:5000 to destination.net:80:

```
ssh -nNT -L 5000:destination.net:80 user@example.net
```

Proxy HTTP
----------

```
ssh -nNT -D LOCALPORT SSHACCOUNT
```

Using the following, the local port 8080 will proxied through example.net.

```
ssh -nNT -D 8080 user@example.net
```

Then, set-up your browser:

```
SOCKS host: localhost
      port: 8080
      
  [x] Socks v5
```

Arguments explained
-------------------

* `-n` Redirects stdin from /dev/null (actually, prevents reading from stdin).  This must be used when ssh is run in the background.
* `-N` Do not execute a remote command.  This is useful for just forwarding ports (protocol version 2 only).
* `-T` Disable pseudo-terminal allocation.
* `-L [bind_address:]port:host:hostport` Local port forward to host:hostport
* `-D [bind_address:]port` Local dynamic application-level port forwarding


Syntax:
```
ssh -L localport:host:hostport user@ssh_server -N
```

where:

-L - port forwarding parameters (see below)
localport - local port (chose a port that is not in use by other service)
host - server that has the port (hostport) that you want to forward
hostport - remote port
-N - do not execute a remote command, (you will not have the shell, see below)
user - user that have ssh access to the ssh server (computer)
ssh_server - the ssh server that will be used for forwarding/tunneling
Without the -N option you will have not only the forwardig port but also the remote shell. Try with and without it to see the difference.

Note:

Privileged ports (localport lower then 1024) can only be forwarded by root.
In the ssh line you can use multiple -L like in the example...
Of course, you must have ssh user access on secure_computer and moreover the secure computer must have access to host:hostport
Some ssh servers do not allow port forwarding (tunneling). See the sshd man pages for more about port forwarding (the AllowTcpForwarding keyword is set to NO in sshd_config file, by default is set to YES)...
Example:
```
ssh -L 8888:www.linuxhorizon.ro:80 user@computer -N 
ssh -L 8888:www.linuxhorizon.ro:80 -L 110:mail.linuxhorizon.ro:110 \ 
25:mail.linuxhorizon.ro:25 user@computer -N
```
The second example (see above) show you how to setup your ssh tunnel for web, pop3 and smtp. It is useful to recive/send your e-mails when you don't have direct access to the mail server.

For the ASCII art and lynx browser fans here is illustrated the first example:
```
   +----------+<--port 22-->+----------+<--port 80-->o-----------+ 
   |SSH Client|-------------|ssh_server|-------------|   host    | 
   +----------+             +----------+             o-----------+ 
  localhost:8888              computer      www.linuxhorizon.ro:80
```


...And finally: Open your browser and go to http://localhost:8888 to see if your tunnel is working. That's all folks!

The SSH man pages say:

-L port:host:hostport Specifies that the given port on the local (client) host is to be forwarded to the given host and port on the remote side. This works by allocating a socket to listen to port on the local side, and whenever a connection is made to this port, the connection is forwarded over the secure channel, and a connection is made to host port hostport from the remote machine. Port forwardings can also be specified in the configuration file. Only root can for- ward privileged ports. IPv6 addresses can be specified with an alternative syntax: port/host/hostport

-N Do not execute a remote command. This is useful for just for- warding ports (protocol version 2 only).

If you need additional infos or Q&A please go to Contact Page for our e-mail addresses...

Source http://www.linuxhorizon.ro/ssh-tunnel.html


##
##

# https://gist.github.com/padde/c3fc672a435fc71e621a

!!! WIP !!!
SSH Remote Port Forwarding
TODO: intro

Provision Server
DigitalOcean
512 MB RAM
Ubuntu 14.04
SSHD Config
SSH allows you to share ports forwarded to the server with other remote machines, not just the server itself. By default, SSH will open ports on the loopback address 127.0.0.1 on the server, but can be configured to use th wildcard address 0.0.0.0 instead, which means that we will be able to reach the forwarded port from the internet. On the server, add the following line to /etc/ssh/sshd_config:

GatewayPorts yes
Then restart the ssh daemon

sudo service ssh restart
Basic Firewall
We only allow the following connections:

Connections present at the time running the setup
Port 20 SSH
Port 80 HTTP
On the server run:

sudo iptables -I INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport ssh -j ACCEPT
sudo iptables -A INPUT -p tcp --dport http -j ACCEPT
sudo iptables -A INPUT -j DROP
sudo apt-get install iptables-persistent
sudo service iptables-persistent start
Check if forwarding works
On your local machine, start a web server to test out forwarding. For example, cd to a directory and start a simple webserver using Python:

cd ~/lolcats/
python -m SimpleHTTPServer
# Serving HTTP on 0.0.0.0 port 8000 ...
Then set up remote port forwarding via SSH:

ssh root@<your-server> -R 80:localhost:8000
If everything is ok, ssh should now listen on tcp 0.0.0.0:80 on the server and forward requests to port 8000 on your local machine, where the Python webserver is running. You can check whether SSHD uses the correct address on the server:

netstat -tunelp
It should look like this:

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          10643       1223/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      0          11653       1412/0
tcp6       0      0 :::22                   :::*                    LISTEN      0          10645       1223/sshd
tcp6       0      0 :::80                   :::*                    LISTEN      0          11654       1412/0
Now open a web browser, navigate to http://<your-server> and you should see the directory listing produced by the Python webserver. If so, you have successfully forwarded the port from the remote server to your local machine.

Usage
Although I ommitted it in the previous section, because I also wanted to check some things on the remote server, I would typically add the -N flag to the ssh command in order to prevent it from starting a shell session on the server, which really isn't necessary.

ssh -N root@<your-server> -R 80:localhost:<local-port
You might also want to add the -f flag, which runs the command as a background process. However, I tend to forget those processes and find it tedious to go through the output of ps aux | grep ssh to find unterminated port forwardings in order to kill them afterwards. Instead, I prefer having a command line window open during the entire connection time, and when I am done I just hit Ctrl-C.

Getting fancy
Maybe that's all you wanted, then you can stop reading now and be happy. However, I really wanted a command on my local machine that will allow me to spin up a new subdomain on my forwarding server with a one liner. Here's the interface I am aiming for:

fwd 1234
# creates random subdomain kh3451o5u3204.example.com on server and
# forwards requests to port 1234 on the local machine

fwd 1234 foobar
# creates random subdomain foobar.example.com on server and
# forwards requests to port 1234 on the local machine
When the command is killed with Ctrl + C, the subdomain should disappear from the server in order not to clutter the configuration.

TODO
Install nginx

sudo apt-get install nginx
Configure nginx
server {
  listen 80;
  server_name dev.example.com;
  location / {
    proxy_pass http://127.0.0.1:10001;
  }
}
Add /usr/local/bin/fwd on local machine
#! /usr/bin/env ruby

require 'securerandom'
require 'yaml'
require 'net/ssh'

def ssh_exec!(ssh, command)
  stdout = ''
  stderr = ''
  exit_code = nil

  ssh.open_channel do |channel|
    channel.exec(command) do |*, success|
      abort "Could not execute #{command} on server." unless success

      channel.on_data do |*, data|
        stdout << data
      end

      channel.on_extended_data do |*, data|
        stderr << data
      end

      channel.on_request('exit-status') do |*, data|
        exit_code = data.read_long
      end
    end
  end

  ssh.loop

  [stdout, stderr, exit_code]
end

local_port = ARGV.shift.to_i
abort 'Must be root to forward ports' if local_port < 1024 && `whoami` != 'root'

config = YAML.load_file "#{File.expand_path '~'}/.fwdrc"
abort 'No host provided in ~/.fwdrc' unless config['ssh_host']
abort 'No user provided in ~/.fwdrc' unless config['ssh_user']
ssh_host = config['ssh_host']
ssh_user = config['ssh_user']

subdomain = ARGV.shift
subdomain_length = 8
subdomain ||= SecureRandom.random_number(32**subdomain_length).to_s(32).rjust(subdomain_length, '0')
url = "http://#{subdomain}.#{ssh_host}"
system "echo '#{url}' | pbcopy"
puts 'URL copied to clipboard.'

Net::SSH.start(ssh_host, ssh_user) do |ssh|
  remote_host = '0.0.0.0'
  remote_port = nil
  10_000.upto(11_000) do |port|
    print "Checking port #{port}... "
    stdout, * = ssh_exec! ssh, %Q(netstat -anp tcp | awk '$6 ~ "LISTEN" && $4 ~ "#{port}$"')
    if stdout.empty?
      puts 'ok.'
      remote_port = port
      break
    else
      puts 'already in use.'
    end
  end
  abort 'Could not find an open port.' unless remote_port

  ssh.forward.remote_to(local_port, 'localhost', remote_port, remote_host)
  ssh.loop { !ssh.forward.active_remotes.include? [remote_port, remote_host] }

  # create subdomain config
  # nginx reload

  puts "Now forwarding requests from #{url} to local port #{local_port}."
  puts 'Hit Ctrl-C to stop.'

  ssh.loop { true }
end
Make executable
sudo chmod +x /usr/local/bin/fwd
Add ~/.fwdrc
ssh_host: example.com
ssh_user: root
This can now be removed again from /etc/ssh/sshd_config
GatewayPorts yes
Restart sshd
sudo service ssh restart
