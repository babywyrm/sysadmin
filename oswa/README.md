
# webapp pentest #

#############################
#############################

rustscan -a TARGET
./autorecon.py TARGET

nmap -sV -p- --script=banner TARGET
<br>
nmap -p80 -sV --script http-wordpress-users TARGET -vvv
<br>
nmap -sC -sV -p 22,80,10022,10080 -v -oN nmap_TARGET.txt target.htb
 
dirsearch -u TARGET
<br>
dirb http://TARGET /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt<br>
dirb http://TARGET /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt<br>
dirb http://TARGET /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt<br> 
dirb http://TARGET:50045 /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt<br> 
<br>
<br>
wfuzz -c -z file,//usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt  --hc 301,404 http://TARGET/wp-admin/FUZZ
<br>
wfuzz -c -z file,//usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt  --hc 301,404,200,302 http://TARGET/wp-admin/FUZZ
<br>
<br>
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt
<br>
ffuf -u 'http://TARGET/maintenance/..;/FUZZ' -mc 200 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-files.txt
<br>
ffuf -w subdomains.txt -u http://TARGET.com/ -H “Host: FUZZ.TARGET.com”
<br>
ffuf -w wordlist.txt -u http://TARGET.com/FUZZ -maxtime 60
<br>
ffuf -w wordlist.txt -u http://TARGE.com/FUZZ -X POST
<br>
ffuf -w wordlist.txt -X POST -d “username=admin\&password=FUZZ” -u http://TARGETT.com/FUZZ
<br>
ffuf -request req.txt -request-proto http -mode clusterbomb -w usernames.txt:HFUZZ -w passwords.txt:WFUZZ
<br>
ffuf  -u 'http://TARGET/image.php?file=FUZZ' /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt 
<br>


#############################<br>
#############################
<br>
(?)
Do we have services that provide juicy card review target?
Exposed repositories?
<br>
(?)
What ports are allegedly open on the surface?
What ports would need to be open internally/externally for the known services to appropriate function?
Is there a mysql/postgre/https/http backend?
Which webservices/apis/database services are allowing ingress?
<br>

(?)
Which webserver technologies are being utilized on the target?
Which of these technologies have juicy CVEs, and/or other viable research?




