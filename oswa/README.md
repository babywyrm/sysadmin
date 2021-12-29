
# webapp pentest #

#############################
#############################

rustscan -a TARGET
./autorecon.py TARGET

nmap -sV -p- --script=banner TARGET

nmap -p80 -sV --script http-wordpress-users TARGET -vvv
nmap -sC -sV -p 22,80,10022,10080 -v -oN nmap_TARGET.txt target.htb
 
dirsearch -u TARGET

dirb http://TARGET /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt 
dirb http://TARGET /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt 
dirb http://TARGET /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 
dirb http://TARGET:50045 /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 

wfuzz -c -z file,//usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt  --hc 301,404 http://TARGET/wp-admin/FUZZ
wfuzz -c -z file,//usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt  --hc 301,404,200,302 http://TARGET/wp-admin/FUZZ

ffuf -u 'http://TARGET/maintenance/..;/FUZZ' -mc 200 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-files.txt
ffuf -w subdomains.txt -u http://TARGET.com/ -H “Host: FUZZ.TARGET.com”
ffuf -w wordlist.txt -u http://TARGET.com/FUZZ -maxtime 60
ffuf -w wordlist.txt -u http://TARGE.com/FUZZ -X POST
ffuf -w wordlist.txt -X POST -d “username=admin\&password=FUZZ” -u http://TARGETT.com/FUZZ
ffuf -request req.txt -request-proto http -mode clusterbomb -w usernames.txt:HFUZZ -w passwords.txt:WFUZZ

#############################
#############################
 
(?)
Do we have services that provide juicy card review target?
Exposed repositories?

(?)
What ports are allegedly open on the surface?
What ports would need to be open internally/externally for the known services to appropriate function?
Is there a mysql/postgre/https/http backend?
Which webservices/apis/database services are allowing ingress?

(?)
Which webserver technologies are being utilized on the target?
Which of these technologies have juicy CVEs, and/or other viable research?




