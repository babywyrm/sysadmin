#!/bin/bash

##
##

#ffufez - A simple script to automate ffuf
printf "~~ffufez~~\n"
printf "Input URL (URL/FUZZ): "
read url
clear

#variables
all_ext=".php,.html,.bak,.old,.txt,.zip,.aspx,.doc"
wordlist_1="/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
wordlist_2="usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
recursive_yes="-recursion -recursion-depth 2"
userpwd=$(pwd) > /dev/null
echo $url | cut -d'/' -f3 > filename.txt
filename=$(cat filename.txt)


printf "~~Wordlists~~\n"
printf "Select Worldlist 1-2: "
printf "\n1. raft-small-directories"
printf "\n2. directory-list-2.3-medium"
printf "\nCustom - Please type full file path\n"
printf ": "
read  wordlist
if [ "$wordlist" == 1 ]; then	
	wordlistf="$wordlist_1"
elif [ "$wordlist" == 2 ]; then
	wordlistf="$wordlist_2"
else 
	wordlistf="$wordlist"
fi
clear

printf "~~Extensions~~\n"
printf """Input manually in this format .txt,.html etc
Automatic -all to use common extensions\n"""
printf ": "
read extension
if [ "$extension" == "-all" ]; then
	extensionf="$all_ext"
else
	extensionf="$extension"
fi

clear

printf "~~Recursive~~\n"
printf "Yes/No"
printf ": "
read recursive
if [ "$recursive" == "yes" ] || [ "$recursive" == "Yes" ]; then
	recursivef="$recursive_yes"
else
	recursivef=""
fi
clear

printf " Scan will be saved here "$userpwd 
sleep 2
##ffuf scan
ffuf -u $url -w $wordlistf $recursivef -t 50 -c -o "$userpwd"/$filename -of html -e $extensionf
rm filename.txt

#######
#######
##
##
