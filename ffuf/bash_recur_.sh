#!/bin/bash

echo "###############################"
echo "#           Ffuf              #"
echo "###############################"
echo ""
echo ""
echo "[1] subdomains.txt"
echo "[2] subdomain-large.txt"
echo "[3] raft-large-directories.txt"
echo "[4] content_discovery_all.txt"
echo "[5] big.txt"
echo "[6] common_paths.txt"
echo "[7] dns-Jhaddix.txt"
echo "[8] wordpress.fuzz.txt"
echo "[9] burp-parameter-names.txt"
echo ""
read -p 'Chose Wordlist: ' wl
read -p 'Give Your URL(with FUZZ): ' u

if [[ $wl == 1 ]]
then
    ffuf -c -w ~/wordlist/subdomains.txt -u $u -recursion
elif [[ $wl == 2 ]]
then
    ffuf -c -w ~/wordlist/subdomain-large.txt -u $u -recursion
elif [[ $wl == 3 ]]
then
    ffuf -c -w ~/wordlist/raft-large-directories.txt -u $u -recursion
elif [[ $wl == 4 ]]
then
    ffuf -c -w ~/wordlist/content_discovery_all.txt -u $u -recursion
elif [[ $wl == 5 ]]
then
    ffuf -c -w ~/wordlist/big.txt -u $u -recursion
elif [[ $wl == 6 ]]
then
    ffuf -c -w ~/wordlist/common_paths.txt -u $u -recursion
elif [[ $wl == 7 ]]
then
    ffuf -c -w ~/wordlist/dns-Jhaddix.txt -u $u -recursion
elif [[ $wl == 8 ]]
then
    ffuf -c -w ~/wordlist/wordpress.fuzz.txt -u $u -recursion
elif [[ $wl == 9 ]]
then
    ffuf -c -w ~/wordlist/burp-parameter-names.txt -u $u -recursion
