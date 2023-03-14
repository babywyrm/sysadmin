#!/usr/bin/env bash


#
# From https://superuser.com/questions/109213/how-do-i-list-the-ssl-tls-cipher-suites-a-particular-website-offers
#
# Find cipher suites a website offers
#
# Usage
#   
#     ./test-ciphers.sh google.com:443

SERVER=$1
ciphers=$(openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g')

echo Obtaining cipher list from $(openssl version).

for cipher in ${ciphers[@]}
do
#echo -n Testing $cipher...
result=$(echo -n | openssl s_client -cipher "$cipher" -connect $SERVER 2>&1)
if [[ "$result" =~ ":error:" ]] ; then
  error=$(echo -n $result | cut -d':' -f6)
  echo -n Testing $cipher...
  echo NO \($error\)
else
  if [[ "$result" =~ "Cipher is ${cipher}" || "$result" =~ "Cipher    :" ]] ; then
    echo -n Testing $cipher...
    echo YES
  else
    echo -n Testing $cipher...
    echo UNKNOWN RESPONSE
    echo $result
  fi
fi
done


##
##

