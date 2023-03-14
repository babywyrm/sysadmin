#!/usr/bin/env bash

#
# Find TLS Protocols 
# 
# Usage
#     ./test-tls.sh google.com:443
# 

SERVER=$1
protocols=(-ssl3 -tls1_2 -tls1_1 -tls1)

echo Using $(openssl version).

for proto in ${protocols[@]}
do
echo -n Testing $proto...
result=$(echo -n | openssl s_client -connect $SERVER $proto 2>&1)
if [[ "$result" =~ "no peer certificate available" ]] ; then
  error=$(echo -n $result | cut -d':' -f6)
  echo NO \($error\) 
else
  if [[ "$result" =~ "Cipher is ${cipher}" || "$result" =~ "Cipher    :" ]] ; then
    echo YES
  else
    echo UNKNOWN RESPONSE
    echo $result
    echo ----------------------------------------------------
  fi
fi
done

##
##
