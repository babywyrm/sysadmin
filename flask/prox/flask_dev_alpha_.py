
#########################
#########################

from flask import request, Response
import requests
import os,sys,re
from cmd import Cmd

##########################
##########################

def _proxy(*args, **kwargs):
    resp = requests.request(
        method=request.method,
        url=request.url.replace(request.host_url, 'new-domain.com'),
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response

#########
#########

def url_total(url):
    s = Session()
    res = s.get('http://www.thing.thing.edu/status/main.js.php',cookies={'PHPSESSID':url})
    x = res.text.find("session_digest':'")
    y = res.text.find("'};")
    return res.text[x+17:y]

class pr(Cmd):
    prompt = "==>  "
    def default(self,url):
        url_digest = url_total(url)
        get(url,url_digest)
    def do_exit(self,a):
        exit()
        
pr().cmdloop()

#########################
#########################

##
##
