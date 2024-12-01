##
#
https://bishopfox.com/blog/h2c-smuggling-request
#
##


# HTTP/2 (h2c) Smuggling Tools

HTTP/2 Cleartext (h2c) smuggling tools are essential for detecting and exploiting misconfigurations in HTTP/2 upgrade handling by proxies and servers. This document summarizes key tools for testing and research.

## h2csmuggler
**Purpose**: Detect and exploit HTTP/2 Cleartext (h2c) misconfigurations.  
**Capabilities**:  
- Test for h2c support.  
- Perform HTTP/2 request smuggling.  
- Automate backend path brute-forcing.  
**Installation**:
```bash
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler
pip install -r requirements.txt
```
Examples:

Test h2c support:

python3 h2csmuggler.py --test -x http://target
Perform request smuggling:

python3 h2csmuggler.py -x http://proxy -X POST -d "data" http://backend/resource


Curl
Purpose: Test HTTP/1.1 and HTTP/2 requests, including h2c upgrades.
Capabilities:

Send requests with custom headers.
Force HTTP/2 usage.
Examples:
Test h2c upgrade:

```
curl -v --http1.1 \
  -H "Connection: Upgrade, HTTP2-Settings" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  http://caption.htb
```
Force HTTP/2:

curl -v --http2-prior-knowledge http://caption.htb
nghttp
Purpose: A specialized HTTP/2 client for testing and debugging HTTP/2 connections.
Capabilities:

Establish HTTP/2 Cleartext (h2c) connections.
Send custom HTTP/2 frames.
Installation:
```
apt install nghttp2-client
```
Examples:

Test HTTP/2:

nghttp -v http://caption.htb
Test h2c upgrade:

```
nghttp -v -u :method=GET http://caption.htb
```

Hyper-h2 (Python Library)
Purpose: Programmatically test and send HTTP/2 frames.
Capabilities:

Perform advanced HTTP/2 interactions.
Automate HTTP/2 testing.
Installation:

```
pip install h2
```

Burp Suite
Purpose: Intercept, modify, and analyze HTTP requests.
Capabilities:

Modify headers for Upgrade: h2c requests.
Use extensions for smuggling and vulnerability testing.
Extensions:
HTTP Request Smuggler: Automates detection and exploitation of HTTP smuggling vulnerabilities.
h2spec
Purpose: Conformance testing tool for HTTP/2 implementations.
Capabilities:

Test compliance with the HTTP/2 specification.
Identify misconfigurations in HTTP/2 handling.
Installation:

```
git clone https://github.com/summerwind/h2spec.git
cd h2spec
make
```


Examples:

```
h2spec -h caption.htb -p 80
```

ffuf (Fuzz Faster U Fool)
Purpose: A fast web fuzzer for discovering hidden paths or files.
Examples:
```
ffuf -u http://caption.htb/FUZZ -w /path/to/wordlist.txt
```
mitmproxy
Purpose: Intercept and modify HTTP/2 traffic in real time.
Installation:

apt install mitmproxy
```

Go-http2curl
Purpose: Generate curl commands from HTTP/2 traffic.
Installation:

```
go install github.com/moul/http2curl/cmd/http2curl@latest
```




Blog // Tech // Sep 08, 2020
h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext (h2c)
By: Jake Miller, Security Researcher
HTTP request smuggling example
Share

The revival of HTTP request smuggling has led to devastating vulnerabilities in our modern application deployments. An HTTP request smuggled past the validation of an edge server can lead to serious consequences, including forged internal headers, access to internal management endpoints, and a variety of opportunities for privilege escalation.

HTTP/2 (or HTTP/3) is a promising solution to the issues we’ve faced with request smuggling, but support for HTTP/1.1 isn’t going away anytime soon. In the meantime, we’re still in for more surprises from our good friend HTTP/1.1.

In this post, I demonstrate how upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections can allow a bypass of reverse proxy access controls, and lead to long-lived, unrestricted HTTP traffic directly to back-end servers.

BACKGROUND: HTTP/1.1 UPGRADES AND PROXIES
To understand this vulnerability, let’s review the behavior of the HTTP/1.1 upgrades and how upgrades are implemented by proxies.

The Upgrade header is most often used to upgrade HTTP connections to long-lived WebSocket connections. Proxies support this behavior by keeping the original client connection alive and simply proxying the TCP traffic to the back-end server. At this point, the proxy is no longer content-aware and can no longer enforce access control rules.

Let’s examine the h2c upgrade process. It begins with the client initiating an HTTP/1.1 upgrade request. Once a successful 101 “Switching Protocols” response is received, the client reuses the connection and transmits data in accordance with the newly negotiated protocol, in this case h2c. The diagram below illustrates this behavior:

h2c diagram 1
After receiving the 101 response from the back-end web server, the proxy maintains a persistent TCP connection and no longer monitors the content. To quote the NGINX WebSocket documentation:

“A WebSocket application keeps a long‑running connection open between the client and the server, facilitating the development of real‑time applications. […] NGINX supports WebSocket by allowing a tunnel to be set up between a client and a backend server.

- https://www.nginx.com/blog/web...

In his WebSocket smuggling research, Mikhail Egorov (@0ang3el) demonstrated that by triggering issues with the back end when upgrading to a WebSocket connection, he could maintain a pipelined HTTP/1.1 connection with the back end when the proxy upgraded the connection to a TCP tunnel. This allowed requests to be smuggled, evading the proxy server’s access controls.

Although this form of request smuggling does not lead to socket poisoning (also known as HTTP desync) attacks, it can still allow you to bypass significant edge-server access controls. It is an excellent addition to your bag of tricks when testing services with WebSocket support.

But what if we didn’t have to trick the back end and could just maintain an HTTP-based TCP tunnel by design? Here’s where h2c upgrades come into play. I decided to investigate the behavior of h2c implementations to see if I could find a more flexible option for smuggling. 

THE H2C SPECIFICATION AND A RISKY OPPORTUNITY
Typically, usage of the HTTP/2 protocol is negotiated over the TLS application-layer protocol negation extension (TLS-ALPN), where it is identified by the string "h2." This happens before we send our first HTTP request.

However, HTTP/2 can also be initiated via an HTTP/1.1 Upgrade header, identified by the string "h2c" for cleartext communication. Here is an example request:
```
GET / HTTP/1.1
Host: www.example.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

The hop-by-hop header HTTP2-Settings contains Base64 encoded HTTP/2 connection parameters. According to the specification, h2c upgrades are allowed only on cleartext connections and the HTTP2-Settings header should not be forwarded (RFC 7540 Section 3.2.1).

Reading the specification led me to three questions:

If the edge proxy is performing TLS termination, and I send an h2c upgrade request in an HTTP message, how would the back-end server  know that we are attempting an h2c upgrade over TLS?
If the edge proxy is not h2c-aware, will it forward a client’s h2c upgrade request?
If the edge proxy successfully forwards my h2c upgrade to the back-end server and it is accepted by that server, can I bypass proxy restrictions in the provided TCP tunnel?
cURL and other HTTP/2 clients won’t let you perform an h2c upgrade over TLS because it is a violation of the specification. So, using the hyper-2 HTTP2 library, I created a custom client to test.

PROOF OF CONCEPT
I configured an NGINX server with TLS termination on port 443 with a WebSocket-like proxy_pass on the / endpoint to a back-end service supporting h2c upgrades. I also configured the NGINX server with an access control that blocked all requests to the /flag endpoint, as shown in the configuration below:
```
server {
    listen       443 ssl;
    server_name  localhost;

    ssl_certificate       /usr/local/nginx/conf/cert.pem;
    ssl_certificate_key   /usr/local/nginx/conf/privkey.pem;

    location / {
     proxy_pass http://backend:9999;
     proxy_http_version 1.1;
     proxy_set_header Upgrade $http_upgrade;
     proxy_set_header Connection $http_connection;
    }

    location /flag {
    deny all;
    }
```

For the back-end server, I created a simple Golang server that supported h2c upgrades:

```
// Lightly modified example from: https://github.com/thrawn01/h2c-golang-example
package main

import (
    "fmt"
    "golang.org/x/net/http2"
    "golang.org/x/net/http2/h2c"
    "net"
    "net/http"
    "os"
)

func checkErr(err error, msg string) {
    if err == nil {
        return
    }
    fmt.Printf("ERROR: %s: %s\n", msg, err)
    os.Exit(1)
}

func main() {    
    h2s := &http2.Server{}

    handler := http.NewServeMux()
    handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, %v, http: %v", r.URL.Path, r.TLS == nil)
    })

    handler.HandleFunc("/flag", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "You got the flag!");
    })

    server := &http.Server{
        Addr:    "0.0.0.0:9999",
        Handler: h2c.NewHandler(handler, h2s),
    }

    fmt.Printf("Listening [0.0.0.0:9999]...\n")
    checkErr(server.ListenAndServe(), "while listening")
}
```

Directly sending requests to the proxy for the / endpoint succeeded and the /flag endpoint failed, as expected:

H2C Smuggling - Golang server
This behavior is shown in the diagram below:

h2c diagram 2
Now using my custom client, h2cSmuggler, to initiate an upgrade over TLS, we are able to successfully access the restricted endpoint (-x specifies the proxy):

H2C Smuggling in action
This behavior is shown in the diagram below:

h2c diagram 3
 Let’s break down what just happened:

h2cSmuggler transmits an HTTP/1.1 upgrade request to the / endpoint on the NGINX reverse proxy.
The proxy forwards the Upgrade and Connection headers to the back end, which responds with "101 Switching Protocols" and prepares to receive HTTP2 communications.
Upon receiving the 101 response from the back end, the proxy “upgrades” the connection to an unmanaged TCP tunnel.
Upon receiving the 101 response from the proxy, h2cSmuggler reuses the existing connection and exchanges HTTP/2 initialization frames with the server. These include the server’s response for the endpoint requested in the HTTP/1.1 h2c upgrade (the / endpoint).
Using HTTP/2 multiplexing, h2cSmuggler sends an additional request for the restricted /flag
The proxy, which is no longer monitoring communications in the TCP tunnel, forwards the request to the back-end server.
The server responds with the flag.
As shown above, we successfully bypassed the proxy’s access controls to access the private endpoint! (Try out the tool and Docker demos here.)

Per the specification, proxies will always expect h2 protocol negotiation to occur through TLS-ALPN. So, we can instead initiate h2c connections via HTTP/1.1 over TLS using h2cSmuggler.

We can also perform this attack over some cleartext channels. As long as the proxy does not support h2c upgrades and simply forwards the client’s h2c upgrade request to the back end, this attack will likely succeed on non-encrypted channels as well.

Through a separate experiment, I confirmed that in the event of multiple layers of proxies, this technique still works. Assuming all of the proxies successfully pass the necessary headers, you can perform the original attack and it will pass your data along the series of intermediary TCP tunnels created by each respective proxy.

With this type of request smuggling (“tunnel smuggling”?), you can send as many requests as you like via HTTP/2 multiplexing. Also, as we know from prior research, HTTP request smuggling enables a wide variety of attacks, including: forging internal headers, accessing restricted administrative endpoints, and sometimes Host header SSRF allowing further movement through the network.

But I know what you’re thinking: "That NGINX config seems too specific. When is that going to happen?"

Here are insecure HAProxy, Traefik, and Nuster configurations (about as generic and innocuous as you can get) that forward the required h2c headers by default: 
```
HAProxy/Nuster

mode http
frontend fe
bind *.8080
   default_backend be1
backend be1
server s1 backend:80
Traefik


http:
  routers:
    to-test:
      rule: "PathPrefix (`/`)"
      service: test

  services:
    test:
      loadBalancer:
        servers:
        - url: http://backend:80

```
Note: Traefik doesn’t include HTTP-2-Settings on the proxied Connection string, which may cause the attack to fail on some h2c implementations. 

What about back-end servers supporting h2c?

Because of its ability to reduce bandwidth, h2c makes a strong candidate for low-latency intra-network (i.e., microservice) communication, and avoids the management and (contested but often cited) performance overhead of TLS.

As such, popular web frameworks often support a configuration option to enable h2c upgrade support. That said, support is rarely an out-of-the-box default.

Assuming an insecure front-end proxy configuration, h2c usage in microservices may increase the likelihood of a successful attack.

REMEDIATION
To mitigate the risks of h2c smuggling on proxy servers:

WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket).
WebSocket support not required: Do not forward Upgrade headers.
Which services are (and are not) affected by default?

For h2c smuggling to succeed, the Upgrade header (and sometimes the Connection header) needs to be successfully forwarded from the edge server to a back-end server that supports h2c upgrades. This configuration can occur on any reverse proxy, WAF, or load balancer.

By default, the following services do forward Upgrade and Connection headers during proxy-pass, thereby enabling h2c smuggling out-of-the-box.:

HAProxy
Traefik
Nuster
By default, these services do not forward both Upgrade and Connection headers during proxy-pass, but can be configured in an insecure manner (by passing unfiltered Upgrade and Connection headers):

AWS ALB/CLB
NGINX
Apache
Squid
Varnish
Kong
Envoy
Apache Traffic Server
Example remediation for HAProxy/Nuster:

If only WebSocket upgrades should be allowed:

http-request replace-value Upgrade (.*) websocket
If no upgrades should be allowed:

http-request del-header Upgrade
Example remediation for Traefik:

This middleware configuration will replace or remove Upgrade headers as they appear in incoming requests:

```
http:
  routers:
    routerA:
      middlewares:
        - "testHeader"
  <span style="color:#c2282e;">…omitted for brevity…</span>
  middlewares:
    testHeader:      
      headers:
        customRequestHeaders:
          Upgrade: "" # "" removes the header; set to “websocket” to hardcode the value

```

OUR FINDINGS FROM TESTING ON COSMOS (FORMERLY CAST)
As part of our research process, we test newly discovered attack techniques against customers of Bishop Fox's Cosmos, a managed service that continually tests customers' external perimeters.

Here are lessons we learned when we attempted to identify instances of h2c smuggling across a large set of hosts:

Each proxy pass endpoint needs to be verified separately. When testing across all customer assets, the result set varied based on the path we were testing (/api/ is a more common proxy_pass path than /). Testing one arbitrary endpoint (e.g., /api/) against multiple targets is less effective than testing multiple known endpoints (e.g., the results of directory enumeration with gobuster) against a single target.
The primary false positives on TLS-enabled services were servers that responded with “101 Switching Protocols” in response to our h2c upgrade request, but didn’t respond to any of the subsequent HTTP/2 frames that we sent. Instead, we only received TCP ACK and RST packets at the transport layer. This indicated that servers may respond with a 101 but may not be equipped to communicate HTTP/2.
It is a good idea to test for both compliant Connection: Upgrade, HTTP2-Settings and the non-compliant Connection: Upgrade variants of the connection header (h2cSmuggler’s --upgrade-only option). Similar to the proxies, not all back ends were compliant.
Here are some exploitation tips:

Endpoint brute-forcing with HTTP/2 multiplexing (h2cSmuggler’s -i option) is very fast and can be used to find additional internal endpoints.
See param-miner’s list of headers for inspiration for spoofed internal headers.
Because you are bypassing intermediary proxies, your request may be missing headers expected by the back-end service. Additional information disclosures via error messages or recon may be required for successful interaction with back-end services.
If there are no access controls to bypass, then tunneling requests via h2c smuggling does not provide any additional access (e.g., a TLS terminating network load balancer may forward upgrades, but it doesn't enforce any HTTP access controls).
CONCLUSION
Request smuggling and other proxy bypass vulnerabilities highlight a growing issue affecting modern web application architecture: an overreliance on edge-sever access controls for security guarantees.

In many ways, arbitrary user-controlled requests through request smuggling or request forgery attacks have become the “hijacking the instruction pointer” of modern, RPC-driven microservice architectures. Maintaining defense-in-depth strategies, reducing the significance of smuggled headers in your architecture, and being prepared to identify and reject suspicious requests on the back end will help reduce the impact of future attack techniques.

Check out the tool and demos here: https://github.com/BishopFox/h2csmuggler

Follow me on Twitter at: @theBumbleSec

THANK YOU
Thank you to @0ang3el for his fantastic research on WebSocket request smuggling, and to @regilero and @albinowax for their inspiring and terrifying work on HTTP smuggling vulnerabilities.

