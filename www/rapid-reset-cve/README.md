# Introduction

##
#
https://gist.github.com/adulau/7c2bfb8e9cdbe4b35a5e131c66a0c088
#
https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack
#
##

![2023_worlds_largest_rapid_reset_diagram max-1616x909](https://github.com/babywyrm/sysadmin/assets/55672787/b6b503d7-8b27-4caf-9237-f07e632132a3)


With HTTP/2, the client can open multiple concurrent streams on a single TCP connection, each stream corresponding to one HTTP request. The maximum number of concurrent open streams is, in theory, controllable by the server, but in practice clients may open 100 streams per request and the servers process these requests in parallel. It’s important to note that server limits can not be unilaterally adjusted.

For example, the client can open 100 streams and send a request on each of them in a single round trip; the proxy will read and process each stream serially, but the requests to the backend servers can again be parallelized. The client can then open new streams as it receives responses to the previous ones. This gives an effective throughput for a single connection of 100 requests per round trip, with similar round trip timing constants to HTTP/1.1 requests. This will typically lead to almost 100 times higher utilization of each connection.

The HTTP/2 Rapid Reset attack built on this capability is simple: The client opens a large number of streams at once as in the standard HTTP/2 attack, but rather than waiting for a response to each request stream from the server or proxy, the client cancels each request immediately.

The ability to reset streams immediately allows each connection to have an indefinite number of requests in flight. By explicitly canceling the requests, the attacker never exceeds the limit on the number of concurrent open streams. The number of in-flight requests is no longer dependent on the round-trip time (RTT), but only on the available network bandwidth.

In a typical HTTP/2 server implementation, the server will still have to do significant amounts of work for canceled requests, such as allocating new stream data structures, parsing the query and doing header decompression, and mapping the URL to a resource. For reverse proxy implementations, the request may be proxied to the backend server before the RST_STREAM frame is processed. The client on the other hand paid almost no costs for sending the requests. This creates an exploitable cost asymmetry between the server and the client.

Another advantage the attacker gains is that the explicit cancellation of requests immediately after creation means that a reverse proxy server won't send a response to any of the requests. Canceling the requests before a response is written reduces downlink (server/proxy to attacker) bandwidth.


###
###
###


This Gist aims to centralise the most relevant public sources of information related to the [HTTP/2](https://datatracker.ietf.org/doc/html/rfc7540) Rapid Reset vulnerability. This vulnerability has been disclosed jointly by Google, Amazon AWS, and Cloudflare on 10 October 2023 at 12:00 UTC.

Please help us make this page as comprehensive as possible by contributing relevant references, vendor advisories and statements, mitigations, etc.

# References

- [CVE-2023-44487](https://cvepremium.circl.lu/cve/CVE-2023-44487), CIRCL CVE Search
- [How AWS protects customers from DDoS events](https://aws.amazon.com/blogs/security/how-aws-protects-customers-from-ddos-events/), AWS
- [How it works: The novel HTTP/2 ‘Rapid Reset’ DDoS attack](https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack), Google
- [HTTP/2 Rapid Reset: deconstructing the record-breaking attack](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/), Cloudflare
- [Microsoft Response to Distributed Denial of Service (DDoS) Attacks against HTTP/2](https://msrc.microsoft.com/blog/2023/10/microsoft-response-to-distributed-denial-of-service-ddos-attacks-against-http/2/), Microsoft 
- Potential mention of a [similar issue in 2018 concerning HAproxy](https://www.mail-archive.com/haproxy@formilux.org/msg44134.html)
- [RFC7540 - Hypertext Transfer Protocol Version 2 (HTTP/2)](https://datatracker.ietf.org/doc/html/rfc7540)
- [Security Advisory 2023-074 HTTP/2 Rapid Reset DDoS Vulnerability](https://www.cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-074.pdf), CERT-EU
- [HTTP/2 Rapid Reset Vulnerability, CVE-2023-44487](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487), CISA
- [Using HTTP/3 Stream Limits in HTTP/2](https://martinthomson.github.io/h2-stream-limits/draft-thomson-httpbis-h2-stream-limits.html) - IETF draft to backport the HTTP/3 steam limits in HTTP/2

# Vendor advisories and statements

- [Apache Tomcat](https://github.com/apache/tomcat/commit/9cdfe25bad707f34b3e5da2994f3f1952a163c3e) - Fixed in 8.5.94
- [AWS](https://aws.amazon.com/security/security-bulletins/AWS-2023-011/)
- [F5](https://www.f5.com/company/blog/http-2-rapid-reset-attack-impacting-f5-nginx-products)
- [HAPROXY](https://www.haproxy.com/blog/haproxy-is-not-affected-by-the-http-2-rapid-reset-attack-cve-2023-44487) - HAProxy is not affected by the HTTP/2 Rapid Reset Attack
- [Microsoft IIS](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-44487)
- [Microsoft MsQuic](https://github.com/microsoft/msquic/releases/tag/v2.2.3) - Fixed in 2.2.3
- [Nginx](https://www.nginx.com/blog/http-2-rapid-reset-attack-impacting-f5-nginx-products/)
- [nghttp2 library](https://github.com/nghttp2/nghttp2/security/advisories/GHSA-vx74-f528-fxqg) - Fixed in 1.57.0

# Testing if HTTP/2 is enabled

## OpenSSL

~~~shell
echo 1 | openssl s_client -alpn h2 -connect google.com:443 -status 2>&1  | grep "ALPN"
~~~

## Nmap

~~~shell
nmap -p 443 --script=tls-nextprotoneg www.google.com
~~~

# Testing if it's vulnerable (use at your own risk)

- [Basic vulnerability scanning tool to see if web servers may be vulnerable to CVE-2023-44487](https://github.com/bcdannyboy/CVE-2023-44487)

# Potential remediation

### NGINX 

## can be configured to mitigate the vulnerability

- Disabling HTTP/2 in NGINX is not necessary. Simply ensure you have configured:

  -  `keepalive_requests` should be kept at the default setting of 1000 requests
  -  `http2_max_concurrent_streams` should be kept at the default setting of 128 streams
  -  `limit_conn` and `limit_req` should be set "with a reasonable setting balancing application performance and security"

## If you want to remove `http2` support

- Remove reference to `http2` in the listening part

### DDoS protection / CDNs

Web apps that are behind the following DDoS protection providers / CDNs should not be impacted:

- AWS
- Cloudflare
- Google Cloud
- Microsoft Azure
