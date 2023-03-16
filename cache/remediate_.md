
##
#
https://www.we45.com/post/an-in-depth-guide-to-web-cache-poisoning-and-how-to-prevent-it
#
##

Web cache poisoning is a relatively intuitive vulnerability to understand. Similar to poisoning a reservoir and rendering the water toxic, web cache poisoning works by inserting malicious data into a web cache that’s returned to the client-side user.While modifying web cache data itself isn’t an attack, it can be used to deliver harmful payloads that initiate cross-site scripting (XSS) or host-header injection attacks.

What is web cache memory?
Web caching is the process of temporarily storing data, such as a duplicate of a web page supplied by the web server, for later use.This copy is cached or saved as a web page the first time a user visits the website. When they visit the same website again, they’re served the cached copy instead of reaching out to the web server.Web caching is a great way to speed up website load times because the user doesn’t have to wait for the server to respond every single time. By reducing the burden on the backend servers, companies also save on network costs in the long run.

Types of web cache
1. Site Cache:The site cache or page cache stores website data the first time the web page is loaded. Saved items are instantly retrieved and presented to visitors each time a user comes to the website. This is a type of client-side caching, and it can be controlled by the end user. This caching technique is used in static sites which change rarely.2. Browser Cache:Browser caching is a type of site caching built into the end-user’s web browser. Website elements are stored by the browser on your visitor’s computer and grouped with other files associated with your content. A browser cache can contain HTML pages, CSS stylesheets, images, and other multimedia content.Browser caching overlaps with site caching because they are both client-side systems. The primary difference is that the browser, rather than the end-user, controls the cache. All browsers have a cache that flushes out old files without any need for user intervention3. Server Cache:This includes Content Delivery Network (CDN) caching, object caching, and opcode caching. Each stores a different content on the website’s server. This type of caching is administered by website owners without any input from end-users.Server caching is one of the most effective strategies for lowering server loads. When a request is made, the server examines its temporary storage for the required content before executing the request in its entirety.If the requested content is already in the server cache, it will be returned to the browser immediately. This allows the server to handle more traffic and deliver websites faster. This caching technique is best for high-traffic websites that need to reduce server overload.4. Micro cache:This is a type of site cache which only stores content for periods of up to 10 seconds. It’s controlled by end-users and requires limited input from website owners. This cache can be used in updating graphs on currency exchange and stock websites.

Web Cache poisoning
So far, we’ve discussed what web caches are, types of caches, and why they’re implemented.The main advantage with a web cache is that it reduces the burden on the web server or origin server when it receives the same request. This means the cache server stays in between the client and server. First, it checks if the related request and response are present in the cache. If it’s there, it sends the response to the user. If the cache doesn’t contain the related information, it sends a request to the web server.

web cache poisoning diagram
The web cache stores the HTTP Response for a set of time based on a set of rules called ‘cache keys’. Cache keys are part of HTTP requests and are used to identify the responses. They consist of the values of one or more response headers, as well as the whole or part of the URL path.There are many ways to exploit the web cache poisoning vulnerability, but here’s a specific example:Let’s say a website has header X-Original-User-Agent, and the value is reflected in the response.Request:

GET /my/vulnerable/site?background=pink HTTP/1.1

Host: example.com

User-Agent: Mozilla/5.0

X-Original-User-Agent: FirstrequestAgent

Accept: html/text

Cookie: ASP.NET_Session=23131;

Here, the cache key-value “/my/vulnerable/site?background=pink” and “example.com” and unused input(X-Original-User-Agent) are reflected in the response. Response:

HTTP/1.1 200 OK

X-Cache: Miss from cloudfront

...

<body>

<div id=”User-Agent”>FirstrequestAgent</div>

</body>Here, X-Original-User-Agent value is not properly sanitised; that means that the page could be susceptible to a reflected Cross-Site Script (XSS). If the X-Original-User-Agent header value is unkeyed, an attacker could perform web cache poisoning. It will be confirmed by sending a second request right after the first. If the response is identical to the response of the first request, the endpoint is likely to be vulnerable to web cache poisoning.Request:

GET /my/vulnerable/site?background=pink HTTP/1.1

Host: example.com

User-Agent: Mozilla/5.0

X-Original-User-Agent: SecondrequestAgent

Accept: html/text

Cookie: ASP.NET_Session=23131;



Response:

HTTP/1.1 200 OK

X-Cache: Hit from cloudfront

...

<body>

<div id=”User-Agent”>FirstrequestAgent</div>

</body>



The response shows X-Cache: Hit whichmeans the request was processed by the Cache server only.Once the vulnerability is confirmed, the attacker can inject a XSS script in the header. The reflected XSS will turn into stored XSS for the time being.Request:

GET /my/vulnerable/site?background=pink HTTP/1.1

Host: example.com

User-Agent: Mozilla/5.0

X-Original-User-Agent: <script>alert(document.domain)</script>

Accept: html/text

Cookie: ASP.NET_Session=23131



Response:

HTTP/1.1 200 OK

Cache-Control: public, max-age=3600

...

<body>

<div id=”User-Agent”>

<script>alert(document.domain)</script>

</div>

</body>Depending on the web application, attackers can exploit Stored XSS, Open redirects, and Denial of Service (DOS) attacks using this vulnerability.If the attacker submits the malicious request to the server, the same attack can be transformed into a DOS. When a real user hits the keyed request, the server will display a message that says, “The service is down” or “Website under maintenance,” which is saved in the cache server. The cache server transmits the page indicating that the service is offline or under maintenance.

How to prevent web cache poisoning
There are multiple ways to mitigate web cache poisoning, so here are the ones I find most effective:

Do not trust data in HTTP headers. Never return HTTP headers to users in cached, and if needed, sanitise user-supplied data.
Cache only static files and static content.
Regularly monitor web security advisories.
Check the cache refresh time and watch for any anomalies.

```
References:
https://www.varnish-software.com/glossary/what-is-web-caching/

‍https://managewp.com/blog/types-of-web-cache

‍https://blog.detectify.com/2020/07/28/do-you-trust-your-cache-web-cache-poisoning-explained/

‍https://developers.cloudflare.com/cache/best-practices/avoid-web-poisoning

‍https://www.acunetix.com/blog/articles/what-is-web-cache-poisoning/
