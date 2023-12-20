
CORS, CSP, and Their Differences
Last updated: June 18, 2023

##
#
https://www.baeldung.com/cs/cors-csp-differences
#
##

Written by:Sandip Roy
NetworkingSecurityHTTP Security Attacks
1. Introduction
Cross-Origin Resource Sharing (CORS) and Content Security Policy (CSP) safeguard the integrity of a webpage and the secrecy of personal data. Both CORS and CSP save a website from malicious threats, but CSP is more selective about what is acceptable in an HTTP response.

In this tutorial, we’ll look at CORS and CSP and their differences, benefits, and limitations.

2. CORS and CSP
Generally, due to the Same Origin Policy (SOP), malicious scripts can’t access data from other domains (origins).

The term origin typically refers to the protocol, domain, and port. For example, https://www.baeldung.com and http://www.baeldung.com have different origins because the protocols differ.

Although SOP is a significant and well-tested security principle, many contemporary applications, such as the “mashups“, need to load resources from a trusted origin (domain, protocol, or port) to provide better functionality.

Moreover, cross-origin reads via scripts and cross-domain requests, such as Ajax requests via JavaScript, are by default prohibited by SOP. In addition, web pages may freely incorporate cross-domain pictures, stylesheets, scripts, and videos.

CORS and CSP are there to allow safe cross-origin reads.

3. CORS
Using the CORS HTTP header, a server can specify any origin other than its own from which a browser can load a resource:

This figure shows the steps of HTTP request using CROS mechanism
Hence, by combining SOP with CORS, web mashups can load resources only from whitelisted origins, thereby preventing access to potentially harmful domains.

Also, SOP guidelines don’t allow the execution of the scripts by third-party domains. However, CORS can specify whitelisted exceptions to allow some scripts.

3.1. Benefits and Limitations
Here are some advantages of CORS:

It uses a group of HTTP headers to relax the SOP’s universal black-list policy for third-party domain’s HTTP requests 
Browsers get access to data from cross-origin sources
Requests for resources are passed without credentials like cookies or the authorization header
A combination of CORS requests with a wildcard (“*”) and credentials (“True”) isn’t allowed
CORS has the following shortcomings:

There’s no protection against Cross-Site Request Forgery (CSRF) attacks
Poorly configured CORS increases the possibility of CSRF attacks or exacerbates their impact
4. CSP
CSP is another security measure we implement via an HTTP header.

Without a CSP, the browser loads every file on a website, which may be risky. By specifying the proper CSP directive in the HTTP response header, CSP restricts which data sources a web application can use:

This figure shows how CPS is used for access approval or rejection
As we see, CSP allows a web page to load only whitelisted resources, whereas others are blocked. Additionally, it helps to avoid attacks like Cross Site Scripting (XSS) and other code injection attacks.

4.1. Benefits and Limitations
Here are some advantages of CSP:

Risk mitigation and detection of XSS attacks
Defining legitimate sources of executable scripts
It can set a whitelist of domains
Also, it allows protocols
Connection is encrypted
CSPs have the following shortcomings:

CSP isn’t suitable for static websites we host on separate domains or subdomains that don’t require login or cookies
It isn’t suitable for websites using templates or frameworks with security flaws
Malicious code in a script can go unnoticed even if we sourced it from a trusted domain.
5. Comparison  
In brief, here are the differences between CORS and CSP:

Rendered by QuickLaTeX.com

5.1. CORS HTTP Headers
The Access-Control-Allow-Origin (ACAO) header is the most important one for CORS. The CORS policies are set on a particular host/page from the ACAO response headers.

Further, it’s a practice to send a preflight OPTIONS request to check the likelihood of success of ACAO using headers such as:

Origin specifies the request’s source
Access-Control-Allow-Methods allows HTTP methods
Access-Control-Max-Age sets the longest possible time the browser should keep the preflight request in its cache
Access-Control-Allow-Credentials for allowing cookies to be sent by browsers as part of ACAO.
5.2. CSP HTTP Headers
We can use the CSP HTTP header to specify the access policies. There are precise guidelines for individual policies for each content type (images, media, scripts).

Following are examples of some of the commonly used CSP headers:

default-src for fallback for other resource types having no policy of their own
script-src prevents inline scripts from running
style-src restricts inline styles from being applied
media-src restricts block media files from loading
img-src restricts block image files from loading
5. Conclusion
In this article, we talked about CORS and CSPs. Web applications employ CORS and CSP to regulate data sharing. Moreover, CORS and CSP facilitate data loading on web pages of the same or different origin. 

The difference between them is that CSP is selective about what we can allow in our HTTP response to trust a website’s sources.

Comments are closed on this article!
