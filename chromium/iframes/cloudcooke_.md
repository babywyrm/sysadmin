Safari iframe cookie workaround
===============================

Safari by default discards cookies set in an iframe unless the host that's serving the iframe has set a cookie before, outside the iframe. Safari is the only browser that does this.

The 10k foot view
-----------------

In order to get around the issue, the parent (src) and child/iframed/remote (dest) site have to work together, if the source site only wants users to access the destination via the iframe and can't assume that the user has visited the destination host before.

Normally, a user would navigate from page A, with no external iframe, to page B, with an external iframe, by clicking a direct link between the two. To make the workaround work, the link from page A is instead a "bounce" URL on the destination site, which sets a cookie (no requirements on name, value, etc.) and redirects back to page B. The redirect can be hard-coded for security, or left more open.

The warning
-----------

The following files are a naive example of the problem/solution. You'll want to think through your solution more carefully...don't copy-paste these snippets into a production setting! I haven't thought through the security ramifications of what's shown here...which means that there are some, and they aren't good. You've been warned.

The implementation details
--------------------------

This gist includes an implementation of both source and destination sides of the above workaround, including a test to make sure that it actually works. To see the fix in action, place src.php on one host, dest_xxx.php on another, then edit lines 2 and 3 on src.php to reference where those files show up.

To see the Safari problem without the solution, on a new Safari browser, navigate to src.php?redirected=true on a "clean" Safari. By "clean" we mean that Safari has never had a cookie (successfully) set by the destination domain before. The easiest way to do this is to fire up a Safari-powered instance on BrowserStack or the like.

When you load the page, you'll get an iframe. Click the link inside the iframe and you'll be greeted with a "Cookie not set!" message.

To see the solution, navigate to src.php (without the query string parameter) in the same browser (since the cookie wasn't successfully set, there's no need to set up a new clean Safari instance, though you can if you like). Then click the "Bounce here..." link. The browser will hit the remote site, which will set a blank cookie and redirect back to src.php?redirected=true.

When you click the link inside the iframe this time, you'll get "Cookies match!".

Note that if you use some browser (Chrome, Firefox, IE) other than Safari, you can just hit src.php?redirected=true and get "Cookies match!" without having to first go through the redirect.

The credits
-----------

This issue was discovered, and its solution devised, while working on Parking Mobility (https://parkingmobility.com).

##
##


dest_bounce.php
<?php
header("Location: " . $_GET['redirect']);
setcookie("__trust");
dest_get.php
<?php
if (!isset($_COOKIE['testcookie']))
    echo "Cookie not set!";
else if ($_COOKIE['testcookie'] != $_GET['cookie'])
    echo "Cookies don't match: " . $_COOKIE['testcookie'] . ' != ' . $_GET['cookie'];
else
    echo "Cookies match!";
dest_set.php
<?php
$value = uniqid();
setcookie("testcookie", $value);
echo "<p>Now go <a href='dest_get.php?cookie=" . $value . "'>here</a></p>";
src.php
<?php
$internalPath = "http://local.test/path";
$externalPath = "http://remote.test/path";
?>

<html><head><title>Redirect Cookie Test</title></head>
<body>
    <?php if ($_GET['redirected']): ?>
        <p>iframe starts below...</p>
        <iframe src="<?= $externalPath ?>/dest_set.php"?>
    <?php else: ?>
        <a href="<?= $externalPath ?>/dest_bounce.php?redirect=<?= $internalPath ?>/src.php?redirected=true">Bounce here...</a>
    <?php endif; ?>
</body>
Load earlier comments...
@tgima1
tgima1 commented on Mar 16, 2020 • 
I used a popup to do the trick (by temporary passing the cookie as parameter to a third party API).
If you have full control on site B (code + DNS) I advice you to declare a subdomain in you site B which forward silently to your wished website/API (add a new AAAA entry with your service IP) :

       +------------------+                          +-----------------------+
       |                  |   XHR with credentials   |                       |
       |  www.siteB.com   --------------------------->  api-siteA.siteB.com  |
       |                  |                          |                       |
       +------------------+                          +-----------------------+
@russau
russau commented on Mar 30, 2020
It looks like all of these approaches have gone away with Safari 13.1 :(

https://community.shopify.com/c/Shopify-APIs-SDKs/Safari-13-1-and-embedded-apps/td-p/688416
https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/

@mwleinad
mwleinad commented on Apr 7, 2020
Any idea if there's a workaround with safari 13.1?

@antstorm
antstorm commented on Apr 12, 2020
Looks like requesting storage access via their APIs is the way to do it — https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/

@Arcolye
Arcolye commented on Apr 29, 2020 • 
What a fantastic time to put this extra hurdle on struggling and furloughed development teams. Thanks Apple, Safari, and specifically John Wilander!

With brick-and-mortar businesses struggling and software companies doing what they can to help out, NOW was the time to release this huge software-breaking change? Not 2022 like Chrome has roadmapped? Now? During the Covid recession? And with "Storage Access API" still in a poorly-documented and experimental phase? Now?

Badly done, Safari. Badly done indeed. Shame on you, John Wilander.

@asecondwill
asecondwill commented on May 1, 2020
The workarounds seem to work, but not in webkit view in eg facebook/twitter/instagram webviewer. And clues on what to do would be ace.

@stevenlawrance
stevenlawrance commented on May 4, 2020
From https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/, it appears that a workaround that uses OAuth2 may exist, though it's not exactly clear how to invoke this (and using Secure+HttpOnly cookies isn't sufficient to make it work). I'll have to poke around the WebKit source code..

Option 1: OAuth 2.0 Authorization with which the authenticating domain (in your case, the third-party that expects cookies) forwards an authorization token to your website which you consume and use to establish a first-party login session with a server-set Secure and HttpOnly cookie.

@github-xuser
github-xuser commented on May 19, 2020
I have a workaround based on an interface to sagepay.
We tell sagepay where to return to after CC entry in an iframe, Once the user submits the CC form to sagepay, they redirect the iframe to us and we take over control of the iframe and close it.
Unless its the latest safari. Then the iframe redirect happens, but with no session cookie so our software has no continuity and terminates because it thinks the session has timedout. Not very good when someone is trying to buy something in your shop.
I already implemented a change so that the iframe was created with a page from our domain which then redirects to sagepay, so i know that safari has the correct session cookie in the iframe. This did actually fix quite a lot of the problems but not all.
My thought for fixing them all was that safari doesnt like sending the correct session cookie when sagepay redirects back to our domain, but i wonder what will happen if i make the redirect from sagepay simply do another redirect from us, to us.
It worked, on the second redirect from our domain to our domain the session cookie is correct.
That has to be a bug in safari.
So if i am dom1.com and sagepay is dom2.com the fix is:
Create an iframe with src = dom1.com/redirect1 this simply contains html or javascript to do the correct redirect to your dom2.com page.
Tell dom2.com to return to dom1.com/dummyredirect. dummyredirect copies all the querystring or post data and returns a page that redirects back to dom1.com/theproperreturnaddress.
Its passed all our tests so far.
I hope it helps someone else, I can't see safari getting fixed or even acknowledging the bug anytime soon.

@xabier98
xabier98 commented on May 20, 2020
Hi

Please ¿can you explain or write an small example with your solution?

Thank you

Best Regards

@engelmav
engelmav commented on May 26, 2020
What a fantastic time to put this extra hurdle on struggling and furloughed development teams. Thanks Apple, Safari, and specifically John Wilander!

With brick-and-mortar businesses struggling and software companies doing what they can to help out, NOW was the time to release this huge software-breaking change? Not 2022 like Chrome has roadmapped? Now? During the Covid recession? And with "Storage Access API" still in a poorly-documented and experimental phase? Now?

Badly done, Safari. Badly done indeed. Shame on you, John Wilander.

Fascinating. The economic impact of code changes... should be factored in with behemoth applications and firms like Safari/Apple.

@jhud
jhud commented on May 30, 2020 • 
Hi everyone, commiserations to those of you who also got blindsided by this during all the other Covid-19 IT dramas. Anyway, here is my quick fix for this.

Note that you cannot nest the document.hasStorageAccess, otherwise it misses the user interaction, so I don't bother checking - I run the code every time. I dropped this code inside my iframe. It needs to be triggered from an onClick, ie:

 <div onclick="safariFix();">If you have problems logging in on Safari, please click here.</div>
But instead I call this directly from my login form:

  <input type="submit" onclick="safariFix();" id="login_submit_button" value="{% trans 'Log in' %}" />
The first login fails because Safari pops up a non-blocking "do you want to allow..." popup, but it'll suffice until there's a fix that won't pollute the UI with some "click this if you are on Safari" button.

<script>
  // Safari now suddenly blocks iframe cookie access, so we need to call this during some user interaction
  function safariFix() {
    if (navigator.userAgent.search("Safari") >= 0 && navigator.userAgent.search("Chrome") < 0) {
      document.requestStorageAccess().then(() => {
          // Now we have first-party storage access!
          console.log("Got cookie access for Safari workaround");
          // Let's access some items from the first-party cookie jar
          document.cookie = "foo=bar";              // drop a test cookie
        },  () => { console.log('access denied') }).catch((error) => {
          // error obtaining storage access.
          console.log("Could not get access for Safari workaround: " + error);
        });
      }
  }
</script>
Apologies for the messiness - it's Saturday night and I just need to rush this out now so my customers can start making money again.

@mpirog-hw
mpirog-hw commented on Jun 5, 2020 • 
The economic impact of code changes... should be factored in with behemoth applications and firms like Safari/Apple.

Not just economic, but very real health impact. My company delivers healthcare related information to patients, including COVID-19 content. We act as a third party to health plans and it's an all too common practice for this industry to integrate within iframes.

As it stands, patients using Safari can't access our content due to this security change. Content like ours has been shown to improve health outcomes. If you use Safari you might suffer a worse outcome in the event of a health crisis.

looks like requesting storage access via their APIs is the way to do it

The storage access API in Safari will flat out reject requestStorageAccess() if the client hasn't visited the third-party in first-party context AND has interacted with the site — https://stackoverflow.com/questions/52173595/how-to-debug-safari-itp-2-0-requeststorageaccess-failure

Interestingly, Firefox's implementation doesn't appear to enforce this same requirement, only adding to the confusion.

The majority of our users don't know who we are and have never visited our domain directly. The Storage Access API is clearly designed to accommodate social media network workflows. The rest of us are getting steamrolled.

@lenusch
lenusch commented on Jul 5, 2020
Does it work now? Is there a functional workarround? I didn't get this to work until now :-(

@sarayaz
sarayaz commented on Jul 8, 2020
Does anybody have solution for this in safari 13+ ?

@joostfaassen
joostfaassen commented on Aug 18, 2020
None of these solutions worked for us. And the same issue started showing up in Google Chrome and other browsers (especially in incognito / private modes).

What we did is add an upstream location on the vhost of the site that embeds the other site. I.e. this adds https://mainsite/my-embedded-site/* that forwards requests to https://my-embedded-site/

This way both sites get served to the end user from the main domain (mainsite) making all cookies "first party" cookies.

This solves the problem for us on all combinations of platforms, browsers and incognito vs normal modes.

Additionally, make sure your "secure" and "samesite" cookie options are set correctly, and make sure the cookie names on the main + embedded sites differ (otherwise they keep thrashing eachother's sessions 😄 )

It does require that you control the embedding app's server, so this won't solve the situation for everybody.. but I hope it'll help some people in this thread!

@jhud
jhud commented on Aug 18, 2020
Note that Apple seems to keep closing off iFrame cookies with every Safari update and breaking my workarounds. I gave up and am moving to a JS library. It might be possible to pass cookies with postMessage, but in the end it'll be less screwing around to just do an API integration with the host sites.

@luxio
luxio commented on Aug 20, 2020
@joostfaassen Thank you for sharing your solution.

What we did is add an upstream location on the vhost of the site that embeds the other site. I.e. this adds https://mainsite/my-embedded-site/* that forwards requests to https://my-embedded-site/

Could you share your server configuration to create the upstream location?

@JamesMcMurrin
JamesMcMurrin commented on Aug 20, 2020
I tried a similar script to this, and IE 11 died just from having the document.requestStorageAccess in the script. Never mind that it'll never reach it (or that I put it in a try catch), it throws a syntax error just seeing it.

The first login fails because Safari pops up a non-blocking "do you want to allow..." popup, but it'll suffice until there's a fix that won't pollute the UI with some "click this if you are on Safari" button.
```
<script>
  // Safari now suddenly blocks iframe cookie access, so we need to call this during some user interaction
  function safariFix() {
    if (navigator.userAgent.search("Safari") >= 0 && navigator.userAgent.search("Chrome") < 0) {
      document.requestStorageAccess().then(() => {
          // Now we have first-party storage access!
          console.log("Got cookie access for Safari workaround");
          // Let's access some items from the first-party cookie jar
          document.cookie = "foo=bar";              // drop a test cookie
        },  () => { console.log('access denied') }).catch((error) => {
          // error obtaining storage access.
          console.log("Could not get access for Safari workaround: " + error);
        });
      }
  }
</script>
  ```
@benross
benross commented on Sep 9, 2020
Thanks for the many ideas in this thread!

Wanted to share we've been using a service to get around this issue and so far it has been working well for us: cloudcookie.io. We host content in 3rd party iframes and often don't have access to the parent (host) page. It's a commercial solution so might not be appropriate for all but pretty inexpensive (and has a free tier).

@lenusch
lenusch commented on Sep 10, 2020
Thanks for the many ideas in this thread!

Wanted to share we've been using a service to get around this issue and so far it has been working well for us: cloudcookie.io. We host content in 3rd party iframes and often don't have access to the parent (host) page. It's a commercial solution so might not be appropriate for all but pretty inexpensive (and has a free tier).

Hi, i double checked everything but we have a PHP App and need a Session Cookie and this Javascript "CloudCookie" will not be able to pass Session Cookie to PHP, or am i mistaken? My Mate told me this would be not fit my needs. :-S

@jhud
jhud commented on Sep 10, 2020 • 
I looked at some existing solutions, and big companies which rely on iframes appear to be passing the session tokens through PostMessage between the host page and the iframe.

But I am sick of doing these increasingly ugly hacks. IMO, iframes and 3rd party cookies are dead - Apple has just killed them a year or so earlier.

So I have converted my old iframe integrations to use my existing app REST API + JavaScript + local storage. My customers love this JS client-side integration compared to iframes, and it gives me a unified interface for my apps and web. It's a much more solid solution which will last for the ages.

I know you don't want to hear this if you are looking for a quick fix, but I suggest that you already start planning to ditch iframes + 3rd party cookies in the medium to long term.

@code2infiniteE
code2infiniteE commented on Sep 11, 2020
Thanks for the many ideas in this thread!
Wanted to share we've been using a service to get around this issue and so far it has been working well for us: cloudcookie.io. We host content in 3rd party iframes and often don't have access to the parent (host) page. It's a commercial solution so might not be appropriate for all but pretty inexpensive (and has a free tier).

Hi, i double checked everything but we have a PHP App and need a Session Cookie and this Javascript "CloudCookie" will not be able to pass Session Cookie to PHP, or am i mistaken? My Mate told me this would be not fit my needs. :-S

I also tried cloudcookie.io and have it working on a project. It's a front-end (javascript) cookie framework, so if you need the cookies on the server-side (eg PHP), you just need to add an ajax call or page redirect once you get the cookies from the front-end. (@lenusch)

@Benamin
Benamin commented on Sep 17, 2020 • 
this solution is works; https://github.com/vitr/safari-cookie-in-iframe/blob/master/index-fixed.html

@sparkdoo
sparkdoo commented on Oct 18, 2020
So I have converted my old iframe integrations to use my existing app REST API + JavaScript + local storage. My customers love this JS client-side integration compared to iframes, and it gives me a unified interface for my apps and web. It's a much more solid solution which will last for the ages.

@jhud how are you dealing with the security implications of providing a client side javascript approach vs iframe? We considered both options but found the risk of running our javascript next to potentially malicious javascript too much of a concern to proceed, but of course as you say the new concern is that our existing solution will be completely blocked in the not so distant future

@Tofandel
Tofandel commented on Aug 31, 2021
The joys of tech giants imposing their wishes to everybody because they are trying to block third party tracking, except third party tracking can find tons of workaround other than cookies usually, but for authenticating a user in a secure way you need cookies, so effectively they screw you, force you to use a thousand times less secure approach for the sake of user privacy and don't give you an alternative

Iframes are not just used for third party tracking and sadly they don't understand that.

@jhud
jhud commented on Aug 31, 2021
So I have converted my old iframe integrations to use my existing app REST API + JavaScript + local storage. My customers love this JS client-side integration compared to iframes, and it gives me a unified interface for my apps and web. It's a much more solid solution which will last for the ages.

@jhud how are you dealing with the security implications of providing a client side javascript approach vs iframe? We considered both options but found the risk of running our javascript next to potentially malicious javascript too much of a concern to proceed, but of course as you say the new concern is that our existing solution will be completely blocked in the not so distant future

I trust all the host websites. I would love to have better integration to avoid CSRF/XSS attacks, but it is sufficient for my customers' purposes, and it is the situation the tech vendors have left us in.

The approach is basically to write a Single Page Application. After having done React and Vue.js development since making this decision, it has just cemented my opinion that client-side JS is the way to go for anything other than a basic CRUD website.

@gbenchanoch
gbenchanoch commented on Sep 10, 2021
Thanks for the many ideas in this thread!

Wanted to share we've been using a service to get around this issue and so far it has been working well for us: cloudcookie.io. We host content in 3rd party iframes and often don't have access to the parent (host) page. It's a commercial solution so might not be appropriate for all but pretty inexpensive (and has a free tier).

Are you still using CloudCookie? Has the solution been stable for you across all browsers, as well as mobile? I am having stability issues loading a specific 3rd party provider via iframe, particularly on Safari.

@pini85
pini85 commented on Oct 14, 2021 • 
Thanks for the many ideas in this thread!

Wanted to share we've been using a service to get around this issue and so far it has been working well for us: cloudcookie.io. We host content in 3rd party iframes and often don't have access to the parent (host) page. It's a commercial solution so might not be appropriate for all but pretty inexpensive (and has a free tier).

I would also be interested to know if this is still valid

@code2infiniteE
code2infiniteE commented on Oct 15, 2021
@pini85 && @gbenchanoch yes cloudcookie.io has been working for us so far! :)

