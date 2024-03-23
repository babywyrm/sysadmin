XSS in express-useragent through HTTP User-Agent

##
#
https://hackerone.com/reports/362702
#
##

Share:
TIMELINE
b9b86c2fc8409c628fb3de6 submitted a report to Node.js third-party modules.
June 6, 2018, 11:28am UTC
Hello,
I would like to report an XSS in express-useragent module due a lack of validating User-Agent header. Please note I already created an Github issue and asked for CVE ( CVE-2018-9863). I did not know about Node.js third-party modules on hackerone.
Description
express-useragent is simple NodeJS/ExpressJS middleware exposing User-Agent details to your application and views. Basically it parses User-Agent and return it in structured JSON format.
The issue
while parsing User-Agent there are no escaping or sanitization mechanism. User-Agent header is controlled by the user. An attacker can craft a malicious script and inject it through the HTTP header.
Steps to reproduce
```
git clone https://github.com/biggora/express-useragent
cd express-useragent
node test/http.js (an HTTP server should listen on 3000 tcp)
curl "http://localhost:3000" -H 'User-Agent: <script>alert("XSS")</script>' > poc.html
```

open poc.html with your favorite web browser
you should see an alertbox popup
Proof of concept (screenshots)
Image F305913: Screenshot_from_2018-04-09_18-50-35_(1).png 15.90 KiB
Zoom in Zoom out Copy Download


Image F305914: Screenshot_from_2018-04-09_18-51-21_(1).png 48.36 KiB
Zoom in Zoom out Copy Download

Proof of concept with a fix (video) express_useragent_xss.mkv (F305912)
Mitigation
Correctly escape and sanitize user input ( HTTP User-Agent ). Please note I proposed a fix in the video
Impact
An attacker could execute javascript code that could lead to XSS.
3 attachments:
F305912: express_useragent_xss.mkv
F305913: Screenshot_from_2018-04-09_18-50-35_(1).png
F305914: Screenshot_from_2018-04-09_18-51-21_(1).png
Show older activities
ba3142c38d7de2241d2c522
 
posted a comment. 
June 17, 2018, 3:38pm UTC
I agree with @lirantal.
b9b86c2fc8409c628fb3de6
 
posted a comment. 
June 17, 2018, 6:02pm UTC
Hi,
Sorry for the slow response. I agree with @lirantal:
Code 171 BytesUnwrap lines Copy Download
IMO it will be the responsibility of the user using this middleware to understand which context it is used and escape it properly (it can be JSON, markdown, HTML, JS, etc)
Bur here is the catch, I think that @bougakovgeorge should at least escape greater/less sign <> from the user agent value. By removing <> most if not all XSS vectors that require <> won't work.
Here is a list of some user agents:
Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0
Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0
Mozilla/5.0 (TV; rv:44.0) Gecko/44.0 Firefox/44.0
As you can see on the above list none of the user agent contains *<> *, we could use a white list of allowed characters to minimize XSS injection. I would like to suggest to update provided examples on github showing a secure way on how to implement the middleware for both client/server side.
Server side:
As we know the middleware returns a JSON so we should set this HTTP HEADER Content-Type: application/json to prevent an XSS to be executed in modern web browsers.
Client side:
Here, its more complicated because it really depends on how the developer will use the return valued. Its more about which context the value will be reflected but in any case the user should sanitize the returned value before outputting/reflecting it.
If you need more information let me know,
@ibrahimd
ba3142c38d7de2241d2c522
 
posted a comment. 
June 17, 2018, 8:58pm UTC
You must be mistaken. I am NOT the maintainer of the library, I just responded to your issue. @biggora (https://github.com/biggora) is the maintainer.
b9b86c2fc8409c628fb3de6
 
posted a comment. 
June 17, 2018, 9:06pm UTC
Hi @bougakovgeorge, my apologies, I thought you were the maintainer, because @lirantal said that he will invite the package maintainer.
lirantal
 
posted a comment. 
June 17, 2018, 9:13pm UTC
@bougakovgeorge I have also invited Alexy but unfortunately he hasn't yet joined this issue. If you're able to ping him we'll appreciate it.
@ibrahimd updating the examples is ok. About blacklisting the < > it's again up to the maintainer's since one can argue that it is a free text field (there's nothing that forbids those chars as far as I know).
lirantal
 
changed the scope from useragent to express-useragent. 
June 29, 2018, 9:51pm UTC
lirantal
 
posted a comment. 
June 29, 2018, 9:53pm UTC
@ibrahimd I tried inviting the author again.
If there will be no sign from him on this report during next week I will proceed with closing this report as informative.
If you're able to help contact him and ask him to join this conversation I will greatly appreciate it so we can check with him about adding security disclosures in the README and updating the examples.
b9b86c2fc8409c628fb3de6
 
posted a comment. 
June 30, 2018, 12pm UTC
@lirantal thanks for the update.
I'm a little bit disappointed with the idea if we can't get the module author to participate to this thread during the next week, you will close the report as informative. I work hard to report only valid bugs to rise my hackerone's signal and reputation.
In the end I will gladly accept your final decision.
I'll send him a PR, he seems to be responsive to pull requests, in the description section I'll explain our situation here.
lirantal
 
posted a comment. 
June 30, 2018, 3:01pm UTC
@ibrahimd I will follow-up and do my best to get him on the conversation. I saw already that you opened the issue in their repository and there wasn't any response from the author, only from a contributor who isn't stepping in to fill the gap so we'd need the module maintainer for this.
Will definitely appreciate if you can also ping him and get him to join this conversation.
ba3142c38d7de2241d2c522
 
posted a comment. 
June 30, 2018, 10:06pm UTC
I would totally help you fix it, I just can’t imagine and/or replicate the issue with just a browser.
b9b86c2fc8409c628fb3de6
 
posted a comment. 
July 1, 2018, 11:19am UTC
@bougakovgeorge reproduction steps using a browser:
install User-Agent Switcher - chrome extension
create a new user-agent
name your new user-agent whatever you want
Image F314226: User-Agent_switcher-new_user-agent.PNG 95.44 KiB
Zoom in Zoom out Copy Download

set user-agent value to: <script>alert(0)</script>
Image F314226: User-Agent_switcher-new_user-agent.PNG 95.44 KiB
Zoom in Zoom out Copy Download

select the new user agent
start one of the test examples: node test/express.js
browse: http://localhost:3000 using chrome
the XSS value will be reflected but not triggered due the fact its reflected inside JSON context.
From here we know that the user agent is not sanitized, let's edit one of the examples (express.js) simulating a scenario of developer who want to display the user agent of the visitor:
edit test/express.js:
Code 99 BytesUnwrap lines Copy Download
...
app.get('/', function (req, res) {
    res.send("User-Agent: " + req.useragent.source);
});
...
save changes and run again the server: node express.js
visit http://localhost:3000 using chrome (make sure user-agent switch is on and using custom payload)
XSS window should pop up.
Image F314225: User-agent_XSS-popup.PNG 32.39 KiB
Zoom in Zoom out Copy Download

@lirantal I am sure you're doing your best, I'll do my best as well. If you need anything else please let me know.
2 attachments:
F314225: User-agent_XSS-popup.PNG
F314226: User-Agent_switcher-new_user-agent.PNG
ba3142c38d7de2241d2c522
 
posted a comment. 
July 1, 2018, 11:53am UTC
You can switch your UA without any extensions, but only an idiot will switch his user agent to ‘<script>maliciouscode();</script>’ and visit a JSON page. Also, if a web developer needs to see what browser user uses, they can see the UA string using ‘window.navigator.useragent’ which is perfectly safe.
Also, AFAIK HTTP protocol specification does not forbid <> characters and escaping and/or them will be a violation of specification.
lirantal
 
posted a comment. 
July 1, 2018, 4:23pm UTC
@bougakovgeorge Let's try to keep it civilized and respectful. We all have good intentions.
Regardless to a fix or not, do you agree to add a disclaimer in the README ?
ba3142c38d7de2241d2c522
 
posted a comment. 
July 1, 2018, 6pm UTC
I also have good intentions, and a disclaimer can be nice, but I just can’t imagine a real scenario where this exploit can be used and executed. I also think that if you patch this library to escape these symbols, you need to make it an option and don’t force it. Also, I don’t think that this module is still maintained and [I repeat] I am not the maintainer or a contributor of this module. I just wanted to use it in my service, implemented it and wanted to open an issue and a pull request to add macOS Mojave support and I just saw your issue and expressed my opinion. Sorry for any misunderstanding caused.
Side note: Is your main goal “to rise my (ibrahimd’s) hackerone's signal and reputation.”? It’s kinda strange...
lirantal
 
posted a comment. 
July 1, 2018, 7pm UTC
@bougakovgeorge I appreciate your involvement in the conversation, though I don't like that insinuation in that side note. Maybe you need to read my comment https://hackerone.com/reports/362702#activity-2894646 again.
Thank you for your contribution in triaging the security report.
ba3142c38d7de2241d2c522
 
posted a comment. 
July 1, 2018, 8:32pm UTC
I didn’t mean to insult anyone, but Ibrahim wrote the exact thing I included in the side note. Is there any way I can leave this conversation because I am totally the wrong guy to be here. I am not a maintainer, I don’t even have write access to the repo, so can you please exclude me from this mailing list?
lirantal
 
posted a comment. 
July 1, 2018, 9:26pm UTC
Sure, I'll go ahead and remove you from the thread.
Thanks for joining in the first place and willing to help!
lirantal
 
removed ba3142c38d7de2241d2c522 as a participant. 
July 1, 2018, 9:26pm UTC
b9b86c2fc8409c628fb3de6
 
posted a comment. 
July 6, 2018, 8:22am UTC
@lirantal as you could noticed, four days ago I tried to reach out the owner of the module on twitter, no response yet. This morning I sent him a message on facebook waiting for a feedback. I think that's the best I can do in this situation.
lirantal
 
posted a comment. 
July 6, 2018, 10:16am UTC
Agree.
Should we go ahead and resolve this report as informative and disclose it?
b9b86c2fc8409c628fb3de6
 
posted a comment. 
July 6, 2018, 10:33am UTC
Yes, go ahead.
lirantal
 
closed the report and changed the status to Informative. 
July 6, 2018, 10:37am UTC
Closing report.
lirantal
 
requested to disclose this report. 
July 6, 2018, 10:37am UTC
b9b86c2fc8409c628fb3de6
 
agreed to disclose this report. 
