![Untitled 10](https://github.com/babywyrm/sysadmin/assets/55672787/572ac152-4b34-4e82-ad56-26c4ca24c889)


##
#
https://0xw0lf.github.io/hackthebox/2020/08/01/HTB-Oouch/
#
#https://github.com/topavankumarj/Vulnerable-OAuth2.0-Application
#
##

![Untitled 12](https://github.com/babywyrm/sysadmin/assets/55672787/36ed175f-76ec-4ab8-a88a-84e5b79342d4)
![Uploading Untitled 14.png…]()
![Untitled 15](https://github.com/babywyrm/sysadmin/assets/55672787/b138c5e8-f8e4-446a-b825-2a77e225cdf1)





Dhaval Kapil
BLOG ABOUT PROJECTS CONTACT
Attacking the OAuth Protocol
Feb 17, 2017 • Dhaval Kapil

This post is about developing a secure OAuth 2.0 server, the inherent weaknesses of the protocol, and their mitigation.

Introduction
Recently, I had the opportunity to mentor a fellow student at SDSLabs on a project related to the OAuth 2.0 protocol. It was then that I decided to read the official manual for OAuth 2.0. It took me a few hours to go through the entire document and analyze it.

The OAuth 2.0 protocol itself is insecure. The document specifies some security measures that are optional (which boils down to missing for the casual developer). Apart from that, there are additional loopholes as well. Herein, I try to enumerate the various vulnerabilities of the OAuth 2.0 protocol which I found after reading the standard and a couple of online resources. I suggest mitigation to each of these which might be either following the standard strictly or even changing the standard slightly.

This is aimed to benefit both: developers working with OAuth 2.0 as well as security researchers.

Overview
I’ll be assuming that the reader is familiar with the OAuth 2.0 protocol. There are tons of online resources to read up on this. The reader should also be familiar with basic attacks like CSRF, XSS and open redirect. I’ll be mainly focussing on the Authorization code grant and a little on the Implicit grant. As a refresher, these are the steps involved in an Authorization code grant:

The user requests the client to start the authorization process through the user-agent by issuing a GET request. This happens when the user clicks on ‘Connect’/’Sign in with’ button on the client’s website.

The client redirects the user-agent to the authorization server using the following query parameters:
response_type: code
client_id: The id issued to the client.
redirect_uri(optional): The URI where the authorization server will redirect the response to.
scope(optional): The scope to be requested.
state(recommended): An opaque value to maintain state between the request and callback.
After the user authenticates and grants authorization for requested resources, the authorization server redirects the user-agent to the redirect_uri with the following query parameters:
code: The authorization code.
state: The value passed in the above request.
The client further uses the authorization code to request for an access token(with appropriate client authentication) using the following parameters in the request body:
grant_type: authorization_code
code: The authorization code received earlier.
redirect_uri: The redirect_uri passed in the first request.
Attacks
Now, I’m going to talk about various attacks possible by modifying the above-mentioned requests. I’ll be specifying the assumptions in each of the cases separately.

Attacking the ‘Connect’ request
This attack exploits the first request mentioned above, i.e. the request generated when a user clicks ‘Connect’ or ‘Sign in with’ button. Many websites allow users to connect additional accounts like Google, Facebook, Twitter, etc. using OAuth. An attacker can gain access to the victim’s account on the Client by connecting one of his/her own account(on the Provider).

Steps:

The attacker creates a dummy account with some Provider.

The attacker initiates the ‘Connect’ process with the Client using the dummy account on the Provider, but, stops the redirect mentioned in request 3(in the Authorization code grant flow). i.e. The attacker has granted Client access to his/her resources on the Provider but the Client has not yet been notified.

The attacker creates a malicious webpage simulating the following steps:
Logging out the user on Provider(using CSRF).
Logging in the user on Provider with the credentials of his/her dummy account(using CSRF).
Spoofing the 1st request to connect the Provider account with Client. This can be easily done, as it is just another GET request. It is preferred to do this within an iframe so that the victim is unaware of this.
When the victim visits the attacker’s page, he/she is logged out of Provider and then gets signed in as the dummy account. The ‘Connect’ request is then issued which results in the attacker’s dummy account to be connected with the victim’s account on Client. Note that the victim will not be asked for granting access to the client as the attacker has already approved it in Step 2.

Now, the attacker can log in to the victim’s account on Client by signing in with the dummy account on Provider.
Mitigation

Although the vulnerability exists on the Provider itself(allowing CSRF log in and log out), it is even better to protect the ‘Connect’ page from allowing requests that do not originate from the user. This can be ensured by using a csrf_token within the client to protect the 1st request. The OAuth 2.0 standard should specify this.

Attacking ‘redirect_uri’
Presently, to prevent attackers using arbitrary redirect_uri, many OAuth servers partially match this parameter with a redirect_uri prespecified during client registration. Generally, during registration, the client specifies the domain and only those redirect_uri on that particular domain are allowed. This becomes dangerous when an attacker is able to find a page vulnerable, to say XSS, on the client’s domain. The attacker can subsequently steal authorization_code.

Steps:

The attacker is able to leak data(say through XSS) from a page on the client’s domain: https://client.com/vuln.

The attacker injects Javascript code(if XSS) on that page that sends the URL loaded in the browser(with parameters as well as fragments) to the attacker.

The attacker creates a webpage that forces the user to visit a malicious link such as: https://provider.com/oauth/authorize?client_id=CLIENT_ID&response_type=code&redirect_uri=https%3A%2F%2Fclient.com%2Fvuln

When the victim loads this link, the user-agent is redirected to https://client.com/vuln?code=CODE. This CODE is then sent to the attacker.

The attacker can use this code at his/her end to issue an access token by passing it to the authentic redirect_uri such as https://client.com/oauth/callback?code=CODE.

This attack is even more dangerous if the authorization server supports the Implicit grant. By passing response_type=token, the attacker can steal the token directly.

Mitigation

To prevent the attack for Authorization code grant, OAuth already specifies the following in the standard for an access token request:

The authorization server MUST:

ensure that the “redirect_uri” parameter is present if the “redirect_uri” parameter was included in the initial authorization request as described in Section 4.1.1, and if included ensure that their values are identical.
With this, the attacker will be unable to perform Step 5. The client will request for an access token with authentication_code and authentic redirect_uri which will not match with https://client.com/vuln. Hence, the authorization server will not grant an access token. However, developers rarely take this into consideration. Individually, this does not represent any real threat, but with other vulnerabilities(as mentioned above), this can lead to leaking of access tokens. Note that, this will not prevent attacking authorization servers using Implicit grant.

Another protective measure, which in my opinion is more secure and handles both the above cases is that the authorization server should whitelist a list of redirect_uri. Also, while sanitizing this parameter, exact matches should be made instead of partial matches. Usually, clients have predefined redirect_uri and they rarely need to change them.

CSRF on Authorization response
By performing a Cross Site Request Forgery attack, an attacker can link a dummy account on Provider with victim’s account on Client(as mentioned in the first attack). This attack uses the 3rd request of the Authorization code grant.

Steps:

The attacker creates a dummy account on Provider.

The attacker initiates the ‘Connect’ process with the Client using the dummy account on the Provider, but, stops the redirect mentioned in request 3(in the Authorization code grant flow). i.e. The attacker has granted Client access to his/her resources on the Provider but the Client has not yet been notified. The attacker saves the authorization_code.

The attacker forces the victim to make a request to: https://client.com/<provider>/login?code=AUTH_CODE. This can be easily done by making the victim opening a malicious webpage with any img or script tag with the above URL as src.

If the victim is logged in Client, the attacker’s dummy account is now connected to his/her account.

Now, the attacker can log in to the victim’s account on Client by signing in with the dummy account on Provider.

Mitigation

OAuth 2.0 provides security against such attacks through the state parameter passed in the 2nd and 3rd request. It acts like a CSRF token. The attacker cannot forge a malicious URL without knowing the state which is user session specific. However, in the current implementation of OAuth, this parameter is NOT required and is optional. Developers not well versed with security are susceptible to ignore this.

OAuth 2.0 should force clients to send a state parameter and handle requests that are missing this parameter as ‘error requests’. Proper guidelines should also be given for generating and handling csrf tokens.

Note: Using the state parameter does not prevent the first attack mentioned above(Attacking the ‘Connect’ request).

Reusing an access token - One access_token to rule them all
OAuth 2.0 considers access_token to be independent of any client. All it ensures is that an access_token stored on the authorization server is mapped to appropriate scopes and expiration time. An access token generated for client1 can be used for client2 as well. This poses a danger to clients using the Implicit grant.

Steps:

The attacker creates an authentic client application client1 and registers it with a Provider.

The attacker somehow manages to get the victim use client1. Thereby, he/she has access to the access token of the victim on client1.

Assume that the victim uses client2 which further uses the Implicit grant. In Implicit grant, the authorization server redirects the user-agent to a URL such as: https://client2.com/callback#access_token=ACCESS_TOKEN. The attacker visits this URL with the access_token of the client.

client2 authenticates the attacker as the victim. Hence, a single access token can be used on many different clients that use Implicit grant.

Mitigation

Clients must ensure that the access token being used was indeed issued by them. Some OAuth server like Facebook, provide endpoints to get the __ a particular access_token was issued to: https://graph.facebook.com/app?fields=id&access_token=ACCESS_TOKEN.

Open Redirect in OAuth 2.0
The OAuth 2.0 standard specifies the following guidelines for handling errors in Authorization requests:

If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.

If the resource owner denies the access request or if the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs the client by adding the following parameters to the query component of the redirection URI using the “application/x-www-form-urlencoded” format, per Appendix B:

Some OAuth servers, misinterpret this and interchange the order of the two checks. That is, if the request fails for reasons other than redirection URI, such as invalid scope, the server informs the client by redirecting it to the URL passed by the client without validating it. This makes the OAuth server to serve as an open redirector. A possible URL crafted by the attacker can be https://provider.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&scope=INVALID_SCOPE&redirect_uri=http://attacker.com/.

This vulnerability was once present in Facebook, Microsoft, and Google.

Mitigation

The mitigation is trivial: the authorization server should first validate the redirect_uri parameter and continue accordingly.

Conclusion
In short, while developing an OAuth server, security should be kept in mind. Knowledge about various attack vectors is necessary. The OAuth specification should be updated to enforce the appropriate security measures mentioned above. Oauth by Sakurity is a great improvement over OAuth 2.0.

This list is not complete. If you know of any other attacks or even better ways to mitigate the above-mentioned attacks feel free to comment!

Find me on Github and Twitter



Github logo Twitter logo Linkedin logo Email logo Google+ logo Keybase logo RSS logo
SITEMAP | CONTACT | DISCLAIMER

© 2018 Dhaval Kapil. All rights reserved
