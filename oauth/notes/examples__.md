
##
#
https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts
#
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
#
##


```
Investigate if the redirect_uri is properly validated
Investigate if a state parameter is present and properly validated
Investigate for possible XSS vulnerabilities from reflected OAuth parameters
```

OAuth Entities
The OAuth protocol comprises the following acting entities:

The Resource Owner: The entity that owns the resource. This is typically the user.
The Client: The service requesting access to the resource on behalf of the resource owner.
The Authorization Server: The server that authenticates the resource owner and issues access tokens to the client.
The Resource Server: The server hosting the resources the client requests to access.
Note that these entities are not required to be physically separate. For instance, the authorization and resource servers may be the same system.

Abstract Communication Flow
The communication flow between these entities works as follows:

The client requests authorization from the resource owner.
The client receives an authorization grant from the resource owner.
The client presents the authorization grant to the authorization server.
The client receives an access token from the authorization server.
The client presents the access token to the resource server.
The client receives the resource from the resource server.
Concrete Example
Let's consider the following entities:

Resource owner: The user, who we will name Alice.
Client: An imaginary fitness tracking platform called fittrack.com.
Authorization Server: An imaginary platform for identity management called authserve.com.
Resource Server: For simplicity's sake, this is the same as the authorization server: authserve.com.
Assume that Alice wants to log in to fittrack.com using her authserve.com account. The communication flow may look like this:

Alice clicks "Login with authserve.com" on fittrack.com. She is redirected to the login page of authserve.com.
Alice logs in to authserve.com and consents to giving access to her profile to the third-party service fittrack.com. Afterward, authserve.com issues an authorization grant to fittrack.com.
fittrack.com presents the authorization grant to authserve.com.
authserve.com validates the authorization grant and issues an access token that enables fittrack.com to access Alice's profile.
fittrack.com presents the access token to authserve.com in a request to an API endpoint that accesses Alice's profile information.
authserve.com validates the access token and provides fittrack.com with Alice's profile information.
After the exchange, fittrack.com can access Alice's profile information on authserve.com, i.e., make requests to authserve.com in Alice's name. This is achieved without sharing Alice's credentials with fittrack.com.

OAuth Grant Types
OAuth defines different grants used for different contexts and use cases. We will look at the two most common grant types, the authorization code grant and the implicit grant.

Authorization Code Grant
The authorization code grant is the most common and secure OAuth grant type. This grant type's flow is the same as the abstract flow discussed above.

Step-by-Step Flow:

Authorization Request:

http
Copy code
GET /auth?client_id=1234&redirect_uri=http://fittrack.com/callback&response_type=code&scope=user&state=randomstate HTTP/1.1 
Host: authserve.com
client_id: A unique identifier for the client fittrack.com.
redirect_uri: The URL to which the browser will be redirected after a successful authorization by the resource owner.
response_type: This is always set to code for the authorization code grant.
scope: Indicates what resources the client fittrack.com needs to access.
state: A random nonce generated by the client that serves a similar purpose to a CSRF token tying the authorization request to the following callback request.
Resource Owner Authentication:

The authorization server authserve.com will request the user to log in and authorize the client fittrack.com to access the requested resources.
Authorization Code Grant:

http
Copy code
GET /callback?code=abc123&state=randomstate HTTP/1.1
Host: fittrack.com
code: The authorization code issued by the authorization server.
state: The state value from the authorization request to tie these two requests together.
Access Token Request:

http
Copy code
POST /token HTTP/1.1
Host: authserve.com

client_id=1234&client_secret=SECRET&redirect_uri=http://fittrack.com/callback&grant_type=authorization_code&code=abc123
client_secret: A secret value assigned to the client by the authorization server during the initial registration.
grant_type: This is always set to authorization_code for the authorization code grant.
Access Token Grant:

json
Copy code
{
  "access_token": "token123",
  "expires_in": 3600
}
Resource Request:

http
Copy code
GET /user_info HTTP/1.1
Host: authserve.com
Authorization: Bearer token123
Resource Response:

json
Copy code
{
  "username": "alice",
  "email": "alice@authserve.com",
  "id": 1234
}
Implicit Grant
The implicit code grant is shorter than the authorization code grant as the authorization code exchange is skipped. This results in a more straightforward implementation at the cost of lower security since access tokens are exposed in the browser.

Step-by-Step Flow:

Authorization Request:

http
Copy code
GET /auth?client_id=1234&redirect_uri=http://fittrack.com/callback&response_type=token&scope=user&state=randomstate HTTP/1.1 
Host: authserve.com
The response_type parameter is set to token.
Resource Owner Authentication:

The authorization server authserve.com will request the user to log in and authorize the client fittrack.com to access the requested resources.
Access Token Grant:

http
Copy code
GET /callback#access_token=token123&token_type=Bearer&expires_in=3600&scope=user&state=randomstate HTTP/1.1
Host: fittrack.com
Resource Request:

http
Copy code
GET /user_info HTTP/1.1
Host: authserve.com
Authorization: Bearer token123
Resource Response:

json
Copy code
{
  "username": "alice",
  "email": "alice@authserve.com",
  "id": 1234
}
In both examples, the client fittrack.com can access Alice's profile information on authserve.com without requiring Alice to share her credentials with fittrack.com.




Open Redirect & Chaining Vulnerabilities
As we discussed a couple sections ago, the redirect_uri parameter may be exploited to steal the victim's authorization code. However, this type of vulnerability can easily be prevented by implementing proper whitelist checks on the redirect URL. Typically, this is done by checking the URL's origin consisting of the protocol, host, and port of the URL against a whitelisted value. This way, the client is still able to move the callback endpoint without breaking the entire OAuth flow while preventing an attacker from manipulating the redirect URL to a system under their control. The redirect URL's origin must match the predefined whitelisted value provided by the client.

This may seem perfectly secure, and on its own, it is. However, this drastically changes when the client web application hosed on the whitelisted origin contains an open redirect. While some open redirects can be security vulnerabilities, other open redirects exist by design, for instance, redirect endpoints in social media. However, an open redirect can be exploited by an attacker to steal a victim's OAuth token.

To explore this in more detail, let us assume, the OAuth client academy.edu hosts its callback endpoint at http://academy.edu/callback and implements an open redirect at http://academy.edu/redirect that redirects to any URL provided in the GET parameter url. Furthermore, the authorization server hubgit.edu validates the redirect_uri provided in an authorization request by checking it against the whitelisted origin http://academy.edu/.

Now, an attacker can exploit this scenario to steal a victim's authorization code by sending a manipulated authorization request to the victim with the following redirect URL:

http://things.edu/redirect?u=http://attacker.edu/callback
This URL passes the authorization server's validation. However, after successful authentication by the user, the authorization code is first sent to http://things.edu/redirect, resulting in a redirect to http://attacker.edu/callback. Thus, the attacker obtains the authorization code despite the correctly implemented validation of the redirect_uri parameter. The rest of the exploit works just as described in the section Stealing Access Tokens.

This scenario resulted in a real world bug bounty report disclosed here.

Abusing a Malicious Client
So far, we have assumed the attacker to be a separate actor not present in the OAuth flow. However, typically, authorization servers support OAuth client registration, enabling an attacker to create their own malicious OAuth client under their control. The attacker can then use this client to obtain access tokens from unknowing victims, which may be used in improperly implemented OAuth clients for victim impersonation.

For instance, an attacker could create the web application evil.edu and register it as an OAuth client with hubgit.edu to enable OAuth authentication. If an unknowing victim logs in to evil.edu with their hubgit.edu account using OAuth, the attacker controlled client receives the user's access token to hubgit.edu. The attacker could now try to use this access token to access academy.edu. If the client academy.edu does not verify that the access token was issued for a different client and grants access, the attacker is able to impersonate the victim on academy.edu.

A scenario similar to this was discovered in the real world as described here

##
https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts
##



How the state parameter prevents the attack
The state parameter prevents the attack discussed above. Depending on the implementation, this is typically achieved by a mismatch between the state values in the authorization code grant if the previous authorization request was not initiated by the same user.

For instance, just like before, an attacker might obtain an authorization code for their own account. 
In the authorization request, the attacker can choose an arbitrary value for the state:

```
POST /authorization/signin HTTP/1.1
Host: hubgit.things
Content-Length: 96
Content-Type: application/x-www-form-urlencoded

username=attacker&password=attacker&client_id=0e8f12335b0bf225&redirect_uri=%2Fclient%2Fcallback&state=1337
```



OAuth Vulnerability Prevention
As we have seen, there are multiple ways that improper implementation of the OAuth flow can result in web vulnerabilities. Some of these vulnerabilities result in devastating consequences, including leakage of the entire user session. To prevent these vulnerabilities, all OAuth entities must implement strict security measures. In particular, the authorization server and the client must strictly implement and adhere to all aspects of the OAuth protocol.

OAuth Vulnerability Prevention
Generally, the OAuth standard must be strictly followed to prevent vulnerabilities resulting from faulty implementation. This applies to all OAuth entities. Furthermore, to prevent CSRF vulnerabilities, the state parameter must be enforced by the authorization server and implemented by the client, even though the standard does not strictly require it.

Additionally, the client must prefer the authorization code grant over the implicit grant if possible. Thoroughly validating all OAuth flow requests and responses is essential for preventing common vulnerabilities such as open redirect attacks and token leakage. OAuth authorization servers should carefully validate redirect URIs to ensure they belong to trusted domains and reject requests with suspicious or unauthorized redirect URLs. OAuth clients must securely store access tokens and ensure they are transmitted over secure channels using HTTPS to prevent interception and token theft.

On top of that, general security measures apply to systems responsible for OAuth implementation. That includes regular security audits, penetration testing, and code reviews. These can help identify and mitigate vulnerabilities in OAuth implementations while staying informed about the latest security threats and best practices. Another critical aspect of vulnerability prevention involves implementing robust authentication mechanisms, such as multi-factor authentication (MFA), to add an extra layer of security to the OAuth process. By requiring users to verify their identity through multiple factors such as passwords, biometrics, or one-time codes, MFA significantly reduces the risk of unauthorized access, even if credentials are compromised.

For more details on OAuth securiy best practices, check out this document.