# Table of Contents

##
#
https://github.com/Kennyslaboratory/OAuth2-Security-Cheatsheet/blob/main/README.md
#
##


 * [OAuth2 Security Cheat Sheet](#Table-of-Contents)
  * [Overview](#Overview)
    * [Key Frameworks](#Key-Frameworks)
    * [Main Components](#Main-Components)
    * [Auth Flow Types](#Auth-Flow-Fypes)
    * [GET Request Parameters](#GET-Request-Parameters)
    * [POST Request Parameters](#POST-Request-Parameters)
    * [Token Types](#Token-Types)
    * [Misc. Token Types](#Misc.-Token-Types)
    * [Client Types](#Client-Types)
  * [Common OAuth2 Vulnerabilities](#Common-OAuth2-Vulnerabilities)
  * [Planning your Server Architecture](#Planning-your-Server-Architecture)
    * [What Authroization Grant Type Should I Use?](#What-Authroization-Grant-Type-Should-I-Use?)
    * [Where should I store my Access/Refresh Tokens?](#Where-should-I-store-my-Access/Refresh-Tokens?)
      * [Avoid putting tokens in local/session storage](#Avoid-putting-tokens-in-local/session-storage)
    * [When should I use Handle-Based Tokens?](#When-should-I-use-Handle-Based-Tokens?)
  * [Securing Client Credentials](#Securing-Client-Credentials)
    * [Generate client_secret using strong cryptography - _(client & auth server)_](#generate-client_secret-using-strong-cryptography---client--auth-server)
    * [Implement rate limiting on the exchange/token server endpoint - _(auth server)_](#implement-rate-limiting-on-the-exchangetoken-server-endpoint---auth-server)
    * [Use a Cryptographic hashing algorithm that is appropriate for storing client_secrets - _(auth server)_](#use-a-cryptographic-hashing-algorithm-that-is-appropriate-for-storing-client_secrets---auth-server)
    * [Store the client_secret securely on the client - _(client)_](#store-handle-based-access-and-refresh-tokens-securely---client)
  * [Securing Tokens](#securing-tokens)
    * [Store handle-based access and refresh tokens securely - _(auth server)_](#store-handle-based-access-and-refresh-tokens-securely---auth-server)
    * [Expire access and refresh tokens propmptly - _(auth server)_](#expire-access-and-refresh-tokens-propmptly---auth-server)
    * [Store handle-based access and refresh tokens securely - _(Client)_](#implement-rate-limiting-on-the-exchangetoken-server-endpoint---auth-server)
  * [Securing your Users](#securing-your-users)
    * [Implement the `state` parameter - _(client)_](#implement-the-state-parameter---client)
    * [Expire Authorization Codes - _(auth server)_](#expire-authorization-codes---auth-server)
    * [Invalidate authorization codes after use - _(auth sever)_](#invalidate-authorization-codes-after-use---auth-sever)
    * [Generate strong authorization codes - _(auth server)_](#generate-strong-authorization-codes---auth-server)
    * [Bind client to authorization code - _(auth server)_](#bind-client-to-authorization-code---auth-server)
    * [Strictly Validate the redirect URI - _(auth server)_](#strictly-validate-the-redirect-uri---auth-server)
    * [Hash authorization codes - _(auth server)_](#hash-authorization-codes---auth-server)
  * [PKCE](#pkce)
    * [How PKCE Works](#how-pkce-works)
    
    
# Overview
OAuth2 is not a program, service, or coding library.  OAuth2 is simply a framework/standard that was created by the Internet Engineering Task Force to give websites *limited* access to their data/services to other third-party websites using a decenteralized Authorization Server.  

### Key Frameworks
OAuth2 is used for Authorization, not Authentication/Identity.  However, using an extension call OpenID Connect, we can use OAuth2 for Authentication.
| Frameworks | Description |
| --- | --- |
| [OAuth2](https://tools.ietf.org/html/rfc6749) | Authorization framework that enables a third-party application to obtain limited, short-term access to an HTTP service. |
| [OpenID Connect](https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1) | Works ontop of OAuth2, this adds an Identity Layer to the framework.  "Sign In with Google" |

### Main Components
There's typically 5 different actors in the OAuth2 flow:
| Components | Description |
| --- | --- |
| `User` | The subject that is attempting to access a protected resource.  You, me, or some API. |
| `User Agent` | The local software that the User is interfacing with in order to communicate with the client. This can be a phone app or your web browser. |
| `Client` | This is the server application _(Web App)_ that runs the OAuth2 logic.  No data or protected resources are located here. |
| `Auth Server` | The server that is used to authenticate the User.  Tokens are exchanged here for access to protected resources. |
| `Resource Server` | Server hosting the protected resources. This is the API you want to access. |

![](auth-code-flow.png)

### Auth Flow Types
There are *4 types* of ways to use OAuth2, however, nearly 100% of cases the application is going to us the "Authorization Code Grant" for OpenID Connect:
| Flow Types | Description |
| --- | --- |
| [Implicit Grant]() | No Auth Code, instead the Client obtains the Access Token directly and no Auth Code is created or exchanged. |
| [Authorization Code Grant]() | **Most Common.** The Client obtains an Authorization Code that the Client can exchange for an Access Token after the User logs in at the Authorization Server. |
| [Resource Owner Password Credentials Grant]() | Basically the Client enters in your Username and Password and signs into the server on your behalf. |
| [Client Credentials Grant]() | The Client is given master credentials that it can use to obtain Access Tokens. |

#### GET Request Parameters
| Parameter | Description |
| --- | --- |
| `response_type` | Specifies what type of Authorization Flow is being used. |
| `client_id` | This is used by the Auth Server to Identify the client. |
| `redirect_uri` | Specifies where to redirect the User-Agent. |
| `scope` _(optional)_ | Declare what resources/permission you want from the Identity Provider. |
| `state` _(recommended)_ | If not using PKCE to prevent CSRF attack then the state parameter is necessary to protect user accounts fro hijacking via CSRF. |

#### POST Request Parameters
| Parameter | Description |
| --- | --- |
| `Host` | authorization-endpoint.com |
| `grant_type` | Specifies the type of Auth Flow you are using.  I.E. `code` |
| `code` | This is where the Auth Code is after logging into the Auth Server / Identity Provider. |


### Token Types
| Token Types | Description |
| --- | --- |
| [Bearer Tokens]() | An unsigned token that is used by OAuth2.  It's located in the Authorization Header of HTTP Requests and is also considered a predominate access token.  |
| [Access Tokens]() | A short-lived token that grants access to a protected resource.  Normally exchanged with an Authorization Code.  Access Tokens are also encrypted strings that contain user information. |
| [Refresh Tokens]() | A seperate token that is used to renew an expired Access Token. |
| [Identity Tokens]() | A Self-Contained, JSON Web Token used by OpenID Connect for account login purposes. |

**Tip:** Think of Access Tokens like a session that is created once you authenticate to a website. As long as that session is valid, we can interact with that website without needing to login again. Once the session times out, we would need to login again with our username and password. Refresh tokens are like that password, as they allow a Client to create a new session.

### Misc. Token Types
| Token Types | Description |
| --- | --- |
| [Handle-Based Tokens]() | *Reference tokens* that are typically random strings used to retrieve the data associated with that token. Similar to passing a reference to a variable in a programming language. |
| [Self-Contained Tokens]() | *Contain all the data* associated with that token. This is similar to passing a variable by value in a programming language. This is typically expressed as a JWT. |

#### Note: 
  * Refresh tokens are handle-based.
  * Access tokens can be either, handle-based or self-contained.
  * Identity tokens (OpenID/Connect) are self-contained. *(JWTs)*
  
### Client Types
| Clients | Description |
| --- | --- |
| [Public Client]() | A client that is located on the same device as the User-Agent.  This client should not be used to store client secrets because it can't be secured. This category includes mobile applications, single page applications, and desktop clients as an attacker is able to extract the secrets by downloading those applications. |
| [Confidential Client]() | A Web Application that is located on a server seperate to the User-Agent. |

# Common OAuth2 Vulnerabilities
| Attack | Description |
| --- | --- |
| [Classic CSRF Attack]() | Using a CSRF Attack to forward a User to the Auth Server, having them obtain an Auth Code, then having them use it to pair the attacker's IdP Account with their client account. |
| [Pseudo-Auth CSRF Attack](https://security.stackexchange.com/questions/20187/oauth2-cross-site-request-forgery-and-state-parameter) | If OAuth2 is being used as a pseudo-authentication protocol to login, then it is possible to obtain access to a user account by linking your account with their's via CSRF Attack. |
| [Stealing client_secret]() | If the client_secret is embedded in the same local device as the User-Agent then it may be possible to steal the client_secret used to verify the Client with the Auth Server. |
| [Open Redirect]() | Stealing the Authorization Code by hijacking the redirect_url parameter and redirecting the final GET Response to an attacker's server. |
| [Reusable Authorization Codes]() | Authorization Codes should only be able to be used once.  Once used, they should be invalidated. |
| [Weak state parameter]() | The state parameter has weak entropy if is perdictable and not cryptographically secure, for example, [computing the state parameter with NTP](https://crypto.stackexchange.com/questions/18207/is-it-safe-to-seed-a-random-number-generator-from-system-time). |
| [Unchecked state parameter]() | The client does not check or validate the state parameter before submitting the Auth Code for an Access Token. | 
| [state Fixation]() | Very rare but this issue arises in broken OAuth2 libraries from Identity Providers.  If the application allows a user-provided state to initialize the OAuth flow then the state parameter can be broken and CSRF may still be possible. |

# Planning your Server Architecture:
#### What Authroization Grant Type Should I Use?

As a general rule of thumb, if you are developing a standard Web Application or Native Mobile Application then you should be using the Authorization Code Grant.  The Implicit Grant was generally how we used to do things before CORS support was widely available but I rarely if ever see a use for the Implicit Grant Type now.
**Example:**
 * If you're building a classic web application: Use the Authorization Code Grant.
 * If you're building a single page application: Use the Authorization Code Grant **without secrets**.
   * Read more about developing OAuth2 Flow for Single Page Apps, [here](https://www.oauth.com/oauth2-servers/single-page-apps/#:~:text=The%20only%20way%20the%20authorization,using%20a%20registered%20redirect%20URL.).
 * If you are building a native mobile application: Use the Authorization Code Grant with [PKCE](https://medium.com/identity-beyond-borders/what-the-heck-is-pkce-40662e801a76).
 * If your client is 100% internal and is authenticating with trusted APIs and not unknown users, then it's probably *absolutely trusted*.  In this can you can use user credentials (i.e. the Facebook app accessing Facebook Auth): In this case, Use the Resource Owner Password Grant.
 * If your client is the sole owner of the data, and there is no user login: Use the Client Credentials Grant.

#### Where should I store my Access/Refresh Tokens?

Design your application so that it can store the Refresh Tokens securely on a server. However, if you are developing a completely RESTful application then this may not be an option for you.  If you do not trust that the client can store tokens securely *(single-page web applications, etc)*, then do **not** issue Refresh Tokens. An attacker with access to long-lived Refresh Tokens and a client_secret will be able to obtain new Access Tokens and use those Access tokens to access the resources of other users. The main downside of not using Refresh Tokens is that users/clients would need to re-authenticate every time the Access Token expires.
##### Avoid putting tokens in local/session storage:

Access tokens and esspecially refresh tokens should **never** be stored in the local/session storage, because then they can be stolen via Cross-Site Scripting attacks or other attacks that can read local/session storage.  Remember, this area of storage is meant to be public and accessable to the User-Agent. If your client is not being hosted on the same device as the User-Agent then it would be best practice to store the access token in a cookie with [cookie prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) enabled.  At the bare minimun the cookie should use the HttpOnly, Secure, and SameSite cookie prefixes.

#### When should I use Handle-Based Tokens?
Handle-Based Tokens are references to tokens  To increase maintainability, use self-contained tokens from within your network on systems you control, but use handle-based tokens outside of the network. The main reason is that Access Tokens are meant to be consumed by the API itself, not by the Client. If we share self-contained tokens with Clients, they might consume these tokens in ways that we had not intended. Changing the content (or structure) of our self-contained tokens might thus break lots of Client applications in unforeseen ways when communicating with APIs.

If the Client application requires access to data that is in the self-contained token, offer an API that enables Client applications to obtain information related to that Access Token. If we want to use self-contained tokens and prevent clients from accessing the contents, encrypt those tokens.

# Securing Client Credentials
Clients need a `client_id` and a `client_secret` to verify itself with an Identity Provider.  The `client_id` is public but the `client_secret` needs to be secured and stored in a confidential location, like on a server.  It goes both ways however, if the Auth Server itself is compromised, then certain security measures should be implemented to protect the database of valid client credentials.

#### Generate client_secret using strong cryptography - _(client & auth server)_
If the client secrets are weak, an attacker may be able to guess them at the token endpoint.

To remediate this, generate secrets with a length of at least 128 bit using a secure pseudo-random number generator that is seeded properly. Most mature OAuth 2.0 frameworks implement this correctly so if you are using a popular library from a trusted provider, then you should be okay when using the library/framework to generate the client_secret.

#### Implement rate limiting on the exchange/token server endpoint - _(auth server)_
To prevent bruteforcing, OAuth2 endpoints should implement rate limiting to slow down attackers.  For example, if someone is trying to bruteforce a state parameter or the client credentials.


#### Use a Cryptographic hashing algorithm that is appropriate for storing client_secrets - _(auth server)_
If the client secrets are stored as plain text, an attacker may be able to obtain them from the database at the resource server or the token endpoint.

To remediate this, store the client secrets like you would store user passwords: hashed with a strong hashing algorithm such as Argon2id, bcrypt, scrypt, or pbkdf2. If you're having trouble deciding which hashing algorithm to use, then check out [this post](https://medium.com/analytics-vidhya/password-hashing-pbkdf2-scrypt-bcrypt-and-argon2-e25aaf41598e) on hashing algorithms. When validating the secret, hash the incoming secret and compare it against the one stored in the database for that client.

#### Store the client_secret securely on the client - _(client)_
An attacker may be able to extract secrets from client if they have access to it's logic on local storage or through a code repository.

Always store the secrets using secure storage offered by your technology stack (typically encrypted) and keep these secrets out of version repositories.

**Important:** public clients should NOT have secrets.  This includes clients embedded into mobile phone applications and single page applications.  Either don't use a `client_secret` at all in this case or use a service like AWS Lambda to handle OAuth2 Authorization Code-to-Token Exchanges.

# Securing Tokens

### Store handle-based access and refresh tokens securely - _(auth server)_
If the handle-based tokens are stored as plain text, an attacker may be able to obtain them from the database at the resource server or the token endpoint.

To remediate this, hash the tokens before storing them using a strong hashing algorithm. When validating the token, hash the incoming token and validate whether that hashed value exists in the database.

Hash tokens with a hashing algorithm.  Access Tokens are generally supposed to be shortlived, and a dictionary attack is likely not going be able to crack a hashed token that is of random string length.  Therefore, you can opt for a faster hashing algorithm instead of using the same ones we use to store passwords like Argon2, bscrypt, or scrypt.  SHA256 should be sufficient depending on your risk profile.


### Expire access and refresh tokens propmptly - _(auth server)_
Expiring access and refresh tokens limits the window in which an attacker can use captured or guessed tokens.

To remediate this, expire access tokens 15-30 minutes after they have been generated. Refresh tokens can be valid for much longer. The actual amount depends on the risk profile of the application. Anything between a couple of hours or a year might be acceptable.

### Store handle-based access and refresh tokens securely - _(Client)_
If the handle-based tokens are stored as plain text in a database, an attacker may be able to obtain them from the database at the client.

To remediate this, keep the access tokens in memory and store the refresh tokens using secure storage offered by your technology stack (typically encrypted).

# Securing your Users
The most common way that OAuth2 can be used by hackers to steal your users' account logins and data is through Authorization Code Theft bia CSRF Attacks and Open Redirects.  Both are fairly easy to prevent but very often the protections are not implemented properly.

### Implement the `state` parameter - _(client)_
An attacker will be able to associate his/her OAuth 2.0 identity with another user's account registered on your client application if the client does not use the state parameter.  They do this by using a common CSRF Bug in the OAuth2 framework.

The `state` parameter is recommended and it should be used. The client application should generate a secure random string, store the secure random string in the user's session, and send it to the authorization server using the 'state' parameter via the the user's browser. The authorization server will send this parameter back after the authorization request via the user's browser. The client application should then validate whether the value stored in the requesting user's session matches the received value.

You must validate this `state` parameter on the client before exchanging an authorization code for an access token, otherwise simply including a `state` and not checking it will defeat the purpose.

### Expire Authorization Codes - _(auth server)_
Attackers that steal or brute force unused authorization codes will be able to use them regardless of how long ago they were issued.  This won't prevent CSRF Attacks and is not a subsitute for the `state` parameter.  A professional attack can use AJAX to renew the Authorization Code in on their malicious page periodically.

To mitigate a bruteforce of Authorization Codes, expire authorization codes after 10-15 minutes if they have not been used.

Although this attack is very impractical if you're already throttling Access Token requests and secure your `client_secret` properly. It is still best practice to expire the Authorization Codes in a healthy time window.

### Invalidate authorization codes after use - _(auth sever)_
Attackers can reuse authorization codes when intercepted. Clients exchange authorization codes together with a client ID and `client_secret` for access tokens. These access tokens then grant the client access to the victim's resources. Attackers can also do this if the client does not use a `client_secret` (e.g. public client) or if the `client_secret` is compromised as an attacker can obtain access tokens with the intercepted authorization code(s).

When an authorization code is exchanged for an access code, the authorization server should invalidate the authorization code and not issue any more access codes against it.

### Generate strong authorization codes - _(auth server)_
An attacker may be able to guess the authorization code if they have weak entrophy when created.

Generate authorization codes with a length of at least `128 bits` using a cryptographically secure pseudo-random number generator (CSPRNG) that is seeded properly with a True Random Number Generator.  This may seem difficult but just about all technology stacks will have this functionality built-in, read their documentation for guidance on using CSPRNGs.

### Bind client to authorization code - _(auth server)_
An attacker that obtains authorization codes provided by the application to a particular client will be able to exchange them for access tokens using his/her own client ID and client secret. These access tokens will then grant the attacker access to the victim's resources.

Verify that the client that executes the exchange request is the same as the client that was provided with the authorization code.

### Strictly Validate the redirect URI - _(auth server)_
Whitelist the EXACT callback uri for the Authorization Code.  Some might think that they can simply register their domain name, however, if there is Cross-Site Scripting anywhere on the domains that are allowed, it can be leveraged into a redirect to an attacker's site.  

In otherwords, if the redirect URI is not validated properly, an attacker may be able to perform an open redirect or steal authorization codes. Attackers can redirect the user to a website they control by initially providing the URL of a website they trust (the authorization server). As the authorization code is a parameter appended to the redirect URI by the server, an attacker may be able to steal the authorization code. This authorization code can be used to get access tokens if the client secret is compromised or not needed.

The authorization server should verify whether the provided redirecturi is one of the redirecturis that the clients provided during the registration process. 

Again, it is extremely important that the match is an **exact string match**, as otherwise attackers may be able to circumvent the URI validation logic or perform other types of technology-specific attacks.

### Hash authorization codes - _(auth server)_
Attackers may steal authorization codes from the database using an attack such as SQL injection.

Hash the authorization codes when stored in the database on the authorization server to further protect their users.  However, if you have a SQL Injection, you have much bigger problems.

# PKCE
Proof Key for Code Exchange (PKCE) can be used to prevent CSRF attacks on the Authorization Code Flow but it's real use is to protect public client from Authorization Code Interception.

In the event that you are designing a mobile application, it may be possible for other applications to register the same custom URL scheme as your application. This can cause problems when your application is communicating back-and-forth with other servers.  It's possible to steal authorization codes this way if a malicious application is present on the mobile device.

## How PKCE Works:
 * Client creates a code_verifier, code_challenge, and code_challenge_method
 * Client Hashes the code_verifier using SHA256 and sets the code_challenge as the hash
 * Client sends code_challenge and code_challenge_method to Authorization Server when it redirects the User to authenticate.
 * Auth Server holds onto code_challenge and sends an Authorization Code to Client.
 * Client sends both the Authorization Code and the code_verifier together to the Authorization Server.
 * Authorization server uses SHA256 to hash the code_verifier and compares the hash with the code_challenge.
