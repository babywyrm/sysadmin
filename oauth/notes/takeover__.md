# OAuth to Account takeover

##
#
https://github.com/HackTricks-wiki/hacktricks/blob/master/pentesting-web/oauth-to-account-takeover.md
#
##

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Basic Information <a href="#d4a8" id="d4a8"></a>

OAuth offers various versions, with foundational insights accessible at [OAuth 2.0 documentation](https://oauth.net/2/). This discussion primarily centers on the widely used [OAuth 2.0 authorization code grant type](https://oauth.net/2/grant-types/authorization-code/), providing an **authorization framework that enables an application to access or perform actions on a user's account in another application** (the authorization server).

Consider a hypothetical website _**https://example.com**_, designed to **showcase all your social media posts**, including private ones. To achieve this, OAuth 2.0 is employed. _https://example.com_ will request your permission to **access your social media posts**. Consequently, a consent screen will appear on _https://socialmedia.com_, outlining the **permissions being requested and the developer making the request**. Upon your authorization, _https://example.com_ gains the ability to **access your posts on your behalf**.

It's essential to grasp the following components within the OAuth 2.0 framework:

- **resource owner**: You, as the **user/entity**, authorize access to your resource, like your social media account posts.
- **resource server**: The **server managing authenticated requests** after the application has secured an `access token` on behalf of the `resource owner`, e.g., **https://socialmedia.com**.
- **client application**: The **application seeking authorization** from the `resource owner`, such as **https://example.com**.
- **authorization server**: The **server that issues `access tokens`** to the `client application` following the successful authentication of the `resource owner` and securing authorization, e.g., **https://socialmedia.com**.
- **client\_id**: A public, unique identifier for the application.
- **client\_secret:** A confidential key, known solely to the application and the authorization server, used for generating `access_tokens`.
- **response\_type**: A value specifying **the type of token requested**, like `code`.
- **scope**: The **level of access** the `client application` is requesting from the `resource owner`.
- **redirect\_uri**: The **URL to which the user is redirected after authorization**. This typically must align with the pre-registered redirect URL.
- **state**: A parameter to **maintain data across the user's redirection to and from the authorization server**. Its uniqueness is critical for serving as a **CSRF protection mechanism**.
- **grant\_type**: A parameter indicating **the grant type and the type of token to be returned**.
- **code**: The authorization code from the `authorization server`, used in tandem with `client_id` and `client_secret` by the client application to acquire an `access_token`.
- **access\_token**: The **token that the client application uses for API requests** on behalf of the `resource owner`.
- **refresh\_token**: Enables the application to **obtain a new `access_token` without re-prompting the user**.

### Flow

The **actual OAuth flow** proceeds as follows:

1. You navigate to [https://example.com](https://example.com) and select the “Integrate with Social Media” button.
2. The site then sends a request to [https://socialmedia.com](https://socialmedia.com) asking for your authorization to let https://example.com’s application access your posts. The request is structured as:

```
https://socialmedia.com/auth
?response_type=code
&client_id=example_clientId
&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
&scope=readPosts
&state=randomString123
```

3. You are then presented with a consent page.

4. Following your approval, Social Media sends a response to the `redirect_uri` with the `code` and `state` parameters:

```
https://example.com?code=uniqueCode123&state=randomString123
```

5. https://example.com utilizes this `code`, together with its `client_id` and `client_secret`, to make a server-side request to obtain an `access_token` on your behalf, enabling access to the permissions you consented to:

```
POST /oauth/access_token
Host: socialmedia.com
...{"client_id": "example_clientId", "client_secret": "example_clientSecret", "code": "uniqueCode123", "grant_type": "authorization_code"}
```

6. Finally, the process concludes as https://example.com employs your `access_token` to make an API call to Social Media to access

## Vulnerabilities <a href="#323a" id="323a"></a>

### Open redirect\_uri <a href="#cc36" id="cc36"></a>

The `redirect_uri` is crucial for security in OAuth and OpenID implementations, as it directs where sensitive data, like authorization codes, are sent post-authorization. If misconfigured, it could allow attackers to redirect these requests to malicious servers, enabling account takeover.

Exploitation techniques vary based on the authorization server's validation logic. They can range from strict path matching to accepting any URL within the specified domain or subdirectory. Common exploitation methods include open redirects, path traversal, exploiting weak regexes, and HTML injection for token theft.

Besides `redirect_uri`, other OAuth and OpenID parameters like `client_uri`, `policy_uri`, `tos_uri`, and `initiate_login_uri` are also susceptible to redirection attacks. These parameters are optional and their support varies across servers.

For those targeting an OpenID server, the discovery endpoint (`**.well-known/openid-configuration**`) often lists valuable configuration details like `registration_endpoint`, `request_uri_parameter_supported`, and "`require_request_uri_registration`. These details can aid in identifying the registration endpoint and other configuration specifics of the server.

### XSS in redirect implementation <a href="#bda5" id="bda5"></a>

As mentioned in this bug bounty report [https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html](https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html) it might be possible that the redirect **URL is being reflected in the response** of the server after the user authenticates, being **vulnerable to XSS**. Possible payload to test:

```
https://app.victim.com/login?redirectUrl=https://app.victim.com/dashboard</script><h1>test</h1>
```

### CSRF - Improper handling of state parameter <a href="#bda5" id="bda5"></a>

In OAuth implementations, the misuse or omission of the **`state` parameter** can significantly increase the risk of **Cross-Site Request Forgery (CSRF)** attacks. This vulnerability arises when the `state` parameter is either **not used, used as a static value, or not properly validated**, allowing attackers to bypass CSRF protections. 

Attackers can exploit this by intercepting the authorization process to link their account with a victim's account, leading to potential **account takeovers**. This is especially critical in applications where OAuth is used for **authentication purposes**.

Real-world examples of this vulnerability have been documented in various **CTF challenges** and **hacking platforms**, highlighting its practical implications. The issue also extends to integrations with third-party services like **Slack**, **Stripe**, and **PayPal**, where attackers can redirect notifications or payments to their accounts.

Proper handling and validation of the **`state` parameter** are crucial for safeguarding against CSRF and securing the OAuth flow.

### Pre Account Takeover <a href="#ebe4" id="ebe4"></a>

1. **Without Email Verification on Account Creation**: Attackers can preemptively create an account using the victim's email. If the victim later uses a third-party service for login, the application might inadvertently link this third-party account to the attacker's pre-created account, leading to unauthorized access.

2. **Exploiting Lax OAuth Email Verification**: Attackers may exploit OAuth services that don't verify emails by registering with their service and then changing the account email to the victim's. This method similarly risks unauthorized account access, akin to the first scenario but through a different attack vector.


### Disclosure of Secrets <a href="#e177" id="e177"></a>

Identifying and protecting secret OAuth parameters is crucial. While the **`client_id`** can be safely disclosed, revealing the **`client_secret`** poses significant risks. If the `client_secret` is compromised, attackers can exploit the identity and trust of the application to **steal user `access_tokens`** and private information.

A common vulnerability arises when applications mistakenly handle the exchange of the authorization `code` for an `access_token` on the client-side rather than the server-side. This mistake leads to the exposure of the `client_secret`, enabling attackers to generate `access_tokens` under the guise of the application. Moreover, through social engineering, attackers could escalate privileges by adding additional scopes to the OAuth authorization, further exploiting the application's trusted status.

### Client Secret Bruteforce

You can try to **bruteforce the client\_secret** of a service provider with the identity provider in order to be try to steal accounts.\
The request to BF may look similar to:

```
POST /token HTTP/1.1
content-type: application/x-www-form-urlencoded
host: 10.10.10.10:3000
content-length: 135
Connection: close

code=77515&redirect_uri=http%3A%2F%2F10.10.10.10%3A3000%2Fcallback&grant_type=authorization_code&client_id=public_client_id&client_secret=[bruteforce]
```

### Referer Header leaking Code + State

Once the client has the **code and state**, if it's **reflected inside the Referer header** when he browses to a different page, then it's vulnerable.

### Access Token Stored in Browser History

Go to the **browser history and check if the access token is saved in there**.

### Everlasting Authorization Code

The **authorization code should live just for some time to limit the time window where an attacker can steal and use it**.

### Authorization/Refresh Token not bound to client

If you can get the **authorization code and use it with a different client then you can takeover other accounts**.

### Happy Paths, XSS, Iframes & Post Messages to leak code & state values

**[Check this post](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/#gadget-2-xss-on-sandbox-third-party-domain-that-gets-the-url)**

### AWS Cognito <a href="#bda5" id="bda5"></a>

In this bug bounty report: [**https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/**](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/) you can see that the **token** that **AWS Cognito** gives back to the user might have **enough permissions to overwrite the user data**. Therefore, if you can **change the user email for a different user email**, you might be able to **take over** others accounts.

```bash
# Read info of the user
aws cognito-idp get-user --region us-east-1 --access-token eyJraWQiOiJPVj[...]

# Change email address
aws cognito-idp update-user-attributes --region us-east-1 --access-token eyJraWQ[...] --user-attributes Name=email,Value=imaginary@flickr.com
{
    "CodeDeliveryDetailsList": [
        {
            "Destination": "i***@f***.com",
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }
    ]
}
```

For more detailed info about how to abuse AWS cognito check:

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum" %}

### Abusing other Apps tokens <a href="#bda5" id="bda5"></a>

As [**mentioned in this writeup**](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts), OAuth flows that expect to receive the **token** (and not a code) could be vulnerable if they not check that the token belongs to the app.

This is because an **attacker** could create an **application supporting OAuth and login with Facebook** (for example) in his own application. Then, once a victim logins with Facebook in the **attackers application**, the attacker could get the **OAuth token of the user given to his application, and use it to login in the victim OAuth application using the victims user token**.

{% hint style="danger" %}
Therefore, if the attacker manages to get the user access his own OAuth application, he will be able to take over the victims account in applications that are expecting a token and aren't checking if the token was granted to their app ID.
{% endhint %}

### Two links & cookie <a href="#bda5" id="bda5"></a>

According to [**this writeup**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), it was possible to make a victim open a page with a **returnUrl** pointing to the attackers host. This info would be **stored in a cookie (RU)** and in a **later step** the **prompt** will **ask** the **user** if he wants to give access to that attackers host.

To bypass this prompt, it was possible to open a tab to initiate the **Oauth flow** that would set this RU cookie using the **returnUrl**, close the tab before the prompt is shown, and open a new tab without that value. Then, the **prompt won't inform about the attackers host**, but the cookie would be set to it, so the **token will be sent to the attackers host** in the redirection.

### SSRFs parameters <a href="#bda5" id="bda5"></a>

**[Check this research](https://portswigger.net/research/hidden-oauth-attack-vectors) For further details of this technique.**

Dynamic Client Registration in OAuth serves as a less obvious but critical vector for security vulnerabilities, specifically for **Server-Side Request Forgery (SSRF)** attacks. This endpoint allows OAuth servers to receive details about client applications, including sensitive URLs that could be exploited.

**Key Points:**

- **Dynamic Client Registration** is often mapped to `/register` and accepts details like `client_name`, `client_secret`, `redirect_uris`, and URLs for logos or JSON Web Key Sets (JWKs) via POST requests.
- This feature adheres to specifications laid out in **RFC7591** and **OpenID Connect Registration 1.0**, which include parameters potentially vulnerable to SSRF.
- The registration process can inadvertently expose servers to SSRF in several ways:
  - **`logo_uri`**: A URL for the client application's logo that might be fetched by the server, triggering SSRF or leading to XSS if the URL is mishandled.
  - **`jwks_uri`**: A URL to the client's JWK document, which if maliciously crafted, can cause the server to make outbound requests to an attacker-controlled server.
  - **`sector_identifier_uri`**: References a JSON array of `redirect_uris`, which the server might fetch, creating an SSRF opportunity.
  - **`request_uris`**: Lists allowed request URIs for the client, which can be exploited if the server fetches these URIs at the start of the authorization process.

**Exploitation Strategy:**

- SSRF can be triggered by registering a new client with malicious URLs in parameters like `logo_uri`, `jwks_uri`, or `sector_identifier_uri`.
- While direct exploitation via `request_uris` may be mitigated by whitelist controls, supplying a pre-registered, attacker-controlled `request_uri` can facilitate SSRF during the authorization phase.

## OAuth providers Race Conditions

If the platform you are testing is an OAuth provider [**read this to test for possible Race Conditions**](race-condition.md).

## References

* [**https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1**](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)
* [**https://portswigger.net/research/hidden-oauth-attack-vectors**](https://portswigger.net/research/hidden-oauth-attack-vectors)


<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>