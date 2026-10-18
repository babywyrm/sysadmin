JWT Security Best Practices

##
#
https://curity.io/resources/learn/jwt-best-practices/
#
##

architect
20 min
JSON Web Tokens Introduction

JSON Web Tokens (JWTs) are quite common in the OAuth and OpenID Connect world. We're so used to them that we often don't pay much attention to how they're actually used. The general opinion is that they're good for being used as ID tokens or access tokens and that they're secure — as the tokens are usually signed or even encrypted. You have to remember though, that JWT is not a protocol but merely a message format. The RFC just shows you how you can structure a given message and how you can add layers of security that will protect the integrity and, optionally, the content of the message. JWTs are not secure just because they are JWTs, it's the way in which they’re used that determines whether they are secure or not.

This article shows some best practices for using JWTs so that you can maintain a high level of security in your applications. These practices are what we recommend at Curity and are based on community standards written down in RFCs as well as our own experience from working with JWTs.
What is a JWT Token?

A JSON Web Token (JWT, pronounced "jot") is a compact and URL-safe way of passing a JSON message between two parties. It's a standard, defined in RFC 7519. The token is a long string, divided into parts separated by dots. Each part is base64 URL-encoded.
JWT structure

A signed JWT example
JWT Structure

What parts the token has depends on the type of the JWT: whether it's a JWS (a signed token) or a JWE (an encrypted token). If the token is signed it will have three sections: the header, the payload, and the signature. If the token is encrypted it will consist of five parts: the header, the encrypted key, the initialization vector, the ciphertext (payload), and the authentication tag. Probably the most common use case for JWTs is to utilize them as access tokens and ID tokens in OAuth and OpenID Connect flows, but they can serve different purposes as well.
Free Course: JWT Security Best Practices

Free Course: JWT Security Best Practices
Get Started
1. JWTs Used as Access Tokens

JWTs are by-value tokens. This means that they contain data. Even if you can't read that data with your own eyes, it's still there and is quite easily available. Whether it's a problem or not depends on the intended audience of the token. An ID token is intended for the client's developers. You expect it to be decoded and its data used by the client. An access token, on the other hand, is intended for API developers. The API should decode and validate the token. If you issue JWT access tokens to your clients you have to remember that client developers will be able to access the data inside that token. And believe us — if they can, they will. This should make you consider a few things:

    Some developers can start using the data from the JWT in their applications. This isn't a problem in itself but can explode the minute you decide to introduce some changes to the structure of the data in your JWT. Suddenly many integrating apps can stop working as they won't be prepared for the new structure (e.g., some fields missing, or a change to the max length of a field).
    As everyone can read what is inside the token, you should take privacy into account. If you want to put sensitive data about a user in a token, or even Personally Identifiable Information (PII), remember that anyone can decode the token and access the data. If you can't remove such information from the token you should consider switching to the
    Phantom Token approach
    or the
    Split Token approach
    , where you use an opaque token outside your infrastructure, and make JWTs available only to your APIs. Both these patterns leverage integration with an API gateway to achieve this goal, but they differ in implementation details.
    Users’ private data is not the only information that your JWTs can leak. You should make sure that you don't put any valuable information about your API in the token. Anything that would help attackers to breach your API. For example, you should avoid revealing the programming languages, frameworks, operating systems, or the type of the API gateway, as this can help attackers to find vulnerabilities more easily.

It's also good to keep in mind that access tokens are most often used as bearer tokens. That means that the API accepts the token from whoever presented it — it's pretty much like paying with cash in a shop. If you find a $10 bill lying in the street, and pay with it for a coffee, the cashier will accept it, as long as it's a genuine banknote. The same applies to bearer access tokens. If that could pose problems to your application, you should consider changing the bearer token into a Proof of Possession token (a PoP token). You can achieve that with standards like
Demonstrating Proof of Possession
, or, when your client can use mutual-TLS,
by adding a confirmation (cnf) claim
to your tokens. The claim contains information that allows your APIs to verify whether the token holder is allowed to use it, like a fingerprint of the client’s certificate.
2. Avoid JWTs With Sensitive Data on the Front Channel

When it comes to access tokens, you can easily replace them with opaque tokens (as mentioned in the previous section), but the ID token is always a JWT. This means that you should put extra care into what is available in it so that you do not unintentionally reveal any sensitive data. It will be much safer for your UI client to call the user info endpoint and get the user's data from there instead of keeping it directly in the ID token.

Once tokens are cleared of sensitive data there will be no incentive for encrypting them. Even though encryption might sound like an excellent solution to keeping data private, the reality is that it is hard to configure and maintain secure encryption mechanisms. What is more, encryption requires much more computational resources, something that might become a burden for high-traffic applications.
3. JWT Signing And Encryption Algorithms

Regardless if the token is signed (a JWS) or encrypted (a JWE) it will contain an alg claim in the header. It indicates which algorithm has been used for signing or encryption. When verifying or decrypting the token you should always check the value of this claim with a list of algorithms that your system accepts. This mitigates an attack vector where someone would tamper with the token and make you use a different, probably less secure algorithm to verify the signature or decrypt the token. You should prefer allow-lists over deny-lists as it prevents any issues with case sensitivity. There were attacks on APIs that leveraged the fact that even though the server was configured to deny the none algorithm it was still accepting noNe as a valid option. Once the server accepted the token, it was treating it as "signed" with the none algorithm.

The special case of the none value in the alg claim tells clients and resource servers that the JWS is actually not signed at all. This option is not recommended, and you should be absolutely sure what you're doing if you want to enable unsigned JWTs. This would usually mean that you have strong certainty of the identity of both the issuer of the token and the client that handles the token, and you're absolutely sure that no party could have tampered with the token in transit.
Best Algorithms For Signing And Encryption

The registry for JSON Web Signatures and Encryption Algorithms lists all available algorithms that you can use to sign or encrypt JWTs. It also tells you which algorithms are recommended to be implemented by clients and servers, given the current state of knowledge on cryptography security. If you want to ensure financial-grade security to your signature then have a look at the recommendations outlined in the Financial-grade API security profile.

When signing is considered, elliptic curve-based algorithms are considered more secure. The option with the best security and performance is
EdDSA
, though ES256 (The Elliptic Curve Digital Signature Algorithm (ECDSA) using P-256 and SHA-256) is also a good choice. The most widely used option, supported by most technology stacks, is RS256 (RSASSA-PKCS1-v1_5 using SHA-256). The former ones are a lot faster than the latter, which is one of the main reasons for the stronger recommendation. The latter has been around much longer and offers better support in different languages and implementations. Still, if your setup enables this, and you're pretty sure that your clients will be able to use it, you should go for the EdDSA or ES256.

If you really need to use symmetric keys, then HS256 (HMAC using SHA-256) should be your choice — though using symmetric keys is not recommended, take a look at "When to Use Symmetric Signing" below to learn why.
4. When to Validate the JWT

The rule of thumb is — the service that receives a JWT should always validate it. The service should do it, even if it is on an internal network, for example, when the service received the token from another service in internal communication. You shouldn't rely on your environment settings to be part of your security scheme. If you move your services to a public domain, the threat model will change, and you will have to remember to update your security measures — experience shows that this is very often overlooked. Moreover, implementing token validation from the start will guard you against situations where someone manages to break into your network, or you would have a malicious actor in your organization.

The one case when you could consider omitting to check the signature of the token is when you first get it in the response from the token endpoint of the authorization server using TLS. You should definitely validate a token if using the implicit flow, and the token is sent back to the client by means of a redirect URI, as in such a case there is a greater risk of someone tampering with the token before you manage to retrieve it.
5. Always Check the JWT Issuer

Another claim that you should always check against an allow-list is the iss claim. When consuming the JWT, the API should be sure that the token has been issued by an expected authorization server. This is especially important if you adhere to another good practice and dynamically download the keys needed to validate or decrypt tokens. If someone should send you a forged JWT, with their issuer in it, and you then download keys from that issuer, then your application would validate the JWTs and accept them as genuine.

This good practice can also be explained in other words: you should always confirm that any cryptographic keys used to sign or encrypt the token actually belong to the JWT issuer. How to verify this will be different for different implementations. For example, if you're using OpenID Connect then the issuer will be a HTTPS URL. This makes it easy to confirm the ownership of the keys or certificates. Thus, it's good practice to always use such URLs as the issuer value. If this is not the case, you should make sure to get to know how to check this ownership.

Also, remember that the value of the iss claim should match exactly the value that you expect. If you expect the issuer to be https://example.com, then you should reject tokens with https://example.com/secure — this is not the same!
6. Always Check the Audience

The resource server should always check the aud claim and verify that the token was issued to an audience that the server is part of (as the aud claim can contain an array, the resource server should check if the correct value is present in that array). The server should reject any request that contains a token intended for different audiences. This helps to mitigate attack vectors where one resource server would obtain a genuine access token intended for it, and then use it to gain access to resources on a different resource server, which would not normally be available to the original server.

An ID token must contain the client ID in the aud claim (though it can also contain other audiences). You expect the token to be decoded by the client, so it can use the data inside it. This token should not be passed to anyone else. Clients should discard ID tokens that do not contain their ID in the audience claim — these tokens are not meant for this client and should not be used by it.

For access tokens, it is a good practice to use the URL of the API that the tokens are intended for.
7. Make Sure Clients Use Tokens as Intended

JWTs can be used as access tokens or ID tokens, or sometimes for other purposes. It is thus important to differentiate the types of tokens. When validating JWTs, always make sure that they are used as intended. For example, a resource server should not accept an ID token JWT as an access token. You can achieve this in different ways and it will depend on your concrete use case and implementation. Here are some examples:

    You can check the scope of the token. ID tokens don't have scopes, so checking whether an access token has any or a concrete scope will help you differentiate them.
    As noted before, tokens should have different values of the aud claim. If this is the case, you can use that claim's value to check the token type.
    You can use features of you authorization server. For example, the Curity Identity Server sets a purpose claim on the token, with values of either access_token or id_token.
    Some authorization servers set the typ header claim to at+JWT for access tokens. If your server supports that, you can use it to differentiate tokens.
    Different types of tokens could use different keys for signing. Your services will then reject access tokens signed with keys used for issuing ID tokens.
    You can use sets of required claims for different types of tokens. Your services can validate whether the received token contains specific claims that you expect from an access token.

8. Best Practices for Using Claims

Claims in a JWT represent pieces of information asserted by the authorization server. The token is usually signed, so its recipient can verify the signature and thus trust the values of the payload's claims. You should be wary, however, when dealing with some claims in the token's header. The JWT's header can contain claims that are used in the process of signature verification. For example:

    kid contains the ID of the key that the recipient should use for verification,
    jku contains a URI pointing to the JSON Web Key Set — a set that contains the verification key,
    x5c contains the public key certificate corresponding to the signature key.

You should take extra care when using these values straight from the token. If someone spoofed these claims then the malicious values can point your service to forged verification keys that will trick your service into accepting malicious access tokens. As noted before, make sure to verify whether keys contained in such claims, or any URIs, correspond to the token's issuer, or that they contain a value that you expect.
9. Dealing With Time-Based Claims

JWTs are self-contained, by-value tokens and it is very hard to revoke them, once issued and delivered to the recipient. Because of that, you should use as short an expiration time for your tokens as possible. A best practice is to set your JWT expiration to minutes or hours at maximum. You should avoid issuing access tokens valid for days or months.

Remember that the exp claim, containing the expiration time, is not the only time-based claim that you can use for verification. The nbf claim contains a "not-before" time. Recipients should reject the token if the current time is before the time in the nbf claim. Another time-based claim is iat — issued at. Recipients can use this claim to reject tokens that they deem too old, even if the token itself is not yet expired.

When working with time-based claims remember that server times can differ slightly between different machines. You should consider allowing a clock skew when checking the time-based values. A few seconds should usually be enough, and we don't recommend using more than 30 seconds for this purpose, as this would rather indicate problems with the server, not a common clock skew.
10. How to Work With JWT Signatures

In the case of a signed JWT — a JWS — you have to remember that the authorization server signs not only the payload of the token but also the header. Any change in the header or the payload would generate a different signature. This doesn't even have to be a change in the values of claims — adding or removing spaces or line breaks will also create a different token signature.

In order to mitigate a situation where an authorization server would issue two tokens with the same signature (two tokens created in the same second, for the same client and user, with the same scope and set of claims) many authorization servers add a random token ID in the jti claim. Thanks to this addition you can be sure that two different tokens will never have the same signature.

Token recipients require keys to properly validate JWT signatures. Your APIs can obtain them in a few different ways. You can get the keys from the authorization server in an onboarding process, and make sure that all your services have access to those keys. This, however, creates additional work when the keys change. That's why it's good practice to always download the keys or certificates from the authorization server's JSON Web Key Set endpoint (JWKS endpoint). The endpoint returns public keys in a standardized format and the API can cache the response basing on the usual HTTP cache control headers. Whenever the keys change, the API can download a new set, which allows for an easy key rotation that will not break any integrations.
Signing key rotation with JWKS

Using JWKS endpoint to refresh token signing keys

Remember that if the JWT header contains any keys or certificates that the receiver is supposed to use in the verification process then the service must check whether they belong to the expected issuer. For example, the service can validate a certificate trust chain.

Again, remember that the receiver must check the alg header claim against an allow list.
11. When to use Symmetric Signing

The rule of thumb here is to try to avoid using symmetric signing at all. Nowadays, there are probably not many use cases where you would have to use symmetric signing instead of asymmetric. When using symmetric keys then all the parties need to know the shared secret. When the number of involved parties grows it becomes more and more difficult to guard the safety of the secret, and to replace it, in case it is compromised.

Another problem with symmetric signing is the proof of who actually signed the token. When using asymmetric keys you're sure that the JWT was signed by whoever is in possession of the private key. In the case of symmetric signing, any party that has access to the secret can also issue signed tokens.

If, for some reason, you have to use symmetric signing try to use ephemeral secrets, which will help increase security.
12. Pairwise Pseudonymous Identifiers

The OpenID Connect standard introduces Pairwise Pseudonymous Identifiers (PPID) that the authorization server can use instead of plain user IDs. A PPID is an obfuscated user ID, unique for a given client. This helps improve users' privacy. Especially if the user ID is represented by sensitive data like an e-mail or a social security number. Thanks to PPID, the client can still differentiate users, but will not get any excess information. Have a look at
the Pairwise Pseudonymous Identifiers article
to learn more.
13. Do not use JWTs for Sessions

There is a popular belief among web developers that JWTs have some benefits for use as a session retention mechanism — instead of session cookies and centralized sessions. This should not be considered good practice. JWTs were never considered for use with sessions, and using them in such a way may actually lower the security of your applications. If you want to know what the exact reasons against such use of JWTs are, have a look at these articles:

    Stop using JWT for sessions
    Stop using JWT for sessions, part 2: Why your solution doesn't work

Conclusion

This article has explored the best practices of using JSON Web Tokens so that you strengthen your API security and web applications security. It's important to remember that JWT safety depends greatly on how you use and validate tokens. Just because a JWT contains a cryptographic signature it doesn't automatically mean that it's valid, or that you should blindly trust it. Your APIs can become vulnerable to cyber-attacks unless you observe good practices.

The good practices outlined in this article are true at the time of writing and we are making sure to keep them up to date. You should remember, however, that security standards and the security levels of cryptography can change quite rapidly and it's good to keep an eye on what is happening in the industry. You can follow any changes in RFCs that talk about the good practices for JWTs: in RFC 8725 JSON Web Token Best Current Practices and in RFC 7518 JSON Web Algorithms (JWA).

Have a look at OAuth Tools, a free online tool created by Curity, if you want to play around with JWTs, encode and decode them, or work with OAuth and OpenID Connect flows.
