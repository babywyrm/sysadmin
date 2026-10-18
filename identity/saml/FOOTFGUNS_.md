
##
#
https://workos.com/blog/fun-with-saml-sso-vulnerabilities-and-footguns
#
##


If you’re here, you’ve likely been tasked with building SAML-based SSO as a requirement for an enterprise deal. If you’re just diving into the problem space of SSO / SAML, we’d first suggest checking out

. Otherwise, buckle up for a brief but titillating foray into why XML-based authentication is… challenging.
Why is SAML SSO so vulnerability-prone

The attack surface for SAML authentication is extensive, mostly due to the fact that SAML is XML-based.
- it’s hard to form, hard to read, and hard to parse. Combined with the high complexity of the and the number of parties involved in establishing authentication, we get what often feels like a

and all the accompanying implications. Be prepared to tackle a steep learning curve, lots of bugs, high maintenance costs, attack vectors galore, and an absurd spread of edge cases.

Most SAML SSO security vulnerabilities are introduced by Service Providers (SPs) improperly validating and processing SAML responses received from Identity Providers (IdPs). This happens because SAML SSO is typically not a core-value feature for an application, nor is the implementation common knowledge for most developers. Unknowns become even more unlikely to be identified and addressed when the pressure is on to just deliver something to unblock a high-value contract - as is oftentimes the case. However, to build SAML SSO safely and securely in-house requires significant buy-in and

- on the scale of months, representing hundreds of thousands of dollars in developer time.‍

If not done right, you expose your application and your customers to potentially huge security risks. To drive that home, here are just a few recently published SAML-related vulnerabilities:

- “… GitLab SAML integration had a validation issue that permitted an attacker to takeover another user's account.”

- “… an attacker could exploit this [SAML] vulnerability to bypass the authentication process and gain full administrative access to the system [IBM Data Risk Manager].”

- “An attacker could authenticate to a different user's [Mattermost] account via a crafted SAML response.”

    - “… improper verification of signatures in PAN-OS SAML authentication enables an unauthenticated network-based attacker to access protected resources.”

It should be evident by now that oversights in SAML implementations are ubiquitous and problematic, even among experienced engineering teams.

So let’s dive into some of the more common security pitfalls developers building SAML-based SSO should be aware of, as well as cover a few suggested countermeasures. Just to be clear, this guide is by no means comprehensive and is meant to provide a starting point for SAML security considerations as well as some follow-on resources.
Brief anatomy of a SAML response

Let's say we're integrating our application with Okta via SAML. Below is an example of an XML document we might get when attempting to authenticate a user, containing a simplified but valid SAML response:

<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="https://api.workos-test.com/auth/okta/callback" ID="id72697176167120131651975993" InResponseTo="_b464ac6d6621d7a1a814" IssueInstant="2019-11-27T02:45:30.657Z" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk1klancwHzz1SNi357<\saml2:Issuer>
  <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"\>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id7269717616793800631152500" IssueInstant="2019-11-27T02:45:30.657Z" Version="2.0">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk1klancwHzz1SNi357<\saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"\>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#id7269717616793800631152500">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
              <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
            </ds:Transform>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"\>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>TxG611vjAtZ/+F2QFtzcByyh7Hb5Dq928NC6a9FvsfT8r/VENRQ6iUfcZiQDImsCNbc58p8ftYRiKf0pFsGz4Y821c/POBqjaW7eL7J6c7EwBJcSRX6/xGbPd1jgvc4QVPfZuchdjJL6a2vAXPaFM3BDa2mpqp2/bd4VqkjAibvoygqNaI/TzTT5E28nSAez39Y+dzL16jlo4d/5T3g0gqLwsbD0w6KveyJXSQpjyuj1nel3R1w8SZITZmdNBwiPwbk04iE7zWbTNVkh9Dgo+xhhwSpqwBzq4KiCvYl7HhHCgjJVKCPh28V/2xANqZjTtgNB3lrnmz/MwnRn9H5Jsg==<\ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAWz5LOgCMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04Mzk3NDAxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMTkwOTAzMjIwODI1WhcNMjkwOTAzMjIwOTI1WjCBkjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODM5NzQwMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzCXtN0wgczIzU3nKnFb64XZPJB4m+JWX45lUDYoxOLJJKpv41pQ9Cq/SmYTj3EL23ZHA5W/xr9jSbfPYOYiJ6R3T8q6n2cLFWTXsS7axRxTC7Y6tUK+7RM5yydWxB17CsgSCmMGAqux2Z1HkA9JEJxVXCQDTVHww7tjO6bFrRXdWszJt5f6ESNIHfKgm+WXole61Kz3IW4vCQRdfAl7eoK4MBWERJN16j9N9NLpGaPBYs65oF1LQ7WWWZQ/8oYgLKszVvCkxdSBcpym39Ob/fdtdmKesVnxPLJjK/wB3WXVjbbUHqYy/ArkoK2FteYXLHzBmX89HOMuzofUYGbWbvQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBnVSSM4KJ0jO2R3AxF1IKY6orTbHXgl6/glZbSN0AT7Lpf7fduo7n1RnxToaKDQyRPumMPvPnHUvpkfg3BMjUGKFXJJYEc3pKoSrt/aoDsjPLxri+mjK8x0vasGbj7G+T2J6//TPVnGCGYJMRBG7LUfTCbFVVdIQy7agwE/rIzYSbQFaM1RoUAzIjWzkuDVmO6zWtVBUZgySO1dphPctgItPUmZEQUX+EiEK7Azg7wQmOiPv9Kwmj3SSxPmwCHxXScQLQdzicmaI6hMbOeCcFJSuxbGDc1xbJKd/WbLy1ZrDlcDPky8cJILFnZoh/y5+LX7YUEnIwxtE5Ohiwt78dz<\ds:X509Certificate>
        <\ds:X509Data>
      <\ds:KeyInfo>
    <\ds:Signature>
    <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">demo@workos-okta.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer>
        <saml2:SubjectConfirmationData InResponseTo="_b464ac6d6621d7a1a814" NotOnOrAfter="2019-11-27T02:50:30.657Z" Recipient="https://api.workos-test.com/auth/okta/callback"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" NotBefore="2019-11-27T02:40:30.657Z" NotOnOrAfter="2019-11-27T02:50:30.657Z">
      <saml2:AudienceRestriction>
        <saml2:Audience>https://api.workos-test.com/auth/okta/callback</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>

Like we mentioned earlier, the SAML spec is complex and responses can get lengthy, so this example is comparatively quite terse. Keeping things to what you should know before we go into SAML vulnerabilities, let’s walk through what the response (saml2p:Response) is communicating:

    Line 2 begins the SAML response, which has the unique ID id72697176167120131651975993web and is intended for consumption by the workos-test service provider’s Assertion Consumer Service (ACS) URL, i.e. the endpoint https://api.workos-test.com/auth/okta/callback.

    Line 3 specifies the issuer saml2:Issuer and contains the unique URI (also referred to as EntityID) of the IdP that issued the response, in this case http://www.okta.com/exk1klancwHzz1SNi357.

    Line 7 begins the assertion saml2:Assertion with the unique ID id7269717616793800631152500. An assertion is a package of information asserting the identity of a user, often containing additional user attributes like first / last name, email, ID, etc.

    Line 8 specifies the issuer of the assertion itself, in this case also http://www.okta.com/exk1klancwHzz1SNi357.

    Lines 9 - 30 contains the digital signature ds:Signature over the assertion, which should be validated to determine the authenticity of the assertion.

    Lines 31 - 36 specify the subject saml2:Subject of the assertion, i.e. the authenticated principal / user corresponding to the unique identifier found in saml2:NameID, who in this case is demo@workos-okta.com.

    Line 37 saml2:Conditions defines the window of time for which the assertion should be considered valid, i.e. from NotBefore (inclusive) to NotOnOrAfter (exclusive).

Disable DTD processing

The first step in processing a SAML response is parsing the payload. Parsing and loading an XML document into memory is an inherently expensive set of operations, but can be unexpectedly costly due to a feature of XML that allows references to external or remote documents, i.e.

(DTDs).

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE Response [<!ENTITY ggwp SYSTEM "http://workos.com/¯\_(ツ)_/¯.xml">]>
<Response>&ggwp;</saml2p:Response>

When a DTD is encountered, parsers will try to fetch and load the referenced document as well. If the referenced document is large enough or results in infinitely looping references, your server can be slowed or even brought down trying to complete the process. The same holds true if the payload itself is very large, DTDs or not.

Two low-hanging mitigations you should implement to prevent buffer overflows are:

    Limiting SAML payload size to < 1MB. 1MB is a generous upper limit and should be tuned down based on average received payload size.
    Configuring your XML parser to never fetch remote files or try to load and parse DTDs. Some XML parsers do so by default, for example, Python’s 

    module.

XML processing, and thus by extension SAML response processing, is vulnerable to buffer overflow attacks from other scenarios described later on in this post. And unfortunately, protecting your application from a service outage is among the most mild of outcomes compared to the

allows - it is a dark and anxiety-inducing rabbit hole.

So, if you’re not writing your own XML parser (generally not suggested), it’s important to vet the XML parser(s) your application and its dependencies use - ensure they handle other exploits like
and

.
Validate the SAML response schema first

The primary security mechanism in the SAML handshake is the cryptographic validation of

(XML-DSig) - which establishes the trust chain between IdPs and SPs. XML-DSig validation should always be done prior to executing business logic; however, the separation between signature verification and operating on the rest of a SAML payload opens up SAML authentication to vulnerabilities exposed by what are called XML Signature Wrapping (XSW) attacks.  These attacks have numerous permutations which can result in outcomes such as (but not limited to):

    Denial-of-service by inserting arbitrary elements that lead to buffer overflows.

    Escalating permissions by injecting assertions that allow an adversary to impersonate and be authenticated as another user, like an account admin.

The exploit here consists of modifying the payload without invalidating any signatures - think
or

but for for XML.

Original response (pre-WSW):

<Response ID="foo">
  <Signature>
    <SignedInfo>
      <Reference URI="#foo">...</Reference>
    </SignedInfo>
  </Signature>
  <Assertion ID="bar">
    <Signature>
      <SignedInfo>
        <Reference URI="#bar">...</Reference>
      </SignedInfo>
    </Signature>
  </Assertion>
</Response>

Modified response (pre-XSW):

<Response ID="xsw">
  <Signature>
    <SignedInfo>
      <Reference URI="#foo">...</Reference>
    </SignedInfo>
    <Response ID="foo">
      <Assertion ID="bar">
        <Signature>
          <SignedInfo>
            <Reference URI="#bar">...</Reference>
          </SignedInfo>
        </Signature>
      </Assertion>
    </Response>
  </Signature>
  <Assertion ID="snek"></Assertion>
</Response>

The broadest countermeasure to XSW attacks is validating the schema of the SAML XML document. Payloads for SAML responses of any given IdP should have a deterministic standard schema that can be used as a reference in a schema compliance validation module, which should be executed prior to XML-DSig verification. Here are
used by OneLogin’s python3-saml package to perform

. Schemas should be vetted local copies as opposed to being fetched from 3rd party remote locations at runtime or on server start.

All of that being said,

; there is room for error in the validation module logic itself, as well as in the syntactic rigor of the reference schema. A second low-hanging countermeasure to XSW attacks that should be employed for the sake of redundancy is to always use absolute XPath expressions to select elements in processes post-schema validation. Explicit absolute XPath expressions set an unambiguous expectation for the location of elements.

Here’s an example of a valid response that’s been modified in an XSW attack (specifically a signature exclusion attack, more on that later):

<Response ID="foo">
  <Assertion ID="snek">...</Assertion>
  <Assertion ID="bar">
    <Signature>
      <SignedInfo>
        <Reference URI="#bar">...</Reference>
      </SignedInfo>
    </Signature>
  </Assertion>
</Response>

This modification also exploits the common, incorrect, but not unreasonable assumption that a well-formed SAML response will only ever have a single assertion. So while XML-DSig verification would succeed for the signature returned by doc.getElementsByTagName(“Signature”)[0], the assertion returned and processed by doc.getElementsByTagName(“Assertion”)[0] would be the injected snek assertion. This attack would have been more likely to fail if the XPath expression “/Response/Assertion[0]/Signature” was used in the assertion signature validation logic.
Check that you’re the intended recipient

This sounds obvious, but make sure to check that a SAML response is intended for your app. This is low-hanging fruit that can prevent attacks exploiting IdPs that use a shared private signing key for all integrated SPs of a given tenant, as opposed to issuing unique keys per application. The most common attack entails the unauthorized lateral movement by a malicious user across an enterprise’s IdP-integrated apps:
A chart showing a SAML authentication flow where the ContractManager fails to check the intended recipient.

A chart showing a SAML authentication flow where the ContractManager fails to check the intended recipient

‍

A second scenario would be a third party impersonating your app and gaining user access. The likelihood of this attack vector being exploited is pretty low because the malicious party would need to be in possession of the IdP’s private signing key (

) - but we’re mentioning it for the sake of completeness:
A chart showing a SAML authentication flow where a third party impersonates a Service Provider by intercepting the initial SSO sign in and redirecting the actual SAML response to the legitimate Service Provider.

There are Service Providers that don’t bother to check if they’re the intended recipient, relying only on the validity of assertion signatures to prove the sender is a trusted party and that the response is valid. But as we’ve illustrated above, valid signatures aren’t enough to prevent unwanted access.

When dealing with security and authentication, stay paranoid my friend, and have some additional redundancies to catch edge cases. In this case, some easy-to-implement checks are:

    The response destination is present, non-empty, and refers to an ACS URL that you are expecting.
    The response and assertion issuers refer to an IdP EntityID you recognize.
    You are the specified audience for any assertions.

<Response Destination="https://api.your-app.com/auth/okta/callback">
  <Issuer>http://www.okta.com/abcd123</Issuer>
  <Assertion>
    <Issuer>http://www.okta.com/abcd123</Issuer>
  </Assertion>
  <Conditions>
    <AudienceRestriction>
      <Audience>https://api.your-app.com/auth/okta/callback</Audience>
    </AudienceRestriction>
  </Conditions>
</Response>

Validate every signature

Like we mentioned earlier, cryptographic validation of signatures is the primary mechanism for determining the authenticity of SAML payloads. It’s a good idea to read through the

because it anchors SAML security, but the pithy statement to remember when handling SAML responses is only process entities that are validly signed.

There’s a class of attacks that exploit poorly implemented SP security logic known as signature exclusion attacks. These attacks will insert forged unsigned elements, banking on the possibility that the SP’s security logic will skip XML-DSig validation if no signature is found. Another common slipup is implementing validation logic that checks only the first assertion’s signature and then assumes remaining assertions are signed. Here are some rules to follow to avoid the most common oversights:

➞ The entire SAML response itself should be signed
A chart showing that making sure an entire SAML response is signed is the better approach rather than only checking the first assertion.

➞ Every assertion should be signed

Something to note is that you should not assume a response will have only one assertion, and furthermore, each assertion should be signed in its entirety.
A chart showing that it's bad to assume that a response only has one assertion while the better approach is checking for multiple assertions and ensuring they are all signed.

➞ Only accept encryption schemes from an explicitly defined set of algorithms

similarly can sometimes overlook this point, and in fact, there was a related exposed as recently as last year.  If possible, we suggest hardcoding your validation logic to only accept as the encryption scheme. Otherwise, verify Algorithm attribute values are from a

.

Bad:

<ds:SignatureMethod Algorithm=""/>

<ds:SignatureMethod Algorithm="none"/>

Good:

<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>

If you’re planning on using a third party library to do SAML processing and XML-DSig validation, be sure to vet what it does under the hood - especially if it does XML parsing and processing as well. As much as possible, try to avoid libraries that depend directly or indirectly on
or its dependency - many SAML and XML libraries are just language-specific bindings for xmlsec1 and libxml2, and as a result,

.

We highly suggest doing XML-DSig validation in native code - in fact, at WorkOS we built our SAML library from scratch for greater control, and so we can respond immediately to newly discovered

.
Use the canonicalized XML

is the process of transforming an XML document into a semantically identical but normalized representation (more on this later). The CanonicalizationMethod specifies which

to apply - the most commonly occurring one we’ve seen is xml-exc-c14, which strips XML comments during transformation. This generally wouldn’t be a problem, except for the fact that most SAML libraries perform canonicalization prior to doing XML-DSig validation on the canonicalized assertions. Why is this a concern? Here’s what can happen if the library’s underlying XML element text extraction logic doesn’t consider inner comment nodes.

Suppose I’m a disgruntled developer who would dearly like a substantial raise from my company that uses Okta + PayrollService (this is all fictional, I’m not disgruntled). I used to work at PayrollService and so am pretty confident this exploit I’m about to attempt will work, because patching it never got prioritized in favor of feature work, and because no one external has noticed anything amiss, yet… Anyway.

I know that WorkOS IT always uses itadmin@workos.com as an administrative account for every app used within the organization (we don’t actually). So equipped with this knowledge and using my personal domain, I create a PayrollService account for a user itadmin@workos.com.disgruntled.dev and set up SSO with Okta. Self-service free trials FTW.

Here’s a simplified SAML assertion authenticating me as a PayrollService user:

<Assertion ID="id123">
  <Signature>
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="#id123">
    </SignedInfo>
    <SignatureValue>...</SignatureValue>
    <KeyInfo>...</KeyInfo>
  </Signature>
  <Subject>
    <NameID>itadmin@workos.com.disgruntled.dev</NameID>
  </Subject>
</Assertion>

Now I can modify the SAML assertion by adding a comment:

<Assertion ID="id123">
  <Signature>
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="#id123">
    </SignedInfo>
    <SignatureValue>...</SignatureValue>
    <KeyInfo>...</KeyInfo>
  </Signature>
  <Subject>
    <NameID>itadmin@workos.com<!---->.disgruntled.dev</NameID>
  </Subject>
</Assertion>

This modified assertion doesn’t invalidate the signature because canonicalization will strip comments before XML-DSig verification - it will have the same canonical representation as the unmodified assertion. Great!

So now, believing the assertion is authentic, PayrollService checks to see which user is being authenticated. Its SAML library grabs the user identifier from the NameID element, but it, incorrectly, only reads the inner text of the element’s first node, i.e. itadmin@workos.com. Then PayrollService determines that itadmin@workos.com is indeed a user, and just like that, I’m in and ready to approve raises for myself and all my friends!

back in 2018, and while some of the more commonly used open source SAML libraries have since addressed it, there undoubtedly remain many internal or open source libraries that haven’t. So echoing recommendations from before, vet your SAML and XML libraries.‍

Ideally, comments wouldn’t be purged prior to XML-DSig validation, so that injected comments would indeed cause validation to fail - but that’s unrealistic or inadvisable to try to enforce for a couple reasons, which we’ll leave for another time. Instead, you’ll want to make sure that:

    The canonicalized XML document is used in processes post-signature verification.

    Or, barring the first, that full text-extraction is handled gracefully when inner comments exist.

Avoiding replay attacks

Replay attacks occur when a SAML response is captured and re-sent to the Service Provider for duplicate processing, which can have outcomes like denial-of-service for your users, or if the SP charges by API request, eating up request quotas. The most robust countermeasure against replay attacks is preventing the capture of SAML responses in the first place - which can be accomplished by using HTTPS (should be a given already) and never exposing the SAML response to the browser. Here’s what the authentication flow could look like:
A chart showing a SAML authentication flow where SAML responses are prevented from being captured.

However, very few IdPs actually support the

, a requirement of back-channel SAML authentication. As a result, most SAML implementations rely entirely on the browser to relay SAML payloads between the SP and IdP:
A chart showing a SAML authentication flow without back-channel SAML authentication.

Because the SAML response is exposed to the user agent, it becomes trivial to capture (by inspecting the
,

, or with malicious browser plugins) and replay a response. So another approach to mitigating replay attacks is to maintain a cache of previously seen assertion IDs, immediately rejecting responses containing any assertion with an ID that already exists in the cache. A cache item could have a TTL equal to the expiry datetime of the originating assertion, for example:

<Assertion>
  <Conditions NotBefore="2020-08-12T02:40:30.657Z" NotOnOrAfter="2020-08-12T02:50:30.657Z">
    <AudienceRestriction>
      <Audience>https://api.foo.com/auth/callback</Audience>
    </AudienceRestriction>
  </Conditions>
</Assertion>

A third much less robust but much faster to implement countermeasure (which should be implemented regardless) is logic that strictly enforces the validation window for assertions.

One last thing to note is that most SPs that implement SAML SSO use 3rd party open source SAML libraries for speed to value, yet are not protected against replay attacks because the strongest countermeasures require additional architectural changes.
Conclusion

As with most software engineering, building SAML SSO for enterprises follows the
. There’s a hill to climb to get to an MVP, and an entirely different hill if you’d like to sleep at night. SAML-based authentication is rife with sleeping dragons, of which this guide only introduces a very small subset - but hopefully it has been useful in helping you avoid some of them. If product requirements allow, try to avoid integrating with IdPs using SAML; a more modern, safer, and simpler alternative protocol is . And if you’re thinking twice about building SAML SSO yourself in-house, then consider using a 3rd party vendor that makes it their business to provide a safe, performant, highly available, and super fast to integrate SSO API… like !
