
```
1
The user accesses a resource provided by the SP
2
Since the user is not authenticated, the SP initiates authentication by redirecting the user to the IdP with a SAML request
3
The user authenticates with the IdP
4
The IdP generates a SAML assertion containing the user's information, digitally signs the SAML assertion, and sends it in the HTTP response to the browser.
The browser sends the SAML assertion to the SP
5
The SP verifies the SAML assertion
6
The user requests the resource
7
The SP provides the resource
```

SAML Flow Example
As with OAuth, let us walk through a concrete example to ensure we fully understand the SAML flow. 
Let us assume that the user John wants to access the SP academy.htb with his sso.htb credentials. 

The SAML flow then looks like this:

Steps 1 & 2: Authentication Request
John accesses academy.htb. Since this is an unauthenticated request, academy.htb redirects John to sso.htb's IdP with a SAML request that looks similar to this:

Code: xml
```
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24" Version="2.0" ProviderName="SP test" IssueInstant="2014-07-16T23:52:45Z" Destination="http://sso.htb/idp/SSOService.php" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://academy.htb/index.php">
  <saml:Issuer>http://academy.htb/index.php</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
```

The SAML request contains the following parameters:

Destination: The destination where the browser should send the SAML request
AssertionCustomerServiceURL: The URL the IdP should send the response to after authentication
saml:Issuer: The SAML request's issuer
Step 3: Authentication
John authenticates with sso.htb using his username and password. The IdP verifies the credentials and authenticates him.

Step 4: Assertion Generation
After successful authentication, the IdP generates a SAML assertion for John. This Assertion is then sent to John in an HTTP response. John's browser forwards the SAML assertion to the SP academy.htb. The SAML assertion looks similar to this:

Code: xml
```
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_1234567890" IssueInstant="2024-03-18T12:00:00Z" Version="2.0">
	<saml:Issuer>http://sso.htb/idp/</saml:Issuer>
	<saml:Subject>
		<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">johndoe@hackthebox.htb</saml:NameID>
	</saml:Subject>
	<saml:AttributeStatement>
			<saml:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
				<saml:AttributeValue>john</saml:AttributeValue>
			</saml:Attribute>
		<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue>john@hackthebox.htb</saml:AttributeValue>
		<saml:Attribute>
	</saml:AttributeStatement>
</saml:Assertion>
```
The SAML assertion contains the following parameters:

saml:Issuer: The SAML assertion's issuer
saml:Subject: The SAML assertion's subject
saml:NameID: A unique identifier for the SAML assertion's subject
saml:AttributeStatement: List of attributes about the SAML subject




Service Provider
We can access the service provider at http://academy.htb/. The login form is disabled, as the platform does not support direct login. Instead, we can only log in via SAML through the SSO provider:

   
http://academy.htb/

Identity Provider
After clicking the button Log in with our HackTheBox SSO, we are redirected to the identity provider at http://sso.htb/, where we can log in with the provided credentials:

   
http://sso.htb/

SAML Flow
As we can see, the redirect to the IdP contains the SAML request:

image

After URL decoding the SAMLrequest parameter, we are left with the following base64-encoded SAML request:

fVNNj9owFLzzK1DukA/SbWNBJAr9QKIQEbqHXirHfhRLie36OV3239dxsru02sUHR3qemTdjv8yRNrUmy9ae5QF+t4B2NHbr0tQSiT9cBK2RRFEUSCRtAIllpFx+25JkGhFtlFVM1cF/tNssigjGCiV72ma9CPa7T9v9l83uJ884Te8ynqZJNKuqiMazE/2QZXcV0DR9H7/LkjiKq6yn3oNBp7MInGww6tUQW9hItFRaV4+SdBLNJkl2jCOSJCTNfvTUtQsrJLWefrZWkzBEVNOzrUIUja6hCxJ2WxIKrsOy3Jdg/ggGU33WvUgx5P8oJBfy1+3YVQ9C8vV4LCbFvjz2Isun61gpiW0DZmjz/bB9dkYZ5dA8eneUoXeQe/a8c0h8apO/gp6H14AXiiY753CzLlQt2KOvd+uzMg21bweJp7GvCD45eShpJWpg4iSAB88yy7pWDysD1MIisKaFYBz+03wYN+B++FxyCxc7XqlGUyOwexO4UGaHkC9Br+Gr2k3SAU75zWFjhHU4Vy7c50EZ3r0aMNf7aKgzr4wdLulV8d51eMN2Pno6vv6T8r8=

We need to decode and inflate the data to view the SAML request in XML, which we can achieve with a tool like SAMLTool. 
This gives us the following SAML request:

```
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="ONELOGIN_d9da469d44203bb0a13fa8996bea4471592101b9"
    Version="2.0"
    IssueInstant="2024-03-29T10:22:49Z"
    Destination="http://sso.htb/simplesaml/saml2/idp/SSOService.php"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="http://academy.htb/acs.php">
    <saml:Issuer>http://academy.htb/</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        AllowCreate="true" />
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
```

As we can see, the issuer is the service provider http://academy.htb/, and the SAML response will be sent to http://academy.htb/acs.php.

After authenticating with the identity provider, we are redirected to the specified return URL http://academy.htb/acs.php, 
which displays information about our user account:

   
http://academy.htb/acs.php

This is the result of a POST request containing the SAML response in a POST parameter:

image

We can view the XML SAML response by URL-decoding and base64-decoding the data. Inflating is not required. This results in the following SAML response:

```
<samlp:Response
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_6e61f34f4275f4b299932f628497567a6016798cf8" Version="2.0" IssueInstant="2024-03-29T10:27:14Z" Destination="http://academy.htb/acs.php" InResponseTo="ONELOGIN_d9da469d44203bb0a13fa8996bea4471592101b9">
  <saml:Issuer>
    http://sso.htb/simplesaml/saml2/idp/metadata.php
  </saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    [...]
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_122a6a73ecb01dd0a3bbb7e26d15e00cebcadf3233" Version="2.0" IssueInstant="2024-03-29T10:27:14Z">
    <saml:Issuer>
      http://sso.htb/simplesaml/saml2/idp/metadata.php
    </saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        [...]
    </ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://academy.htb/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_fc173d61602f3a77ea73d722266d23e2cd8b7c5f90</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-03-29T10:32:14Z" Recipient="http://academy.htb/acs.php" InResponseTo="ONELOGIN_d9da469d44203bb0a13fa8996bea4471592101b9"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-03-29T10:26:44Z" NotOnOrAfter="2024-03-29T10:32:14Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://academy.htb/</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2024-03-29T10:27:14Z" SessionNotOnOrAfter="2024-03-29T18:27:14Z" SessionIndex="_198010fecef918e3222495ec1eea3401e2b5445a4d">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">1234</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">htb-stdnt</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">htb-stdnt@academy.htb</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```


While this is a lot of data, the most essential parts are the following:

ds:Signature: contains the digital signature by the IdP to ensure the SAML assertion cannot be tampered with
saml:Assertion: The SAML assertion that contains information about the user's authentication status
As we can see, the SAML assertion contains the following attributes, which are displayed on academy.htb:

```

<saml:AttributeStatement>
	<saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
		<saml:AttributeValue xsi:type="xs:string">1234</saml:AttributeValue>
	</saml:Attribute>
	<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
		<saml:AttributeValue xsi:type="xs:string">htb-stdnt</saml:AttributeValue>
	</saml:Attribute>
	<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
		<saml:AttributeValue xsi:type="xs:string">htb-stdnt@academy.htb</saml:AttributeValue>
	</saml:Attribute>
</saml:AttributeStatement>

