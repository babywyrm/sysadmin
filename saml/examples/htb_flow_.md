
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
