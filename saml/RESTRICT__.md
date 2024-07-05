
##
#
https://techdocs.broadcom.com/us/en/ca-enterprise-software/layer7-api-management/api-management-oauth-toolkit/4-6/customizing-the-oauth-toolkit/oauth-audience-restriction.html
#
https://support.okta.com/help/s/article/What-Is-the-Audience-URI?language=en_US
#
https://apim.docs.wso2.com/en/latest/design/api-security/oauth2/grant-types/saml-extension-grant/
#
https://security.stackexchange.com/questions/13424/what-is-the-purpose-of-audiencerestriction-in-saml-2-0
#
https://wiki.resolution.de/doc/saml-sso/latest/all/knowledgebase-articles/technical/error-reading-samlresponse-failed-audience-uri-is-not-a-valid-audience-for-this-response
#
##


What is SAML Audience Restriction?
A SAML (Security Assertion Markup Language) audience restriction is a constraint that is applied to a SAML assertion to limit its audience to a specific entity or entities. 
A SAML audience restriction specifies one or more entities that are allowed to consume the SAML assertion, and it prevents the assertion from being consumed by any other entity.

1. The identity provider (IdP) generates a SAML assertion.
2. The SAML assertion includes a SAML audience restriction that specifies one or more entities that are allowed to consume the assertion.
3. The SAML assertion is sent to the service provider (SP), along with a request for access to a protected resource.
4. The SP verifies that the SAML audience restriction allows it to consume the SAML assertion.
5. The SP extracts the relevant information from the SAML assertion and uses that information to grant the user access to the protected resource.

SAML audience restrictions are an important security feature of the SAML authentication and authorization protocol, 
as they help to prevent the SAML assertion from being consumed by unauthorized entities. 
SAML audience restrictions are typically included in the SAML assertion by the IdP, and they can be used by the SP to ensure that the SAML assertion is intended for its consumption. 
SAML audience restrictions can also be used to support advanced authentication and authorization scenarios, such as multi-tenant environments or federated identity management.



What is the purpose of AudienceRestriction in SAML 2.0?
Asked 12 years, 3 months ago
Modified 12 years, 3 months ago
Viewed 33k times
18

Having read through the core specification for SAML 2.0 section 2.5.1.4 (page 23) I still cannot fully understand the purpose of the AudienceRestriction tag and what problem it is attempting to rectify.

My, probably incorrect, interpretation of the AudienceRestriction tag is that it facilitates a sort of intention statement declaring for what specific URI with the SP a given assertion is valid.

Would very much appreciate if someone could explain (a) the purpose of the tag and (b) a typical use-case scenario and (c) any potential implications of it's exclusion and/or misuse.

saml
Share
Improve this question
Follow
asked Apr 3, 2012 at 12:45
Christoffer's user avatar
Christoffer
1,04011 gold badge66 silver badges1414 bronze badges
Add a comment
1 Answer
Sorted by:

Highest score (default)
15

SAML 2.0 AudienceRestriction is pretty much what you have gathered. It is a validity condition for an assertion. In particular it declares that the assertion's semantics are only valid for the relying party named by URI in that element.

The purpose is to restrict the conditions under which the assertion is valid, and to optionally provide terms and conditions relating to such validity. So the semantics of the element have to do with the scope and conditions of the trust relationships. From SAML 2.0 Core, Section 2.5.1.4(PDF):

Although a SAML relying party that is outside the audiences specified is capable of drawing conclusions from an assertion, the SAML asserting party explicitly makes no representation as to accuracy or trustworthiness to such a party...

...the <AudienceRestriction> element allows theSAML asserting party to state explicitly that no warranty is provided to such a party in a machine- andhuman-readable form. While there can be no guarantee that a court would uphold such a warrantyexclusion in every circumstance, the probability of upholding the warranty exclusion is considerably improved...

I.e., it's not a code thing but a human (risk management/warranty/trust) thing. If it's used incorrectly modules tend to throw errors - most SP's expect themselves to be listed in the AudienceRestriction.

Share
Improve this answer
Follow
edited Apr 3, 2012 at 19:15
answered Apr 3, 2012 at 14:42
Mark Beadles's user avatar
Mark Beadles
4,00222 gold badges2222 silver badges2323 bronze badges
Where is that quote from? – 
Steve
 CommentedApr 3, 2012 at 19:07
I will add the attribution, sorry. – 
Mark Beadles
 CommentedApr 3, 2012 at 19:13
4
I see this as one (of many) ways of reducing replay-attacks. You cannot capture a SAML-assertion valid in one context and reuse it in another context. – 
Rolf Rander
 CommentedMay 12, 2014 at 7:05
@RolfRander Wont recipient solve that? – 
Suraj Jain
 CommentedMar 6, 2020 at 5:32
There is some discussion about the difference here stackoverflow.com/questions/38778156/… – 
Rolf Rander
 CommentedApr 25, 2020 at 14:31



 ```
<?xml version="1.0" encoding="UTF-8"?>
<samlp:response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" id="_3f5be74eec5b0ca666f709ad27e7e4d5ced92b40fa" version="2.0" issueinstant="2014-07-22T20:09:36Z" destination="https://ec2.sandbox.com/ctl/auth/saml/consume/openidp" inresponseto="ONELOGINe975a4c39ed65faaf2cb0db9db325a40ab739688">
   <saml:issuer>https://openidp.feide.no</saml:issuer>
   <ds:signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:signedinfo>
         <ds:canonicalizationmethod algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ds:signaturemethod algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1">
               <ds:reference uri="#_3f5be74eec5b0ca666f709ad27e7e4d5ced92b40fa">
                  <ds:transforms>
                     <ds:transform algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature">
                        <ds:transform algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                     </ds:transform>
                  </ds:transforms>
                  <ds:digestmethod algorithm="http://www.w3.org/2000/09/xmldsig#sha1">
                     <ds:digestvalue>ClSnuL1KqmJCn6pnwgr/OFbGtzs=</ds:digestvalue>
                  </ds:digestmethod>
               </ds:reference>
            </ds:signaturemethod>
         </ds:canonicalizationmethod>
      </ds:signedinfo>
      <ds:signaturevalue>tG/1250TV3Z0E7nYFEA8udqzOKf1KYeRmcimt03Y3KlbSoNEweX/Bq19k3c06+bBt7eNh8m4QDaXnuquNzp1/ozNWj8m5QJchliIf/TW7TeUxsME44/Nc9DLFEuUIBU2uzdkocUtC2DA6u8w/sZUikZB6h05jAFCYYQaIXBl+2A=</ds:signaturevalue>
      <ds:keyinfo>
         <ds:x509data>
            <ds:x509certificate>MIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UECxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0BCQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoXDTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhlaW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBvcGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdAdW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlxAZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4HlnO4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZjcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQYj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1jwKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3KjjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w==</ds:x509certificate>
         </ds:x509data>
      </ds:keyinfo>
   </ds:signature>
   <samlp:status>
      <samlp:statuscode value="urn:oasis:names:tc:SAML:2.0:status:Success" />
   </samlp:status>
   <saml:assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="_c556e8798d9a5530b5ef6903f256859554914e04d8" version="2.0" issueinstant="2014-07-22T20:09:36Z">
      <saml:issuer>https://openidp.feide.no</saml:issuer>
      <ds:signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
         <ds:signedinfo>
            <ds:canonicalizationmethod algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
               <ds:signaturemethod algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1">
                  <ds:reference uri="#_c556e8798d9a5530b5ef6903f256859554914e04d8">
                     <ds:transforms>
                        <ds:transform algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature">
                           <ds:transform algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                        </ds:transform>
                     </ds:transforms>
                     <ds:digestmethod algorithm="http://www.w3.org/2000/09/xmldsig#sha1">
                        <ds:digestvalue>Pwg2mxMwbEDrZi9oivLsSdaHEN8=</ds:digestvalue>
                     </ds:digestmethod>
                  </ds:reference>
               </ds:signaturemethod>
            </ds:canonicalizationmethod>
         </ds:signedinfo>
         <ds:signaturevalue>P8SgqxPYDm4egRKMsMAAeHpXZYYhntTAJeKFA+icVWo6tichubxKl4s1JeU6OrWwIkW5421zEAjAX1xSJix/qbF7rzqGx13TGGL2U/fr1GpOWR4O3jse3+RTJARdWYzUhCZEZkXPmC1sn2unwEEMj4U4aYiOLqXgxIgonqabpIQ=</ds:signaturevalue>
         <ds:keyinfo>
            <ds:x509data>
               <ds:x509certificate>MIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UECxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0BCQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoXDTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhlaW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBvcGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdAdW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlxAZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4HlnO4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZjcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQYj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1jwKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3KjjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w==</ds:x509certificate>
            </ds:x509data>
         </ds:keyinfo>
      </ds:signature>
      <saml:subject>
         <saml:nameid spnamequalifier="https://ec2.sandbox.com/ctl/auth/saml/metadata/openidp" format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_562ba52feb51d86078334cb68c69607edd2206e2b0</saml:nameid>
         <saml:subjectconfirmation method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:subjectconfirmationdata notonorafter="2014-07-22T20:14:36Z" recipient="https://ec2.sandbox.com/ctl/auth/saml/consume/openidp" inresponseto="ONELOGINe975a4c39ed65faaf2cb0db9db325a40ab739688" />
         </saml:subjectconfirmation>
      </saml:subject>
      <saml:conditions notbefore="2014-07-22T20:09:06Z" notonorafter="2014-07-22T20:14:36Z">
         <saml:audiencerestriction>
            <saml:audience>https://ec2.sandbox.com/ctl/auth/saml/metadata/openidp</saml:audience>
         </saml:audiencerestriction>
      </saml:conditions>
      <saml:authnstatement authninstant="2014-07-22T20:06:57Z" sessionnotonorafter="2014-07-23T04:09:36Z" sessionindex="_c21b0465a3742aafbb600bd6325e551c45db1c27cc">
         <saml:authncontext>
            <saml:authncontextclassref>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:authncontextclassref>
         </saml:authncontext>
      </saml:authnstatement>
      <saml:attributestatement>
         <saml:attribute name="uid" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">sveg</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="givenName" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">swathi</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="sn" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">vegesna</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="cn" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">swathi vegesna</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="mail" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">svegesna@bluestatedigital.com</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="eduPersonPrincipalName" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">sveg@rnd.feide.no</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="eduPersonTargetedID" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">3c76215396aeb592422133ba5ce2581795c46c88</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="urn:oid:0.9.2342.19200300.100.1.1" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">sveg</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="urn:oid:2.5.4.42" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">swathi</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="urn:oid:2.5.4.4" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">vegesna</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="urn:oid:2.5.4.3" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">swathi vegesna</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="urn:oid:0.9.2342.19200300.100.1.3" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">svegesna@bluestatedigital.com</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">sveg@rnd.feide.no</saml:attributevalue>
         </saml:attribute>
         <saml:attribute name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:attributevalue xsi:type="xs:string">3c76215396aeb592422133ba5ce2581795c46c88</saml:attributevalue>
         </saml:attribute>
      </saml:attributestatement>
   </saml:assertion>
</samlp:response>
```


 SAML Extension Grant¶
Flow¶
SAML 2.0 is an XML-based protocol. It uses security tokens containing assertions to pass information about an end-user between a SAML authority and a SAML consumer. A SAML authority is an identity provider (IdP) and a SAML consumer is a service provider (SP).

Enterprise applications that have SAML2 based SSO infrastructures sometimes need to consume OAuth-protected resources through APIs. However, these apps prefer to use the existing trust relationship with the IdP, even if the OAuth authorization server is entirely different from the IdP. The API Manager leverages this trust relationship by exchanging the SAML2.0 token to an OAuth token with the authorization server. It acts as the OAuth authorization server.

Info

When SAML bearer token is used, the roles of the user can be retrieved from either the user store or the SAML assertion. When checkRolesFromSamlAssertion system property is set to true, the roles will be checked from the SAML assertion, not the user store. Refer the steps below to set this property:

Set the property -DcheckRolesFromSamlAssertion=true in the <API-M_HOME>/bin/api-manager.(sh|bat) file.
Restart the server.
The diagram below depicts the above with WSO2 Identity Server as the IdP.



The steps of the above diagram are explained below:

Step [1] : User initiates a login call to an enterprise application

Step [2] :

As the application is a SAML SP, it redirects the user to the SAML2.0 IdP to log in.
The user provides credentials at the IdP and is redirected back to the SP with a SAML2.0 token signed by the IdP.
The SP verifies the token and logs the user to the application.
The SAML 2.0 token is stored in the user's session by the SP.
Step [3] :

The enterprise application (SP) wants to access an OAuth2 protected API resource through WSO2 API Manager.
The application makes a request to the API Manager to exchange the SAML2 bearer token for an OAuth2.0 access token.
The API Manager validates the assertion and returns the access token.
Step [4] : User does API invocations through the API Manager by setting it as an Authorization header with the returned OAuth2 access token.

A sequence diagram explaining the above flow would be as follows:



Configuring the token exchange¶
Note

Before you begin, make sure you have the following:

A valid user account in the API Developer Portal.
A valid consumer key and consumer secret. Initially, these keys must be generated in the API Developer Portal clicking the Generate Keys button on the Production Keys tab of the application.
A running API Gateway instance.
If the Key Manager is on a different server than the API Gateway, change the server URL (host and ports) of the Key Manager as mentioned below, in the <API-M_HOME>/repository/conf/deployment.toml file.

[apim.key_manager]
configuration.ServerURL = "<key-manager-server-url>"
A valid SAML2 assertion. For instructions on how to configure WSO2 API Manager with SAML2, see Configuring API Manager for SSO
In this example, WSO2 Identity Server 5.7.0 is used as the IdP to get a SAML token and the API Manager is used as the OAuth server.

Tip

Refer to the configurations in the Identity Server documentation to set up the SAML2 Extension Grant to exchange a SAML2 assertion for a valid OAuth access token.

Sign in to the API Manager's management console (`https://localhost:9443/carbon') using admin/admin credentials.

Note

If you are using a tenant to create the Identity Provider, use the credentials of tenant admin to log into the API Manager's Management Console.

Click Main > Identity Providers > Add.



Provide the following values to configure the IdP:

Under Basic Information

Identity Provider Name : Enter a unique name for the IdP.
Identity Provider Public Certificate : The certificate used to sign the SAML assertion. Export the public certificate of WSO2 IS and import it here. For more information, see Exporting the public certificate in the WSO2 Identity Server documentation.

Alternatively, you can create a self-signed certificate and then export it as a .cer file using the following commands:


keytool -genkey -alias wookie -keyalg RSA -keystore wookieKeystore.jks -keysize 4096 keytool -v -export -file keystore1.cer -keystore wookiekeystore.jks -alias wookie
Alias : Give the name of the alias if the Identity Provider identifies this token endpoint by an alias. e.g., https://localhost:9443/oauth2/token.

Under Federated Authenticators > SAML2 Web SSO Configuration

Enable SAML2 Web SSO : true

Identity Provider Entity Id : The SAML2 issuer name specified when generating the assertion token, which contains the unique identifier of the IdP. You give this name when configuring the SP.

Service Provider Entity Id : Issuer name given when configuring the SP.

SSO URL : Enter the IDP's SAML2 Web SSO URL value. E.g., https://localhost:9444/samlsso/ if you have offset the default port, which is 9443.

Note

If you are in tenant mode, append the tenant domain to the SSO URL as a query parameter as below.

https://localhost:9443/samlsso?tenantDomain=<tenantDomain>



Next, let's  register a service provider.

Sign in to the management console of the Identity Server and click Main > Service Providers > Add.



Choose to edit the service provider that you just registered and click **Inbound Authentication Configuration > SAML2 Web SSO Configuration



Provide the following values to configure the SP and click Update :

Issuer : Give any name
Assertion Consumer URL : The URL to which the IDP sends the SAML response. For example: https://<application-host-name>/<redirection-path>
Enable Response Signing : true
Enable Audience Restriction : true
Audience : URL of the token API. For example: https://localhost:9443/oauth2/token


Let's see how to get a signed SAML2 token (encoded assertion value) when authenticating against a SAML2 IDP. With the authentication request, you pass attributes such as the SAML2 issuer name, token endpoint and the restricted audience. In this guide, we use a command-line client program developed by WSO2 to create the 64-bit, URL-encoded SAML assertion.

Invoking the Token API to generate tokens¶
Follow the steps below to invoke the token API to generate access tokens from SAML2 assertions.

Combine the consumer key and consumer secret keys as consumer-key:consumer-secret. Encode the combined string using base64.  Here's an example consumer key and secret combination:

wU62DjlyDBnq87GlBwplfqvmAbAa:ksdSdoefDDP7wpaElfqvmjDue.

Let's create a SAML2 assertion using the same command-line client that you used in the previous section.

Download the command-line tool from here and extract the ZIP file.

Go to the extracted folder using the command line and execute the following command. We assume that both the client and the API Gateway run on the same server. Therefore, the Token API URL is https://localhost:9443/oauth2/token


Format
Example

java -jar SAML2AssertionCreator.jar <Identity_Provider_Entity_Id> <saml-subject> <saml-recipient> <saml-audience> <Identity_Provider_JKS_file> <Identity_Provider_JKS_password> <Identity_Provider_certificate_alias> <Identity_Provider_private_key_password>

The arguments are as follows:

Identity_Provider_Entity_Id (issuer)	This is the value of the saml:Issuer, which is a unique identifier of the identity provider.
saml-subject	This is the value of the name ID, which is found in the saml:Subject -> saml:NameId
saml-recipient	This is the value of the subject confirmation data recipient, which is found in the saml:Subject -> saml:SubjectConfirmation -> saml:SubjectConfirmationData.Recipient
saml-audience	This is the value that is added to the saml:AudienceRestriction element of the token. This argument can take multiple values separated by commas. Each value is added as a saml:Audience element within saml:AudienceRestriction
Identity_Provider_JKS_file	Pointer to the Java Key Store (JKS) file to be used for credentials.
Identity_Provider_JKS_password	The JKS password.
Identity_Provider_certificate_alias	The alias of the public certificate.
Identity_Provider_private_key_password	The password of the private key that is used for signing.
This command returns a SAML2 assertion XML string and a base64-URL encoded assertion XML string. You now have a SAML2 assertion.

Access the Token API using a REST client such as cURL. For example, the following cURL command generates an access token and a refresh token. You can use the refresh token at the time a token is renewed.


curl -k -d "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&assertion=<base64-URL_encoded_assertion>&scope=PRODUCTION" -H "Authorization: Basic <base64_encoded_consumer-key:consumer_secret>" -H "Content-Type: application/x-www-form-urlencoded" https://localhost:9443/oauth2/token


