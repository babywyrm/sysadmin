
##
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
 
