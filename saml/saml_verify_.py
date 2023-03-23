SAML (Security Assertion Markup Language) is an XML-based standard for exchanging authentication and authorization data between parties, such as identity providers and service providers. SAML assertions can be signed to provide message integrity and authenticity.

SAML signatures are based on public key cryptography. The sender of a SAML message signs the message using their private key, and the receiver can verify the signature using the sender's public key. The signature covers the entire SAML message, including the XML elements and attributes.

To verify a SAML signature, the receiver of the message first extracts the signature from the SAML message. The receiver then retrieves the sender's public key from a trusted source, such as a certificate or metadata document. The receiver then uses the public key to verify the signature.

Here is an example Python script that uses the PySAML2 library to verify a SAML signature:


from xml.etree import ElementTree
from base64 import b64decode
from hashlib import sha1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from saml2.sigver import pre_signature_part, signed_part
from saml2.sigver import verify_signed_element

# Example SAML message with signature
saml_message = """
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                 ID="_e091d75a-9ec6-4ca8-b771-91dc6c364d6d"
                 Version="2.0"
                 IssueInstant="2023-03-22T14:06:00Z"
                 Destination="https://example.com/service"
                 InResponseTo="_d1a222fa-6f9d-4847-9e51-62cf7b51416f">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Status>
    <saml:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xmlns:xs="http://www.w3.org/2001/XMLSchema"
                  ID="_f0ea3f7c-6d5f-43c1-9f92-9ac0d01f0d68"
                  Version="2.0"
                  IssueInstant="2023-03-22T14:06:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_d1a222fa-6f9d-4847-9e51-62cf7b51416f"
                                      NotOnOrAfter="2023-03-22T14:11:00Z"
                                      Recipient="https://example.com/service"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions>
      <saml:AudienceRestriction>
        <saml:Audience>https://example.com/service</saml:Audience>
      </saml:AudienceRestriction>
      <saml:OneTimeUse/>
    </saml


##
##
