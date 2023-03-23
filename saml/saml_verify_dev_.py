#!/usr/bin/python3

##
##

import xml.etree.ElementTree as ET
from xmlsec import constants as xmlsec_constants
from xmlsec.signature import SignatureVerifier, SignatureNotFound


def verify_saml(saml_message, idp_cert):
    # Parse the SAML message XML
    root = ET.fromstring(saml_message)

    # Find the Signature element
    try:
        signature_elem = SignatureVerifier.find_signature(root)
    except SignatureNotFound:
        raise ValueError("Signature not found in SAML message")

    # Verify the signature using the IDP certificate
    verifier = SignatureVerifier()
    try:
        verifier.load_signature(signature_elem)
        verifier.verify(xmlsec_constants.TransformExclC14N,
                        xmlsec_constants.TransformRsaSha1,
                        cert_file=idp_cert)
    except Exception as e:
        raise ValueError("Signature verification failed: {}".format(e))

    # Verify that the message ID matches the expected format
    msg_id = root.get('ID', '')
    if not msg_id.startswith('_'):
        raise ValueError("Invalid message ID: {}".format(msg_id))

    # Verify that the Issuer element contains the expected value
    issuer = root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
    if issuer is None or issuer.text != 'https://idp.example.com':
        raise ValueError("Invalid issuer: {}".format(issuer.text))

    # Verification succeeded
    return True

  
##  
## To use this function, you would pass it a string containing the SAML message and the path to the IDP certificate:
##
  


## SAML (Security Assertion Markup Language) is an XML-based standard for exchanging authentication and authorization data between parties, such as identity providers and service providers. SAML assertions can be signed to provide message integrity and authenticity.
## SAML signatures are based on public key cryptography. The sender of a SAML message signs the message using their private key, and the receiver can verify the signature using the sender's public key. The signature covers the entire SAML message, including the XML elements and attributes.
## To verify a SAML signature, the receiver of the message first extracts the signature from the SAML message. The receiver then retrieves the sender's public key from a trusted source, such as a certificate or metadata document. The receiver then uses the public key to verify the signature.
## Here is an example Python script that uses the PySAML2 library to verify a SAML signature:

##
##

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

import base64
import xmlsec

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
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2023-03-22T14:06:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
"""

# Parse the SAML message
doc = xmlsec.tree.fromstring(saml_message.encode("utf-8"))

# Extract the signature element
signature = xmlsec.tree.find_node(doc, xmlsec.constants.NodeSignature)

# Verify the signature
key = xmlsec.crypto.load_key("key.pem", xmlsec.constants.KeyDataFormatPem)
if xmlsec.crypto.verify(signature, key) != 1


##
##


import xml.etree.ElementTree as ET
from xmlsec import constants as xmlsec_constants
from xmlsec.signature import SignatureVerifier, SignatureNotFound


def validate_saml_signature(saml_message):
    # Parse the SAML message XML
    root = ET.fromstring(saml_message)

    # Find the Signature element
    try:
        signature_elem = SignatureVerifier.find_signature(root)
    except SignatureNotFound:
        raise ValueError("Signature not found in SAML message")

    # Verify the signature using the certificate in the Signature element
    verifier = SignatureVerifier()
    try:
        verifier.load_signature(signature_elem)
        verifier.verify(xmlsec_constants.TransformExclC14N,
                        xmlsec_constants.TransformRsaSha1)
    except Exception as e:
        raise ValueError("Signature verification failed: {}".format(e))

    # Signature is valid
    return True
    
    
##
##
## for example ##
##
##

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
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2023-03-22T14


    
