#!/usr/bin/env python
#
#
##
# https://gist.github.com/tuxfight3r/5ab9edf7816ec0c2f1427ae172205233
##
##

# Prereq: PyCrypto
# Validation: https://www.samltool.com/decrypt.php

# Usage: ./decrypt_saml_response.py --key PRIVATE_KEY --pretty-print RESPONSE_XML

import sys
import optparse
import base64
from lxml import etree
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

ns = {
    'soap11': 'http://schemas.xmlsoap.org/soap/envelope/',
    'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
    'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'xenc': 'http://www.w3.org/2001/04/xmlenc#',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}

#ENC_DATA_XPATH = '/soap11:Envelope/soap11:Body/saml2p:Response/saml2:EncryptedAssertion/xenc:EncryptedData'
ENC_DATA_XPATH = '//saml2p:Response/saml2:EncryptedAssertion/xenc:EncryptedData'

# cf. https://gist.github.com/lkdocs/6519359
def decrypt_RSA(private_key_path, b64message):
    private_key = open(private_key_path, "r").read()
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(base64.b64decode(b64message))
    return decrypted

# cf. https://stackoverflow.com/questions/40188082/aes128-cbc-bad-magic-number-and-error-reading-input-file
def decrypt_AES(key, b64message):
    message = base64.b64decode(b64message)
    initialization_vector = message[:16]
    message_to_decrypt = message[16:]
    crypter = AES.new(key, AES.MODE_CBC, initialization_vector)
    decrypted_message = crypter.decrypt(message_to_decrypt)
    return decrypted_message

def summarize_assertion_xml(xml):
    print('Key:')
    print('  Encryption Method: ' + xml.xpath(ENC_DATA_XPATH + '/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm', namespaces=ns)[0])
    print('  Digest Method: ' + xml.xpath(ENC_DATA_XPATH + '/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod/@Algorithm', namespaces=ns)[0])
    print('  X509 Certificate: ' + xml.xpath(ENC_DATA_XPATH + '/ds:KeyInfo/xenc:EncryptedKey/ds:KeyInfo/ds:X509Data/ds:X509Certificate', namespaces=ns)[0].text)
    print('  Cipher Value: ' + xml.xpath(ENC_DATA_XPATH + '/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue', namespaces=ns)[0].text)
    print('Data:')
    print('  Encryption Method: ' + xml.xpath(ENC_DATA_XPATH + '/xenc:EncryptionMethod/@Algorithm', namespaces=ns)[0])
    print('  Cipher Value: ' + xml.xpath(ENC_DATA_XPATH + '/xenc:CipherData/xenc:CipherValue', namespaces=ns)[0].text)

def xml_prettify():
    import xml.dom.minidom
    return xml.dom.minidom.parseString(str(output)).toprettyxml()

def main():
    parser = optparse.OptionParser()
    parser.add_option("-k", "--private-key", action="store", dest="private_key_path")
    parser.add_option("-p", "--pretty-print", action="store_true", dest="pretty_print")
    parser.add_option("-s", "--summary", action="store_true", dest="summary")
    (opts, args) = parser.parse_args()

    if opts.private_key_path == None:
        print('private key is required.')
        sys.exit(1)

    f = sys.stdin
    if len(args) == 1:
        f = open(args[0], 'r')
    xml = etree.parse(f, parser=etree.XMLParser())

    if opts.summary:
        summarize_assertion_xml(xml)
        sys.exit(0)

    encrypted_key = xml.xpath(ENC_DATA_XPATH + '/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue', namespaces=ns)[0].text
    decrypted_key = decrypt_RSA(opts.private_key_path, encrypted_key)
#    print('decrypted key: ' + str(decrypted_key))

    encrypted_message = xml.xpath(ENC_DATA_XPATH + '/xenc:CipherData/xenc:CipherValue', namespaces=ns)[0].text
    decrypted_message = decrypt_AES(decrypted_key, encrypted_message)
#    print('decrypted message: ' + str(decrypted_message))
    output = str(decrypted_message)

    SAML_ASSERTION_START_MARKER = '<saml2:Assertion '
    SAML_ASSERTION_END_MARKER = '</saml2:Assertion>'
    saml_assertion_start = output.find(SAML_ASSERTION_START_MARKER)
    saml_assertion_end = output.find(SAML_ASSERTION_END_MARKER) + len(SAML_ASSERTION_END_MARKER)
    output = output[saml_assertion_start : saml_assertion_end]

    if opts.pretty_print:
        import xml.dom.minidom
        print(xml.dom.minidom.parseString(str(output)).toprettyxml())
    else:
        print(output)

if __name__ == '__main__':
    main()

##
##

    
