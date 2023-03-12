

##
#
https://www.samltool.com/decrypt.php
#
https://www.componentpro.com/blog/details/encrypting-decrypting-saml-response-xml
#
##



by System Administrator

This topic illustrates how to encrypt a SAML Response XML on the Identity website and decrypt the XML on the Service Provider website.

Encrypting a SAML Response XML:

Instead of adding an unencrypted SAML Assertion to the SAML response with

// Add assertion to the SAML response object.
samlResponse.Assertions.Add(samlAssertion);

, we need to create an EncryptedAssertion object from the unencrypted Assertion object and add the EncryptedAssertion object to the SAML response object as shown in the code below:

// Load the certificate for the encryption.
// Please make sure the file is in the root directory.
X509Certificate2 encryptingCert = new X509Certificate2(Path.Combine(HttpRuntime.AppDomainAppPath, "EncryptionX509Certificate.cer"), "password");
// Create an encrypted SAML assertion from the SAML assertion we have created.
EncryptedAssertion encryptedSamlAssertion = new EncryptedAssertion(samlAssertion, encryptingCert, new System.Security.Cryptography.Xml.EncryptionMethod(SamlKeyAlgorithm.TripleDesCbc));
// Add encrypted assertion to the SAML response object.
samlResponse.Assertions.Add(encryptedSamlAssertion);

Decrypting the SAML Response XML:

To read the encrypted SAML response from the IdP on the Service Provider website, you need to decrypt it and convert to an Assertion object. The following code demonstrates how to do so:

if (samlResponse.GetEncryptedAssertions().Count > 0)
{
   EncryptedAssertion encryptedAssertion = samlResponse.GetEncryptedAssertions()[0];

   // Load the private key.
   // Consider caching the loaded key in a production environment for better performance.
   X509Certificate2 decryptionKey = new X509Certificate2(Path.Combine(HttpRuntime.AppDomainAppPath, "EncryptionKey.pfx"), "password");

   // Decrypt the encrypted assertion.
   samlAssertion = encryptedAssertion.Decrypt(decryptionKey.PrivateKey, null);
}
else
{
   throw new ApplicationException("No encrypted assertions found in the SAML response");
}

How about decrypting encrypted attributes?

Very simple. All you need to do is to load a private key file for decrypting attributes and call the Decrypt method of the EncryptedAttribute class. The following code demonstrates how to do so.

// Load the SAML response from the XML document.
Response samlResponse = new Response(xmlDocument.DocumentElement);

// Access the first assertion object.
Assertion assertion = (Assertion)samlResponse.Assertions[0];

if (assertion.AttributeStatements[0].EncryptedAttributes.Count > 0)
{
   // Load the private key file.
   X509Certificate2 certificate = new X509Certificate2(privateCertificateFile, "password");

   // Loop through the encrypted attributes list.
   foreach (EncryptedAttribute encryptedAttribute in assertion.AttributeStatements[0].EncryptedAttributes)
   {
       // Get the encrypted key.
       EncryptedKey encryptedKey = encryptedAttribute.GetEncryptedKeyObjects()[0];

       // Decrypt the encrypted attribute.
       ComponentPro.Saml2.Attribute decryptedAttribute = encryptedAttribute.Decrypt(certificate.PrivateKey, encryptedKey, null);

       // ...
   }
}
else
{
   // Loop through the encrypted attributes list.
   foreach (ComponentPro.Saml2.Attribute attribute in assertion.AttributeStatements[0].Attributes)
   {
       // TODO: Your code here.

       // ...
   }
}




Qlik Sense: How to decrypt a SAML assertion or error message

How to decrypt a heavily encoded SAML message. 

If you have set up the Identity Provider to encrypt the SAML assertion, then in order to see what it contains for troubleshooting, you will need to decrypt it.

 
Environment:

Qlik Sense Enterprise on Windows  , all versions

It is important to understand the 3 below concepts when using SAML.

    Inflation and base-64 encoding
    Signing
    Encryption

 

A SAML AuthnRequest is:

    Inflated and base-64 encoded (If you use a SAML browser extension, it will deflate it and decode it automatically for you. In order to do that manually, https://www.samltool.com/decode.php can be used.)
    No private key is needed to deflate/decode.
    Signed, so that it cannot be altered. The signature does not hold any useful information for troubleshooting, it is just to make sure that the SAML request hasn't been altered. However if the certificate it has been signed with does not correspond, you won't be able to authenticate.
    The Qlik Sense certificate is needed to validate the signature on the SAML assertion. (Note: Qlik Sense always signs SAML AuthnRequest, this cannot be disabled, however SAML AuthnRequest signature validation can be disabled in the Identity Provider)



A SAML assertion (The assertion is a section in the SAML response) is:

    Inflated and base-64 encoded (If you use a SAML browser extension, it will deflate it and decode it automatically for you. In order to do that manually, https://www.samltool.com/decode.php can be used.)
    No private key is needed to deflate/decode.
    Signed, so that it cannot be altered. The signature does not hold any useful information for troubleshooting, it is just to make sure that the SAML request hasn't been altered. However if the certificate it has been signed with does not correspond, you won't be able to authenticate.
    The Identity Provider certificate is needed to validate the signature on the SAML assertion.
    Encrypted (Optionally). In this case, in order to see if information in the SAML assertion are correct, decrypting the SAML assertion is needed.
    It can be decrypted with https://www.samltool.com/decrypt.php, just paste the deflated/decoded SAML request.
    The Qlik Sense certificate private key is needed to see what the signature holds.
    The SAML response is generated by the Identity Provider and the public certificate of the Service Provider (Qlik Sense) is used to encrypt. You will need the private key of Qlik Sense to decrypt it.
     

Resolution:

    Go to https://www.samltool.com/decrypt.php
    In Encrypted XML, paste the deflated/decoded SAML response.
    In Private Key*, paste the private key of Qlik Sense.

* It must be the private key in clear text, not protected by a passphrase. A protected private key will begin with -----BEGIN ENCRYPTED PRIVATE KEY----- while a clear text private key will begin with -----BEGIN RSA PRIVATE KEY----- 

In order to decrypt a private key, you can use the command:
openssl rsa –in enc.key -out dec.key
You will be asked to enter the passphrase for your private key.

Please note that openssl must be installed and you should run this command from the command prompt in the folder where the binary for openssl is installed.


samltool1.png
 
Related Content:

How To Use SAML Authentication With Qlik Sense 
