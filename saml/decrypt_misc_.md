

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


#
##
##
#


Sign and Encrypt SAML Requests

To increase the security of your transactions, you can sign or encrypt both your requests and your responses in the SAML protocol. In this article, you'll find configurations for specific scenarios, separated under two use cases:

    Auth0 as the SAML service provider (for example, a SAML connection)

    Auth0 as the SAML identity provider (for example, an application configured with the SAML Web App addon)

Auth0 as the SAML service provider

These scenarios apply when Auth0 is the SAML Service Provider, which means that Auth0 connects to a SAML identity provider by creating a SAML connection.
Sign the SAML authentication request

If Auth0 is the SAML service provider, you can sign the authentication request Auth0 sends to the IdP as follows:

    Navigate to Auth0 Dashboard > Authentication > Enterprise, and select SAML.

    Select the name of the connection to view.

    Locate Sign Request, and enable its switch.

    Download the certificate beneath the Sign Request switch, and provide it to the IdP so that it can validate the signature.

Enable/disable deflate encoding

By default, SAML authentication requests are sent via HTTP-Redirect and use deflate encoding, which puts the signature in a query parameter.

To turn off deflate encoding, you can make a PATCH call to the Management API's Update a Connection endpoint and set the deflate option to false.

Updating the options object for a connection overrides the whole options object. To keep previous connection options, get the existing options object and add new key/values to it.

Endpoint: https://{yourDomain}/api/v2/connections/{yourConnectionId}

Payload:

{
	{ 
		"options" : {
			[...], // all the other connection options
		  "deflate": false
	}
}

Was this helpful?
/

Use a custom key to sign requests

By default, Auth0 uses the tenant private key to sign SAML requests (when the Sign Request toggle is enabled). You can also provide your own private/public key pair to sign requests coming from a specific connection.

You can generate your own certificate and private key using this command:

openssl req -x509 -nodes -sha256 -days 3650 -newkey rsa:2048 -keyout private_key.key -out certificate.crt

Was this helpful?
/

Changing the key used to sign requests in the connection can't be done on the Dashboard UI, so you will have to use the Update a Connection endpoint from the Management API v2, and add a signing_key property to the options object, as shown in the payload example below.

Updating the options object for a connection overrides the whole options object. To keep previous connection options, get the existing options object and add new key/values to it.

Endpoint: https://{yourDomain}/api/v2/connections/{yourConnectionId}

Payload:

{
	{ 
		"options" : {
			[...], // all the other connection options
		  "signing_key": {
				"key":"-----BEGIN PRIVATE KEY-----\n...{your private key here}...\n-----END PRIVATE KEY-----",
				"cert":"-----BEGIN CERTIFICATE-----\n...{your public key cert here}...\n-----END CERTIFICATE-----"
			}
    }
	}
}

Was this helpful?
/

To learn how to get the private key and certificate formatted as a JSON string to use in the payload, see Work with Certificates and Keys and Strings.
Receive signed SAML authentication responses

If Auth0 is the SAML service provider, all SAML responses from your identity provider should be signed to indicate it hasn't been tampered with by an unauthorized third-party.

You will need to configure Auth0 to validate the responses' signatures by obtaining a signing certificate form the identity provider and loading the certificate from the identity provider into your Auth0 Connection:

    Navigate to Auth0 Dashboard > Authentication > Enterprise, and select SAML.

    Select the name of the connection to view.

    Locate X509 Signing Certificate, and upload the certificate.

    Select Save Changes.

Auth0 can accept a signed response for the assertion, the response, or both.
Receive encrypted SAML authentication assertions

If Auth0 is the SAML service provider, it may need to receive encrypted assertions from an identity provider. To do this, you must provide the tenant's public key certificate to the IdP. The IdP encrypts the SAML assertion using the public key and sends it to Auth0, which decrypts it using the tenant's private key.

Use the following links to obtain the public key in different formats:

    CER

    PEM

    raw PEM

    PKCS#7

    Fingerprint

Download the certificate in the format requested by the IdP.
Use your key pair to decrypt encrypted responses

As noted above, Auth0 will by default use your tenant's private/public key pair to handle encryption. You can also provide your own public/private key pair if an advanced scenario requires so.

Changing the key pair used to encrypt and decrypt requests in the connection can't be done on the Dashboard UI, so you will have to use the Update a Connection endpoint from the Management API v2, and add a decryptionKey property to the options object, as shown in the payload example below.

Updating the options object for a connection overrides the whole options object. To keep previous connection options, get the existing options object and add new key/values to it.

Endpoint: https://{yourDomain}/api/v2/connections/{yourConnectionId}

Payload:

{
	{ 
		"options" : {
			[...], // all the other connection options
		  "decryptionKey": {
				"key":"-----BEGIN PRIVATE KEY-----\n...{your private key here}...\n-----END PRIVATE KEY-----",
				"cert":"-----BEGIN CERTIFICATE-----\n...{your public key cert here}...\n-----END CERTIFICATE-----"
			}
	}
}

Was this helpful?
/

The SAML metadata available for the connection will be updated with the provided certificate so that the identity provider can pick it up to sign the SAML response.
Auth0 as the SAML identity provider

This scenario applies when Auth0 is the SAML identity provider for an application. This is represented in the Dashboard by an Application that has the SAML Web App Addon enabled.
Sign the SAML responses/assertions

If Auth0 is the SAML identity provider, it will sign SAML assertions with the tenant's private key and provide the service provider with the public key/certificate necessary to validate the signature.

To sign the SAML assertions:

    Go to Auth0 Dashboard > Applications, and select the name of the application to view.

    Scroll to the bottom of the Settings page, select Show Advanced Settings, and select the Certificates view.

    Select Download Certificate, and select the format in which you'd like to receive your signing certificate.

    Send your certificate to the service provider.

By default, Auth0 signs the SAML assertion within the response. To sign the SAML response instead:

    Navigate to Auth0 Dashboard > Applications, and select the name of the application to view.

    Select the Addons view.

    Select SAML2 Web App to view its settings, and locate the Settings code block.

    Locate the "signResponse" key. Uncomment it (or add it, if required), then set its value to true (the default value is false). The configuration should look like this:

    {
      [...], // other settings
      "signResponse": true
    }

Was this helpful?
/

Change the signing key for SAML responses

By default, Auth0 will use the private/public key pair assigned to your tenant to sign SAML responses or assertions. For very specific scenarios, you might wish to provide your own key pair. You can do so with a rule like this:

function (user, context, callback) {
  // replace with the ID of the application that has the SAML Web App Addon enabled
	// for which you want to change the signing key pair.
	var samlIdpClientId = 'YOUR_SAML_APP_CLIENT_ID';
  // only for a specific client
  if (context.clientID !== samlIdpClientId) {
    return callback(null, user, context);
  }

	// provide your own private key and certificate here  
  context.samlConfiguration.cert = "-----BEGIN CERTIFICATE-----\nnMIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV[..all the other lines..]-----END CERTIFICATE-----\n";
  context.samlConfiguration.key = "-----BEGIN PRIVATE KEY-----\nnMIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV[..all the other lines..]-----END PRIVATE KEY-----\n";
      
  callback(null, user, context);
}

Was this helpful?
/

To learn how to turn the private key and certificate files into strings that you can use in a rule, see Work with Certificates and Keys and Strings.
Receive signed SAML authentication requests

If Auth0 is the SAML identity provider, it can receive requests signed with the service provider's private key. Auth0 uses the public key/certificate to validate the signature.

To configure signature validation:

    Download the service provider's certificate with the public key.

    Navigate to Auth0 Dashboard > Applications, and select the name of the application to view.

    Select the Addons view.

    Select SAML2 Web App to view its settings, and locate the Settings code block.

    Locate the "signingCert" key. Uncomment it (or add it, if required), then set its value to the certificate you downloaded from the service provider. The configuration should look like this:

    {
      [...], // other settings
      "signingCert": "-----BEGIN CERTIFICATE-----\nMIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV\n[..all the other lines..]-----END CERTIFICATE-----\n"
    }

Was this helpful?
/

Send encrypted SAML authentication assertions

If Auth0 is the SAML identity provider, you can use rules to encrypt the SAML assertions it sends.

You must obtain the certificate and the public key from the service provider. If you only got the certificate, you can derive the public key using openssl. Assuming that the certificate file is named certificate.pem, you can run:

openssl x509 -in certificate.pem -pubkey -noout > public_key.pem

Once you get the certificate and public key files, you must turn them into strings to use them in a rule. The rule will look like this:

function (user, context, callback) {
  // this rule sets a specific public key to encrypt the SAML assertion generated from Auth0 
  if (context.clientID === 'THE_CLIENT_ID_OF_THE_APP_WITH_THE_SAML_APP_ADDON') {
	  context.samlConfiguration = (context.samlConfiguration || {});
    context.samlConfiguration.encryptionPublicKey = "-----BEGIN PUBLIC KEY-----\nnMIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV\n[..all the other lines..]-----END PUBLIC KEY-----\n";
    context.samlConfiguration.encryptionCert = "-----BEGIN CERTIFICATE-----\nnnMIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV\n[..all the other lines..]-----END CERTIFICATE-----\n";
	}
  callback(null, user, context);
}

Was this helpful?
/

The following algorithms are used:

    AES256 for assertion encryption

    RSA-OAEP (including MGF1 and SHA1) for key transport




