
There are several test ciphers available in OpenSSL that you can use locally on Linux. To list all the available ciphers, you can use the following command:

Copy code
openssl ciphers -v
This command will display a list of available ciphers and their properties. The output may be quite lengthy, but you can use grep to search for specific cipher suites. For example, to find all AES ciphers, you can use the following command:

perl
Copy code
openssl ciphers -v | grep AES
Here are some examples of commonly used test ciphers:

AES256-SHA256: AES cipher with a 256-bit key, using SHA-256 for message authentication
DES-CBC3-SHA: Triple-DES cipher with a 168-bit key, using SHA-1 for message authentication
ECDHE-RSA-AES256-GCM-SHA384: Elliptic curve Diffie-Hellman key exchange with RSA authentication, using AES-GCM with a 256-bit key and SHA-384 for message authentication
You can test these ciphers by using them with the openssl s_client command to connect to a server. For example, to test the AES256-SHA256 cipher, you can use the following command:

perl
Copy code
openssl s_client -connect example.com:443 -cipher AES256-SHA256
This command will connect to the server at example.com on port 443 using the AES256-SHA256 cipher. If the connection is successful, you should see information about the certificate and the negotiated cipher suite.


To display all CBC ciphers available to OpenSSL on Ubuntu, you can use the following command in the terminal:

python
Copy code
openssl ciphers -v 'CBC'
This command will list all the CBC ciphers supported by OpenSSL on your Ubuntu system. The output will include the cipher names and their corresponding key sizes and encryption algorithms.

Note that CBC ciphers have some known security weaknesses and are generally not recommended for use in modern encryption protocols. It's usually better to use ciphers that provide authenticated encryption, such as GCM or ChaCha20-Poly1305, which are available in OpenSSL and offer better security.

##
##
