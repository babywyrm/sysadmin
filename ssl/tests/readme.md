

SSL_Cipher_Test.md
```
Obtaining cipher list from OpenSSL 0.9.8zg 14 July 2015.
Testing ADH-SEED-SHA                   NO (sslv3 alert handshake failure)
Testing DHE-RSA-SEED-SHA               NO (sslv3 alert handshake failure)
Testing DHE-DSS-SEED-SHA               NO (sslv3 alert handshake failure)
Testing SEED-SHA                       NO (sslv3 alert handshake failure)
Testing ADH-AES256-SHA                 NO (sslv3 alert handshake failure)
Testing DHE-RSA-AES256-SHA             YES
Testing DHE-DSS-AES256-SHA             NO (sslv3 alert handshake failure)
Testing AES256-SHA                     NO (sslv3 alert handshake failure)
Testing ADH-AES128-SHA                 NO (sslv3 alert handshake failure)
Testing DHE-RSA-AES128-SHA             YES
Testing DHE-DSS-AES128-SHA             NO (sslv3 alert handshake failure)
Testing AES128-SHA                     NO (sslv3 alert handshake failure)
Testing ADH-DES-CBC3-SHA               NO (sslv3 alert handshake failure)
Testing ADH-DES-CBC-SHA                NO (sslv3 alert handshake failure)
Testing EXP-ADH-DES-CBC-SHA            NO (sslv3 alert handshake failure)
Testing ADH-RC4-MD5                    NO (sslv3 alert handshake failure)
Testing EXP-ADH-RC4-MD5                NO (sslv3 alert handshake failure)
Testing EDH-RSA-DES-CBC3-SHA           NO (sslv3 alert handshake failure)
Testing EDH-RSA-DES-CBC-SHA            NO (sslv3 alert handshake failure)
Testing EXP-EDH-RSA-DES-CBC-SHA        NO (sslv3 alert handshake failure)
Testing EDH-DSS-DES-CBC3-SHA           NO (sslv3 alert handshake failure)
Testing EDH-DSS-DES-CBC-SHA            NO (sslv3 alert handshake failure)
Testing EXP-EDH-DSS-DES-CBC-SHA        NO (sslv3 alert handshake failure)
Testing DES-CBC3-SHA                   NO (sslv3 alert handshake failure)
Testing DES-CBC-SHA                    NO (sslv3 alert handshake failure)
Testing EXP-DES-CBC-SHA                NO (sslv3 alert handshake failure)
Testing EXP-RC2-CBC-MD5                NO (sslv3 alert handshake failure)
Testing RC4-SHA                        NO (sslv3 alert handshake failure)
Testing RC4-MD5                        NO (sslv3 alert handshake failure)
Testing EXP-RC4-MD5                    NO (sslv3 alert handshake failure)
Testing DES-CBC3-MD5                   NO (sslv3 alert handshake failure)
Testing DES-CBC-MD5                    NO (sslv3 alert handshake failure)
Testing EXP-RC2-CBC-MD5                NO (sslv3 alert handshake failure)
Testing RC2-CBC-MD5                    NO (sslv3 alert handshake failure)
Testing EXP-RC4-MD5                    NO (sslv3 alert handshake failure)
Testing RC4-MD5                        NO (sslv3 alert handshake failure)
Testing NULL-SHA                       NO (sslv3 alert handshake failure)
Testing NULL-MD5                       NO (sslv3 alert handshake failure)
ssl_cipher_test.sh
```


```
#!/usr/bin/env bash

# OpenSSL requires the port number.
SERVER=${1:-127.0.0.1:443}
DELAY=1
ciphers=$(openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g')

echo Obtaining cipher list from $(openssl version).

for cipher in ${ciphers[@]}
do
#echo -n Testing $cipher...
result=$(echo -n | openssl s_client -cipher "$cipher" -connect $SERVER 2>&1)
if [[ "$result" =~ ":error:" ]] ; then
  error=$(echo -n $result | cut -d':' -f6)
  RES="NO ($error)"
else
  if [[ "$result" =~ "Cipher is ${cipher}" || "$result" =~ "Cipher    :" ]] ; then
    RES="YES"
  else
    RES="UNKNOWN RESPONSE: $result"
  fi
fi
printf "Testing %-30s %-30s\n" $cipher "$RES"
sleep $DELAY
done
```


##
##

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
