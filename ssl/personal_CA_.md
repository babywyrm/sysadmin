
# How to setup your own CA with OpenSSL

For educational reasons I've decided to create my own CA.
Here is what I learned.

# First things first

Lets get some context first.

## Public Key Cryptography

AKA asymmetric cryptography solves the problem of two entities communicating
securely without ever exchanging a common key, by using two related keys,
one private, one public.

Ciphered text with the public key can only be deciphered by the corresponding
private key, and verifiable signatures with the public key can only be created
with the private key.

But if the two entities do not know each other yet they a way to know for sure
that a public key corresponds to the private key of the other identity.

In other words, when Alice speaks to Bob, Bob tells Alice "this is my public
key K, use it to communicate with me" Alice needs to know it is really Bob's
public key and not Eve's.

The usual solution to this problem is to use a PKI.

## Public Key Infrastructure - PKI

A PKI is an arrangement that binds public keys to identities by means of a
Certificate Authority (CA).

A CA is a centralized trusted third party whose public key is already known.

This way when Alice speaks to Bob, Bob shows Alice a signed message by Trent,
who Alice knows and trusts, that says "this public key K belongs to Bob".
That signed message is called a certificate, and it can contain other info.
Alice is able to verify the signature using Trent's public key, and can know
speak confidently to Bob.

It is also common to have a chain of trust. Alice speaks to Bob, Trent does
not know Bob but knows Carol who knows Bob, so Bob shows Alice a chain of
certificates, one from Carol that says which key belongs to Bob and one from
Trent who says which key belongs to Carol. Even without knowing Carol, Alice
can verify the certificate from Trent, be sure of Carol's key, and if her trust
in Trent is transitive then she can also trust Carol as to who Bob is.

**Note**:  
There is an interesting solution for public authentication of public-key
information is the [web-of-trust][wot] scheme, which uses third party
attestations of self-signed certificates.

## X.509

X.509 is a standard from the International Telecommunication Union for PKI.

Among other things, it defines the format for public key certificates.

Defined over these RFCs:

- Version 1 - [RFC1422][]
- Version 2 - [RFC2459][]
- Version 3 - [RFC5280][]

A X.509 v3 digital certificate has this structure:

- Certificate
    - Version
    - Serial Number
    - Algorithm ID
    - Issuer
    - Validity
        - Not Before
        - Not After
    - Subject
    - Subject public key info
    - Issuer Unique Identifier (optional)
    - Subject Unique Identifier (optional)
    - Extensions (optional)
        - ...
- Certificate Signature Algorithm
- Certificate Signature

### Version, Serial, Algorithm ID and Validity

- **Version** - Indicates X.509 version. Should be 3 (value 0x2).
- **Serial** - Unique positive integer assigned by the CA to each certificate.
- **Algorithm ID** - Must be the same as the field "Certificate Signature
Algorithm"
- **Validity** - Two dates that form the period when the certificate is valid.

### Issuer and Subject

Each a Distinguished Name (DN), unique per CA.

A DN, described in [RFC1779][], consists of a single line with these separated
values:

- CN - CommonName
- L - LocalityName
- ST - StateOrProvinceName
- O - OrganizationName
- OU - OrganizationalUnitName
- C - CountryName

Example:  
`C=PT, ST=Lisboa, L=Lisboa, O=Foo Org, OU=Bar Sector, CN=foo.org/emailAddress=admin@foo.org`

The signing CA may not require all values.

When connecting to an HTTPS server, browsers will check the CN value and it
should be conforming to the domain. Wildcard certificates usually start with
a `*` in CN to allow any subdomain. e.g. `CN=*.example.com`

Note that browsers will reject the wilcard for the naked domain, i.e.
`example.com` is not conforming to `*.example.com`.

However, a certificate can be used for an HTTPS server that replies in multiple
different domains. Additional domains can be specified in the extension
Subject Alternative Names.

#### Subject public key info

Contains the public key algorithm and its specific parameters. e.g.:

- algorithm: rsa encryption
- key size: 2048
- exponent: 0x10001
- modulus: 00:ec:82:3f:78:b6...

#### Issuer and Subject Unique Identifiers

Introduced in version 2 to permit the reuse of issuer and subject names.
For example, suppose a CA goes bankrupt and its name is deleted from the
country's public list, after some time another CA with the same name may
register itself even though it is unrelated to the first one.

IMO, this is all very silly.
Unsurprisingly, IETF recommends that no issuer and subject names be reused.

#### Extensions

Introduced in version 3.
A CA can use extensions to issue a certificate only for a specific purpose,
e.g only for http servers.

Extensions can be critical or non-critical. Non-critical can be ignored, while
critical must be enforced and the whole certificate must be rejected if the
system does not recognize a critical extension.

Some standard extensions:

- Subject Key Identifier
- Authority Key Identifier
- Subject Alternative Name
- Basic Constraints

##### Authority and Subject Key Identifiers

Used where an entity has multiple signing keys.
Identity can be verified by either name and serial number or by this key
identifier.

An identifier is the 160-bit SHA-1 hash of the public key, or just the first
60 bits preceded with the bits 0100.


##### Subject Alternative Name

May contain additional DNS names or IP addresses where the certificate is valid,
that is, besides the one specified in CN.

##### Basic Constraints

Whether the subject is a CA and optionally the maximum length of depth of
certification paths.

## A real world need

Let's suppose we need a signed certificate for an HTTPS server.
This means we need a certificate for the domain (or domains) where the server
will be available.

We need a certificate that the browser can verify and tell the user
that he is on the right servers of the domain of the URL he typed and
that a safe connection is established.

Browsers use a certificate store which has a list of CAs. To check your
you can go to your browser's settings, search for the Certificates section,
maybe in Security or Advanced, there should be some kind of certificate manager.

The browser's certificate store should have several sections, one of them,
probably empty is for client certificates, since HTTPS can also authenticate
the client through certificates, although this isn't used except for some
very specific corporate environments.
The section you want to look at is the 'Authorities' section where the CA
certificates are stored. Your browser most probably has certificates from VeriSign, Comodo, GeoTrust,
Microsoft, etc.

So what we need is a certificate that says our key belongs to our domain issued
(signed) by one of these entities. Or we can also have it issued by an
intermediary entity, one who was authorized by one of the CAs to issue
certificates.

If you do a web search for 'SSL Certificates' you'll find many sellers of
digital certificates. You'll find that "wildcard" certificates are usually
a bit  more expensive.

### Wildcard certificates

A wildcard certificate is a certificate which can be used with multiple
subdomains of a domain.

Browsers look for the CN (Common Name) in the subject field which should be a
domain, or a wildcard like `*.example.com`.

Browsers will accept a certificate with CN `*.example.org` for
`www.example.org`, `login.example.org` or `bo.example.org`. But the "naked"
domain `example.org` will not work.

Additional domains (including the naked domain) may be added in the extension
"SubjectAltName".

To check this out point your browser to `https://mozilla.org` (or some other
HTTPS server), then click the lock icon before the URL, there should be a way
to see the certificate being used. Check the subject Common Name and the
extension Subject Alt Name.

## OpenSSL

OpenSSL is a cryptography toolkit. Contains many subcommands, each with a
manpage of its own e.g. `ca(1)`, `req(1)` , `x509(1)`.

Most of OpenSSL's tools deal with `-in` and `-out` parameters. Usually you
can also inspect files by specifying `-in <file>` and `-noout`, you also
specify which part of the contents you're interested in, to see all use
`-text`. Examples below.


### Generate Keys and Certificate Signing Request (CSR)

Generate an RSA key for the CA:
```
$ openssl genrsa -out example.org.key 2048
Generating RSA private key, 2048 bit long modulus
.........................................+++
```

`openssl genrsa` is the tool to generate rsa keys. `2048` is the key size.
This created a file `example.org.key` that contains the private key.

You can use the tool `openssl rsa` to inspect the key.

```
$ openssl rsa -in example.org.key -noout -text
Private-Key: (2048 bit)
modulus:
    00:ad:d8:71:1f:ab:a7:df:a6:c3:7e:d8:1f:fd:81:
    b0:5a:a8:9d:51:2b:15:c2:98:95:9e:fe:3b:7c:bd:
    ...
publicExponent: 65537 (0x10001)
privateExponent:
    7b:a9:ba:96:b7:c9:bb:eb:69:a7:62:60:27:39:c8:
    d4:44:9b:5b:b0:d5:52:ce:ad:a8:22:da:f8:19:c2:
    ...
prime1:
    00:d3:98:05:f5:49:48:11:f1:46:71:09:6c:b4:cb:
    e6:3e:6f:a1:41:9a:36:43:c3:22:20:06:d1:aa:dd:
    ...
prime2:
    00:d2:54:5e:cc:15:72:3d:5f:b2:64:ab:4f:42:a6:
    15:79:ca:7a:e0:ef:dd:a7:f3:25:f2:f1:75:b2:33:
    ...
exponent1:
    02:bf:5f:9c:6e:c6:2b:cd:79:3f:b0:82:a3:da:5d:
    f4:03:99:11:74:02:2e:61:13:49:5d:2d:4d:cd:b1:
    ...
exponent2:
    79:6c:c1:e9:9a:3c:00:98:9d:b9:a6:78:b4:a6:83:
    61:73:76:ab:23:6f:58:c5:73:d4:24:77:e9:30:10:
    ...
coefficient:
    17:53:93:4a:48:b0:63:9a:71:0e:37:fb:18:ad:be:
    4e:d0:6e:af:6c:bc:7b:ff:44:c6:93:9a:23:03:51:
    ...
```

Optionally, the rsa public key can be extracted from the private key:

```
$ openssl rsa -in example.org.key -pubout -out example.org.pubkey
$ openssl rsa -in example.org.pubkey -pubin -noout -text
Public-Key: (2048 bit)
Modulus:
    00:ad:d8:71:1f:ab:a7:df:a6:c3:7e:d8:1f:fd:81:
    b0:5a:a8:9d:51:2b:15:c2:98:95:9e:fe:3b:7c:bd:
    ...
Exponent: 65537 (0x10001)
```

Any copy of the private key should only be help by the entity who is going to
be certified. This means the key should never be sent to anyone else,
**including the certificate issuer**.

We now generate a Certificate Signing Request which contains some of the info
that we want to be included in the certificate.
To prove ownership of the private key, the CSR is signed with the subject's
private key.

Generate a CSR:

```
$ openssl req -new -key example.org.key -out example.org.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:PT
State or Province Name (full name) [Some-State]:Lisboa
Locality Name (eg, city) []:Lisboa
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Example Org
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:*.example.org
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

We can then take a look at the CSR's contents:

```
$ openssl req -in example.org.csr -noout -text
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=PT, ST=Lisboa, L=Lisboa, O=Example Org, CN=*.example.org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ad:d8:71:1f:ab:a7:df:a6:c3:7e:d8:1f:fd:81:
                    b0:5a:a8:9d:51:2b:15:c2:98:95:9e:fe:3b:7c:bd:
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha1WithRSAEncryption
         5d:f0:d4:d8:85:4c:e7:dd:6d:f2:bd:05:0f:57:8b:d8:0a:40:
         09:10:ad:ab:cc:5b:a1:92:cb:5d:56:16:7f:0b:23:91:32:06:
         ...
```

The certificate is then sent to the issuer, and if he approves the request
a certificate should be sent back.

**Make sure** your Signature Algorithm is not MD5. Old OpenSSL configurations
have `default_md = md5` as default. Browsers reject certificates that use md5
as a signature algorithm because it has been [found to be insecure][md5harmful].

Notice that there are no extensions, to add extensions an additional config
file is needed. This makes the process a bit more complicated so when you
buy a wildcard certificate you don't usually need to specify the extension
SubjectAltName for the naked domain because the issuer will do it for you.

This is an example configuration file for a CSR:

```conf
# The main section is named req because the command we are using is req
# (openssl req ...)
[ req ]
# This specifies the default key size in bits. If not specified then 512 is
# used. It is used if the -new option is used. It can be overridden by using
# the -newkey option. 
default_bits = 2048

# This is the default filename to write a private key to. If not specified the
# key is written to standard output. This can be overridden by the -keyout
# option.
default_keyfile = oats.key

# If this is set to no then if a private key is generated it is not encrypted.
# This is equivalent to the -nodes command line option. For compatibility
# encrypt_rsa_key is an equivalent option. 
encrypt_key = no

# This option specifies the digest algorithm to use. Possible values include
# md5 sha1 mdc2. If not present then MD5 is used. This option can be overridden
# on the command line.
default_md = sha1

# if set to the value no this disables prompting of certificate fields and just
# takes values from the config file directly. It also changes the expected
# format of the distinguished_name and attributes sections.
prompt = no

# if set to the value yes then field values to be interpreted as UTF8 strings,
# by default they are interpreted as ASCII. This means that the field values,
# whether prompted from a terminal or obtained from a configuration file, must
# be valid UTF8 strings.
utf8 = yes

# This specifies the section containing the distinguished name fields to
# prompt for when generating a certificate or certificate request.
distinguished_name = my_req_distinguished_name


# this specifies the configuration file section containing a list of extensions
# to add to the certificate request. It can be overridden by the -reqexts
# command line switch. See the x509v3_config(5) manual page for details of the
# extension section format.
req_extensions = my_extensions

[ my_req_distinguished_name ]
C = PT
ST = Lisboa
L = Lisboa
O  = Oats In The Water
CN = *.oats.org

[ my_extensions ]
basicConstraints=CA:FALSE
subjectAltName=@my_subject_alt_names
subjectKeyIdentifier = hash

[ my_subject_alt_names ]
DNS.1 = *.oats.org
DNS.2 = *.oats.net
DNS.3 = *.oats.in
DNS.4 = oats.org
DNS.5 = oats.net
DNS.6 = oats.in
```

Notice the various DNS names. Since the configuration parser does not allow
multiple values for the same name we use the `@my_subject_alt_names` and
`DNS.#` with different numbers.

With this configuration we can create a CSR with the proper extensions:

```
$ openssl req -new -out oats.csr -config oats.conf
Generating a 2048 bit RSA private key
.............+++
....................................+++
writing new private key to 'oats.key'
-----
```

Because we did not specify a key, OpenSSL uses the information on our
configuration (`default_bits` and `default_keyfile`) to create one.

Lets see the result:

```
$ openssl req -in oats.csr -noout -text
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=PT, ST=Lisboa, L=Lisboa, O=Oats In The Water, CN=*.oats.org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a2:58:fc:57:32:4d:40:aa:62:92:65:86:1d:6b:
                    4f:3e:11:a6:b5:36:f2:48:d2:23:2a:8f:bb:a0:a4:
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
        Requested Extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Alternative Name: 
                DNS:*.oats.org, DNS:*.oats.net, DNS:*.oats.in, DNS:oats.org, DNS:oats.net, DNS:oats.in
            X509v3 Subject Key Identifier: 
                C6:0E:59:B3:1A:FF:1A:A2:FF:F3:DC:76:21:F0:92:FC:57:88:05:6D
    Signature Algorithm: sha1WithRSAEncryption
         0d:45:6c:21:65:20:72:68:30:91:5f:fa:b8:c3:62:a0:66:a2:
         96:6f:76:4a:ba:ca:e3:1d:9e:eb:47:d4:93:87:88:83:a2:f5:
         ...
```

Now we can see that there is a `Request Extensions` section with our coveted
`Subject Alternative Name` field.

A CA can still remove these fields or override them when issuing your
certificate. Including them in your CSR does not guarantee that they will be
in the final certificate.

### CA Key and self-signed Certificate

Now let's play the CA part.

Generate a key for the subject. It is the same as we did for our subject.

```
$ openssl genrsa -out ca.key 2048
Generating RSA private key, 2048 bit long modulus
......................................................+++
.......+++
e is 65537 (0x10001)
```

Generate a self signed certificate for the CA:

```
$ openssl req -new -x509 -key ca.key -out ca.crt
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:PT
State or Province Name (full name) [Some-State]:Lisboa
Locality Name (eg, city) []:Lisboa
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Sz CA
Organizational Unit Name (eg, section) []:SZ CA
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:An optional company name []:
```

OpenSSL uses the information you specify to compile a X.509 certificate using
the information prompted to the user, the public key that is extracted from the
specified private key which is also used to generate the signature.

If we wish to include extensions in the self-signed certificate we could use
a configuration file just like we did for the CSR but we would use
`x509_extensions` instead of `req_extensions`.

#### Signing

One very easy way to sign a certificate is this:

```
$ openssl x509 -req -in example.org.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out example.org.crt
Signature ok
subject=/C=PT/ST=Lisboa/L=Lisboa/O=Example Org/CN=*.example.org
Getting CA Private Key
```

Each issued certificate must contain a unique serial number assigned by the CA.
It must be unique for each certificate given by a given CA.
OpenSSL keeps the used serial numbers on a file, by default it has the same
name as the CA certificate file with the extension replace by `srl`.
So a file named `ca.srl` is created:

```
$ cat ca.srl
ED4B4A80662B1B4C
```

This command produces the file `example.org.crt` which we can examine:

```
$ openssl x509 -in example.org.crt -noout -text
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 17098842325572590412 (0xed4b4a80662b1b4c)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=PT, ST=Lisboa, L=Lisboa, O=Sz CA, OU=SZ CA
        Validity
            Not Before: Mar 20 22:46:43 2014 GMT
            Not After : Apr 19 22:46:43 2014 GMT
        Subject: C=PT, ST=Lisboa, L=Lisboa, O=Example Org, CN=*.example.org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ad:d8:71:1f:ab:a7:df:a6:c3:7e:d8:1f:fd:81:
                    b0:5a:a8:9d:51:2b:15:c2:98:95:9e:fe:3b:7c:bd:
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha1WithRSAEncryption
         05:21:5c:0f:4c:3c:9a:76:7f:3f:fb:fa:e0:09:03:05:c5:16:
         bf:4b:ac:60:d8:86:fc:b2:42:3e:5e:19:45:2a:e2:01:83:67:

```

Notice the serial number, in hex is exactly the contents of the created
`ca.srl` file.

I then setup an https server using the certificate and the key on port 1443
using [bud][]. Bud is a TLS terminator, i.e. it unwraps https incoming
connections and proxies them into a backend server as simple http. I forwarded
bud connections into a static http server with a very simple `index.html`.

I also added the line `127.0.0.1 www.example.org` to my `/etc/hosts` to make my
machine resolve the domain into the loopback address.

I then pointed my browser to `https://www.example.org:1443/`. The browser
immediately complained that certificate was invalid because it did not include
the signing chain. What this means is the certificate says that the entity
`C=PT, ST=Lisboa, L=Lisboa, O=Example Org, CN=*.example.org` is certified by
the entity `C=PT, ST=Lisboa, L=Lisboa, O=Sz CA, OU=SZ CA` but there is no
information as to who certifies this second entity, and since the entity is not
known by the browser the certificate is deemed invalid.

One thing we can do is create another file that contains the example.org
certificate and the ca certificate.

```
$ cat example.org.crt ca.crt > example.org.bundle.crt
```

I did this and then my browser, Firefox, still rejected the certificate, but
now with a different message. Now it complained that the SZ CA was not a
trusted entity.

So I opened my browser settings, and added the ca certificate to the
Authorities section in the certificate store. And now it works!

![](https://i.cloudup.com/OhL6UKbvkM.png)

Well... The browser doesn't give any warning. But it doesn't show the green
icon you're probably already used to seing

![](https://i.cloudup.com/tpp1u2bPAr.png)

This is because of [extended validation][], an extension we did not include in
the certificate that usually requires the CA to verify the legal identification
of the subject. Just to check it, we can ask the browser to export the
certificate into a file we can query with openssl:

```
$ openssl x509 -in github.com.crt -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:7f:be:2e:4b:de:00:84:d2:ca:f8:e3:ec:fe:70:58
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV CA-1
        Validity
            Not Before: Jun 10 00:00:00 2013 GMT
            Not After : Sep  2 12:00:00 2015 GMT
        Subject: businessCategory=Private Organization/1.3.6.1.4.1.311.60.2.1.3=US/1.3.6.1.4.1.311.60.2.1.2=Delaware/serialNumber=5157550/street=548 4th Street/postalCode=94107, C=US, ST=California, L=San Francisco, O=GitHub, Inc., CN=github.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ed:d3:89:c3:5d:70:72:09:f3:33:4f:1a:72:74:
                    d9:b6:5a:95:50:bb:68:61:9f:f7:fb:1f:19:e1:da:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:4C:58:CB:25:F0:41:4F:52:F4:28:C8:81:43:9B:A6:A8:A0:E6:92:E5

            X509v3 Subject Key Identifier: 
                87:D1:8F:19:6E:E4:87:6F:53:8C:77:91:07:50:DF:A3:BF:55:47:20
            X509v3 Subject Alternative Name: 
                DNS:github.com, DNS:www.github.com
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://crl3.digicert.com/evca1-g2.crl

                Full Name:
                  URI:http://crl4.digicert.com/evca1-g2.crl

            X509v3 Certificate Policies: 
                Policy: 2.16.840.1.114412.2.1
                  CPS: http://www.digicert.com/ssl-cps-repository.htm
                  User Notice:
                    Explicit Text: 

            Authority Information Access: 
                OCSP - URI:http://ocsp.digicert.com
                CA Issuers - URI:http://cacerts.digicert.com/DigiCertHighAssuranceEVCA-1.crt

            X509v3 Basic Constraints: critical
                CA:FALSE
    Signature Algorithm: sha1WithRSAEncryption
         5f:15:6d:67:c3:3a:d5:a3:de:16:9c:45:33:26:d5:3d:c9:16:
         74:34:ca:87:48:1b:14:90:6d:f5:ab:47:86:b9:f5:b8:e3:01:
         ...
```

The relevant extension for Extended Validation (EV) is `Certificate Policies`.

Certificate sellers will refuse to issue wildcard certificates with EV, because
cabforum.org, the regulatory body governing the issuance of EV SSL Certificates
decided this is a big no no. EV certificates can, however, have as much
SubjectAltName as you wish.

#### `openssl ca`

You can also sign CSRs with the `ca(1)`.

First we need a configuration file `ca.conf`:

```
# we use 'ca' as the default section because we're usign the ca command
# we use 'ca' as the default section because we're usign the ca command
[ ca ]
default_ca = my_ca

[ my_ca ]
#  a text file containing the next serial number to use in hex. Mandatory.
#  This file must be present and contain a valid serial number.
serial = ./serial

# the text database file to use. Mandatory. This file must be present though
# initially it will be empty.
database = ./index.txt

# specifies the directory where new certificates will be placed. Mandatory.
new_certs_dir = ./newcerts

# the file containing the CA certificate. Mandatory
certificate = ./ca.crt

# the file contaning the CA private key. Mandatory
private_key = ./ca.key

# the message digest algorithm. Remember to not use MD5
default_md = sha1

# for how many days will the signed certificate be valid
default_days = 365

# a section with a set of variables corresponding to DN fields
policy = my_policy

[ my_policy ]
# if the value is "match" then the field value must match the same field in the
# CA certificate. If the value is "supplied" then it must be present.
# Optional means it may be present. Any fields not mentioned are silently
# deleted.
countryName = match
stateOrProvinceName = supplied
organizationName = supplied
commonName = supplied
organizationalUnitName = optional
commonName = supplied

[ ca ]
default_ca = my_ca

[ my_ca ]
#  a text file containing the next serial number to use in hex. Mandatory.
#  This file must be present and contain a valid serial number.
serial = ./serial

# the text database file to use. Mandatory. This file must be present though
# initially it will be empty.
database = ./index.txt

# specifies the directory where new certificates will be placed. Mandatory.
new_certs_dir = ./newcerts

# the file containing the CA certificate. Mandatory
certificate = ./ca.crt

# the file contaning the CA private key. Mandatory
private_key = ./ca.key

# the message digest algorithm. Remember to not use MD5
default_md = sha1

# for how many days will the signed certificate be valid
default_days = 365

# a section with a set of variables corresponding to DN fields
policy = my_policy

[ my_policy ]
# if the value is "match" then the field value must match the same field in the
# CA certificate. If the value is "supplied" then it must be present.
# Optional means it may be present. Any fields not mentioned are silently
# deleted.
countryName = match
stateOrProvinceName = supplied
organizationName = supplied
commonName = supplied
organizationalUnitName = optional
commonName = supplied

```

Remember, you can use `man ca` not only to see details about flags and command
usage but also about the respective configuration sections and settings.

We need to setup some structure first. The configuration file expects a
`newcerts` directory, and the `index.txt` and `serial` files:

```
$ mkdir newcerts
$ touch index.txt
$ echo '01' > serial
```

And now we can finally sign the certificate:

```
$ openssl ca -config ca.cnf -out example.org.crt -infiles example.org.csr
Using configuration from ca.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'PT'
stateOrProvinceName   :ASN.1 12:'Lisboa'
localityName          :ASN.1 12:'Lisboa'
organizationName      :ASN.1 12:'Example Org'
commonName            :ASN.1 12:'*.example.org'
Certificate is to be certified until Mar 21 01:13:36 2015 GMT (365 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Data Base Updated
```

If we wish to add extensions, or even to keep the extensions sent in a CSR
(openssl will remove them when signing), then we need to also include that
configuration.

This is an extra configuration file `oats.extensions.cnf`:

```
basicConstraints=CA:FALSE
subjectAltName=@my_subject_alt_names
subjectKeyIdentifier = hash

[ my_subject_alt_names ]
DNS.1 = *.oats.org
DNS.2 = *.oats.net
DNS.3 = *.oats.in
DNS.4 = oats.org
DNS.5 = oats.net
DNS.6 = oats.in
```

And now:

```
$ openssl ca -config ca.cnf -out oats.crt -extfile oats.extensions.cnf -in oats.csr
Using configuration from ca.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'PT'
stateOrProvinceName   :PRINTABLE:'Lisboa'
localityName          :PRINTABLE:'Lisboa'
organizationName      :PRINTABLE:'Oats In The Water'
commonName            :T61STRING:'*.oats.org'
Certificate is to be certified until Mar 21 01:43:11 2015 GMT (365 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Data Base Updated
```

We have a certificate that includes the SubjectAltNames we wanted:

```
$ openssl x509 -in oats.crt -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=PT, ST=Lisboa, L=Lisboa, O=Sz CA, OU=SZ CA
        Validity
            Not Before: Mar 21 01:43:11 2014 GMT
            Not After : Mar 21 01:43:11 2015 GMT
        Subject: C=PT, ST=Lisboa, O=Oats In The Water, CN=*.oats.org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a2:58:fc:57:32:4d:40:aa:62:92:65:86:1d:6b:
                    4f:3e:11:a6:b5:36:f2:48:d2:23:2a:8f:bb:a0:a4:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Alternative Name: 
                DNS:*.oats.org, DNS:*.oats.net, DNS:*.oats.in, DNS:oats.org, DNS:oats.net, DNS:oats.in
            X509v3 Subject Key Identifier: 
                C6:0E:59:B3:1A:FF:1A:A2:FF:F3:DC:76:21:F0:92:FC:57:88:05:6D
    Signature Algorithm: sha1WithRSAEncryption
         89:7e:7d:67:1e:98:85:78:a1:f2:81:4c:b4:8c:f9:80:cd:47:
         a9:94:94:a3:f0:dd:36:d3:e3:48:93:77:4a:31:16:03:79:9c:
         ...
```

We can verify the certificate is correct:

```
$ openssl verify -CAfile ca.crt oats.crt
oats.crt: OK
```

# That is all

I know there a whole lot of stuff I didn't cover, important things like CRL.
I'm sorry for that. This whole deal looks really messy and I hope we can ditch
it for something better in the future.

[RFC1422]: https://tools.ietf.org/html/rfc1422
[RFC1779]: https://tools.ietf.org/html/rfc1779
[RFC2459]: https://tools.ietf.org/html/rfc2459
[RFC5280]: https://tools.ietf.org/html/rfc5280
[wot]: https://en.wikipedia.org/wiki/Web_of_trust
[md5harmful]: http://www.win.tue.nl/hashclash/rogue-ca/
[bud]: https://github.com/indutny/bud
[extended validation]: https://en.wikipedia.org/wiki/Extended_Validation_Certificate
