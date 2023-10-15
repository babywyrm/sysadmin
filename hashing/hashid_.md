
Resources

Various useful resources

    psypanda/hashID (original hashID)
    wikipedia.org - List of hash functions
    hashcat.net
        wiki
        wiki example hashes
    openwall.com - John the Ripper
        community wiki

Hash Types

Quick reference for all hash types checked by this application and values for hashcat and John the Ripper.

> ./hashcat.exe -m {mode}
$ john --format={format}
Show
entries
Search:
Type	hashcat	John
1Password(Agile Keychain) 	6600 	
1Password(Cloud Keychain) 	8200 	
Adler-32 		
AIX(smd5) 	6300 	aix-smd5
AIX(ssha1) 	6700 	aix-ssha1
AIX(ssha256) 	6400 	aix-ssha256
AIX(ssha512) 	6500 	aix-ssha512
Android FDE ≤ 4.3 	8800 	fde
Android PIN 	5800 	
Apache MD5 	1600 	
bcrypt 	3200 	bcrypt
bcrypt(SHA-256) 		
BigCrypt 		bigcrypt
Blowfish(OpenBSD) 	3200 	bcrypt
BSDi Crypt 		bsdicrypt
Cisco Type 4 		cisco4
Cisco Type 7 		
Cisco Type 8 	9200 	cisco8
Cisco Type 9 	9300 	cisco9
Cisco VPN Client(PCF-File) 		
Cisco-ASA(MD5) 	2410 	asa-md5
Cisco-IOS(MD5) 	500 	md5crypt
Cisco-IOS(SHA-256) 	5700 	
Cisco-PIX(MD5) 	2400 	pix-md5
Citrix Netscaler 	8100 	citrix_ns10
Clavister Secure Gateway 		
CRAM-MD5 	10200 	
CRC-16 		
CRC-16-CCITT 		
CRC-24 		
CRC-32 		crc32
CRC-32B 		
CRC-64 		
CRC-96(ZIP) 		
Crypt16 		
CryptoCurrency(Adress) 		
CryptoCurrency(PrivateKey) 		
Dahua 		dahua
DES(Oracle) 	3100 	
DES(Unix) 	1500 	descrypt
DEScrypt 	1500 	descrypt
Django(bcrypt) 		
Django(bcrypt-SHA256) 		
Django(DES Crypt Wrapper) 		
Django(MD5) 		
Django(PBKDF2-HMAC-SHA1) 		
Django(PBKDF2-HMAC-SHA256) 	10000 	django
Django(SHA-1) 	124 	
Django(SHA-256) 		
Django(SHA-384) 		
DNSSEC(NSEC3) 	8300 	
Domain Cached Credentials 	1100 	mscach
Domain Cached Credentials 2 	2100 	mscach2
Double MD5 	2600 	
Double SHA-1 	4500 	
Drupal > v7.x 	7900 	drupal7
Eggdrop IRC Bot 		bfegg
ELF-32 		
EPi 	123 	
EPiServer 6.x < v4 	141 	episerver
EPiServer 6.x ≥ v4 	1441 	episerver
Fairly Secure Hashed Password 		
FCS-16 		
FCS-32 		
Fletcher-32 		
FNV-132 		
FNV-164 		
Fortigate(FortiOS) 	7000 	fortigate
FreeBSD MD5 	500 	md5crypt
GHash-32-3 		
GHash-32-5 		
GOST CryptoPro S-Box 		
GOST R 34.11-94 	6900 	gost
GRUB 2 	7200 	
Half MD5 	5100 	
HAS-160 		
Haval-128 		haval-128-4
Haval-160 		
Haval-192 		
Haval-224 		
Haval-256 		haval-256-3
HMAC-MD5 (key = $pass) 	50 	hmac-md5
HMAC-MD5 (key = $salt) 	60 	hmac-md5
HMAC-SHA1 (key = $pass) 	150 	hmac-sha1
HMAC-SHA1 (key = $salt) 	160 	hmac-sha1
HMAC-SHA256 (key = $pass) 	1450 	hmac-sha256
HMAC-SHA256 (key = $salt) 	1460 	hmac-sha256
HMAC-SHA512 (key = $pass) 	1750 	hmac-sha512
HMAC-SHA512 (key = $salt) 	1760 	hmac-sha512
hMailServer 	1421 	hmailserver
IKE-PSK MD5 	5300 	
IKE-PSK SHA1 	5400 	
IP.Board ≥ v2+ 	2811 	
IPMI2 RAKP HMAC-SHA1 	7300 	
iSCSI CHAP Authentication 	4800 	chap
Joaat 		
Joomla < v2.5.18 	11 	
Joomla ≥ v2.5.18 	400 	phpass
Juniper Netscreen/SSG(ScreenOS) 	22 	md5ns
Kerberos 5 AS-REQ Pre-Auth 	7500 	krb5pa-md5
Lastpass 	6800 	
LDAP(SSHA-512) 	1711 	ssha512
Lineage II C4 		
LinkedIn 	190 	raw-sha1-linkedin
LM 	3000 	lm
Lotus Notes/Domino 5 	8600 	lotus5
Lotus Notes/Domino 6 	8700 	dominosec
Lotus Notes/Domino 8 	9100 	
MangosWeb Enhanced CMS 		
MD2 		md2
MD4 	900 	raw-md4
MD5 	0 	raw-md5
MD5 Crypt 	500 	md5crypt
md5($pass.$salt) 	10 	
md5($pass.md5($salt)) 	3720 	
md5($salt.$pass) 	20 	
md5($salt.$pass.$salt) 	3810 	
md5($salt.md5($pass)) 	3710 	
md5($salt.md5($pass.$salt)) 	4110 	
md5($salt.md5($salt.$pass)) 	4010 	
md5($salt.unicode($pass)) 	40 	
md5($username.0.$pass) 	4210 	
MD5(APR) 	1600 	
MD5(Chap) 	4800 	chap
md5(md5($pass).md5($salt)) 	3910 	
md5(md5($salt).$pass) 	3610 	
md5(md5(md5($pass))) 	3500 	
md5(sha1($pass)) 	4400 	
md5(strtoupper(md5($pass))) 	4300 	
md5(unicode($pass).$salt) 	30 	
md5apr1 	1600 	
MediaWiki 	3711 	mediawiki
Microsoft MSTSC(RDP-File) 		
Microsoft Office 2007 	9400 	office
Microsoft Office 2010 	9500 	
Microsoft Office 2013 	9600 	
Microsoft Office ≤ 2003 (MD5+RC4) 	9700 	oldoffice
Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1 	9710 	oldoffice
Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2 	9720 	oldoffice
Microsoft Office ≤ 2003 (SHA1+RC4) 	9800 	
Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1 	9810 	
Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2 	9820 	
Microsoft Outlook PST 		
Minecraft(AuthMe Reloaded) 		
Minecraft(xAuth) 		
MSSQL(2000) 	131 	mssql
MSSQL(2005) 	132 	mssql05
MSSQL(2008) 	132 	mssql05
MSSQL(2012) 	1731 	msql12
MSSQL(2014) 	1731 	msql12
MyBB ≥ v1.2+ 	2811 	
MySQL Challenge-Response Authentication (SHA1) 	11200 	
MySQL323 	200 	mysql
MySQL4.1 	300 	mysql-sha1
MySQL5.x 	300 	mysql-sha1
NetNTLMv1-VANILLA / NetNTLMv1+ESS 	5500 	netntlm
NetNTLMv2 	5600 	netntlmv2
Netscape LDAP SHA 	101 	nsldap
Netscape LDAP SSHA 	111 	nsldaps
nsldaps 	111 	nsldaps
NTHash(FreeBSD Variant) 		
NTLM 	1000 	nt
Oracle 11g/12c 	112 	oracle11
Oracle 7-10g 	3100 	
osCommerce 	21 	
OSX v10.4 	122 	xsha
OSX v10.5 	122 	xsha
OSX v10.6 	122 	xsha
OSX v10.7 	1722 	xsha512
OSX v10.8 	7100 	pbkdf2-hmac-sha512
OSX v10.9 	7100 	pbkdf2-hmac-sha512
Palshop CMS 		
PBKDF2(Atlassian) 		
PBKDF2(Cryptacular) 		
PBKDF2(Dwayne Litzenberger) 		
PBKDF2-HMAC-SHA256(PHP) 	10900 	
PBKDF2-SHA1(Generic) 		
PBKDF2-SHA256(Generic) 		pbkdf2-hmac-sha256
PBKDF2-SHA512(Generic) 		
PDF 1.4 - 1.6 (Acrobat 5 - 8) 	10500 	pdf
PeopleSoft 	133 	
PHPass' Portable Hash 	400 	phpass
PHPass' Portable Hash 	400 	phpass
phpBB v3.x 	400 	phpass
PHPS 	2612 	phps
PostgreSQL Challenge-Response Authentication (MD5) 	11100 	postgres
PostgreSQL MD5 		
PrestaShop 	11000 	
RACF 	8500 	racf
RAdmin v2.x 	9900 	radmin
Redmine Project Management Web App 	7600 	
RIPEMD-128 		ripemd-128
RIPEMD-160 	6000 	ripemd-160
RIPEMD-256 		
RIPEMD-320 		
Salsa10 		
Salsa20 		
SAM(LM_Hash:NT_Hash) 		
SAP CODVN B (BCODE) 	7700 	sapb
SAP CODVN F/G (PASSCODE) 	7800 	sapg
SAP CODVN H (PWDSALTEDHASH) iSSHA-1 	10300 	saph
SCRAM Hash 		
scrypt 	8900 	
SHA-1 	100 	raw-sha1
SHA-1 Crypt 		sha1crypt
SHA-1(Base64) 	101 	nsldap
SHA-1(Oracle) 		
SHA-224 		raw-sha224
SHA-256 	1400 	raw-sha256
SHA-256 Crypt 	7400 	sha256crypt
SHA-384 	10800 	raw-sha384
SHA-512 	1700 	raw-sha512
SHA-512 Crypt 	1800 	sha512crypt
sha1($pass.$salt) 	110 	
sha1($salt.$pass) 	120 	
sha1($salt.$pass.$salt) 	4710 	
sha1($salt.unicode($pass)) 	140 	
sha1(md5($pass)) 	4700 	
sha1(sha1(sha1($pass))) 	4600 	
sha1(unicode($pass).$salt) 	130 	
sha256($pass.$salt) 	1410 	
sha256($salt.$pass) 	1420 	
sha256($salt.unicode($pass)) 	1440 	
sha256(unicode($pass).$salt) 	1430 	
SHA3-224 		
SHA3-256 	5000 	raw-keccak-256
SHA3-384 		
SHA3-512 		raw-keccak
sha512($pass.$salt) 	1710 	
sha512($salt.$pass) 	1720 	
sha512($salt.unicode($pass)) 	1740 	
sha512(unicode($pass).$salt) 	1730 	
Siemens-S7 		siemens-s7
SipHash 	10100 	
Skein-1024 		
Skein-1024(384) 		
Skein-1024(512) 		
Skein-256 		skein-256
Skein-256(128) 		
Skein-256(160) 		
Skein-256(224) 		
Skein-512 		skein-512
Skein-512(128) 		
Skein-512(160) 		
Skein-512(224) 		
Skein-512(256) 		
Skein-512(384) 		
Skype 	23 	
SMF ≥ v1.1 	121 	
Snefru-128 		snefru-128
Snefru-256 		snefru-256
SSHA-1(Base64) 	111 	nsldaps
SSHA-512(Base64) 	1711 	ssha512
Sun MD5 Crypt 	3300 	sunmd5
Sybase ASE 	8000 	sybasease
Tiger-128 		
Tiger-160 		
Tiger-192 		tiger
Traditional DES 	1500 	descrypt
vBulletin < v3.8.5 	2611 	
vBulletin ≥ v3.8.5 	2711 	
Ventrilo 		
VNC 		vnc
WebEdition CMS 	3721 	
Whirlpool 	6100 	whirlpool
Woltlab Burning Board 3.x 	8400 	wbb3
Woltlab Burning Board 4.x 		
Wordpress v2.6.0/2.6.1 	400 	phpass
Wordpress ≥ v2.6.2 	400 	phpass
XOR-32 		
xt:Commerce 	21 	
ZipMonster




##
##
##
##

##
#
https://www.freecodecamp.org/news/hacking-with-hashcat-a-practical-guide/
#
##

Hashing is one of the pillars of cybersecurity. From securing passwords to sensitive data, there are a variety of use cases for hashing.

Hashing is often confused with encryption. A simple difference is that hashed data is not reversible. Encrypted data can be reversed using a key. This is why applications like Telegram use encryption while passwords are hashed.

In this article, we will look at installing and working with Hashcat. Hashcat is a simple but powerful command line utility that helps us to – you guessed it – crack hashes.

We will first start by looking at how hashing works in detail.

    Note: All my articles are for educational purposes. If you use this information illegally and get into trouble, I am not responsible. Always get permission from the owner before scanning / brute-forcing / exploiting a system.

What is Password Hashing?

Hashing is the process of converting an alphanumeric string into a fixed-size string by using a hash function. A hash function is a mathematical function that takes in the input string and generates another alphanumeric string.
image-14
How hashing works


There are many hashing algorithms like MD5, SHA1, and so on. To learn more about different hashing algorithms, you can read the article here.

The length of a hash is always a constant, irrespective of the length of the input. For example, if we use the MD5 algorithm and hash two strings like “Password123” and “HelloWorld1234”, the final hash will have a fixed length.

Here is the MD5 hash for “Password123”.

42f749ade7f9e195bf475f37a44cafcb

If we use the input string as “HelloWorld1234”, this will be the result:

850eaebd5c4bb931dbb2bbcf7994c021

Now there is a similar algorithm called encoding. A popular encoding algorithm is base64. Here is how the same “Password123” will look if we encode it with base64:

UGFzc3dvcmQxMjM=

So what is the difference between hashing and encoding? When we encode a string, it can be easily decoded to get the source string. But if we hash a string, we can never get to the source string (maybe with quantum computers, but that's another topic for discussion).

Hashing and encoding have different use cases. We can apply encoding to mask/simplify strings while hashing is used to secure sensitive data like passwords.

If hashes are not reversible, how would we compare the strings? Simple – we compare the hashes.

When we signup for a website, they will hash our password before saving it (hopefully!). When we try to log in again, the same hashing algorithm is used to generate a hash for our input. It is then compared with the original hash saved in the database.

This approach is also what gives rise to hashing attacks. A simple way to attack hashes is to have a list of common passwords hashed together. This list is called a Rainbow table. Interesting name for a table of hashes.

Now that we know how hashing works, let's look at what Hashcat is.
What is Hashcat?

Hashcat is a fast password recovery tool that helps break complex password hashes. It is a flexible and feature-rich tool that offers many ways of finding passwords from hashes.

Hashcat is also one of the few tools that can work with the GPU. While CPUs are great for sequential tasks, GPUs have powerful parallel processing capabilities. GPUs are used in Gaming, Artificial intelligence, and can also be used to speed up password cracking.

Here is the difference between a CPU and a GPU if you want to learn more.

Other notable features of Hashcat include:

    Fully open source.
    Support for more than 200 hashing algorithms.
    Support for Windows, Linux, and Mac.
    Support for cracking multiple hashes in parallel.
    Built-in benchmarking system.

Now that we know what Hashcat is, let's go and install it.
How to Install Hashcat

Hashcat comes pre-installed in Kali and Parrot OS. To install it in Ubuntu / Debian-based systems, use the following command:

$ apt install hashcat

To install it on a Mac, you can use Homebrew. Here is the command:

$ brew install hashcat

For other operating systems, a full list of installation instructions can be found here.

Once the installation is done, we can check Hashcat’s help menu using this command:

$ hashcat -h

image-15
Hashcat help menu

In addition to Hashcat, we will also need a wordlist. A word list is a list of commonly used terms. This can be a password wordlist, username wordlist, subdomain wordlist, and so on.

A popular password wordlist is rockyou.txt. It contains a list of commonly used passwords and is popular among pen testers. You can find the Rockyou wordlist under /usr/share/wordlists in Kali Linux.
How to Work with Hashcat

Now that we know what hashing and Hashcat are, let’s start cracking some passwords.

Before cracking a hash, let's create a couple of hashes to work with. We can use a site like Browserling to generate hashes for input strings.

Let’s create two hashes: A MD5 hash and a SHA1 hash for the string “Password123”. I'm using a weak password to help you understand how easy it is to crack these passwords.

Here are the generated hashes for the input strings.

MD5 hash -> 42f749ade7f9e195bf475f37a44cafcb
SHA1 hash -> b2e98ad6f6eb8508dd6a14cfa704bad7f05f6fb1

We can store these hashes under the names md5.txt and sha1.txt to use them when working with Hashcat.

To crack a password using Hashcat, here is the general syntax.

$ hashcat -m value -a value hashfile wordlist

Let’s dissect the syntax. We have used two flags, -m and -a . The -m flag is used to specify the hash type and the -a flag is to specify the attack mode. You can find the list of hash types and attack modes here.

Let’s crack our md5 hash first. We will crack this hash using the Dictionary mode. This is a simple attack where we provide a list of words (RockYou) from which Hashcat will generate and compare hashes.

We can specify the hash mode as “md5” using the value 0. But Hashcat can also identify the hash type automatically for common hash algorithms.

For the attack mode, we will be using the dictionary mode (0) using the flag -a. Here is the full command:

$ hashcat -m 0 -a 0 md5.txt rockyou.txt

Hashcat will quickly find the value for the hash, in this case, “Password123”:
image-16
Hashcat MD5 crack

Looks simple, doesn't it? Now let’s crack our SHA hash. The hash mode value for SHA1 is 100. Here is the command:

$ hashcat -m 100 -a 0 sha1.txt rockyou.txt

And here is the output from Hashcat:
image-17
Hashcat SHA1 crack

Hashcat supports almost all hashing algorithms with various attack modes. Let's look at a few attack modes and see how they work.
Dictionary attack (-a 0)

As we saw in our example above, a dictionary attack is performed by using a wordlist. A dictionary attack is also the default option in Hashcat. The better the wordlist is, the greater the chances of cracking the password.
Combinator attack (-a 1)

The combinator attack will try different combinations of words from our wordlist. For example, if our wordlist contains the words “pass”, ”123", and ”hello”, Hashcat will generate the following wordlist.

passpass
pass123
passhello
123pass
123123
123hello
hellopass
hello123
hellohello

As you can see, using a simple wordlist can give us a number of combinations. This attack is great if we know some terms that might be used in the password. Keep in mind that, the larger the initial wordlist, the more complicated the final wordlist gets.
Mask attack (-a 3)

The mask attack is similar to the dictionary attack, but it is more specific. Brute-force approaches like dictionary attacks can take a long time to crack a password. But if we have information regarding the password, we can use that to speed up the time it takes to crack the password.

For example, if we know the length of the password and a few characters that might be in the password, we can generate a custom wordlist with those characters.

The mask attack is out of scope for this article, but you can learn more about mask attacks here.

In addition to these common attack types, there are more attack modes in Hashcat. This includes Hybrid mode, Permutation attack, Rule-based attack, and so on. Each of these modes can be used for specific use cases and to speed up password cracking.
How to Defend Against Hashcat

The first and obvious step is to set strong passwords. The stronger the password is, the harder it is to crack it. You can check if your password has been exposed to the internet here.

A more effective way is to add salts to password hashes. A salt is an additional string added to the existing password so the hash generated is different from the normal hash of a string.

For example, if a string “sdf909” is added to a password “Password123”, Rainbow table attacks will immediately fail since they don't have hashes with the salt added to them.

To crack a salted password, the attacker should know both the hash and salt values. This makes it harder to crack hashes using methods such as Rainbow tables.

We can further strengthen salting by using dynamic salts instead of static salts. We can write a function that generates a salt value for every string making it exponentially harder to crack a salted password.

You can read this article to learn more about how Salts work in password hashing.
