<!-- markdownlint-disable MD025 -->

# Hashcat Example hashes

Unless otherwise noted, the password for all example hashes is **hashcat**

|Hash-Mode|Hash-Name|Example|
|:--------|:--------|:------|
|0|MD5|8743b52063cd84097a65d1633f5c74f5|
|10|md5(\$pass.\$salt)|01dfae6e5d4d90d9892622325959afbe:7050461|
|20|md5(\$salt.\$pass)|f0fda58630310a6dd91a7d8f0a4ceda2:4225637426|
|30|md5(utf16le(\$pass).\$salt)|b31d032cfdcf47a399990a71e43c5d2a:144816|
|40|md5(\$salt.utf16le(\$pass))|d63d0e21fdc05f618d55ef306c54af82:13288442151473|
|50|HMAC-MD5 (key = \$pass)|fc741db0a2968c39d9c2a5cc75b05370:1234|
|60|HMAC-MD5 (key = \$salt)|bfd280436f45fa38eaacac3b00518f29:1234|
|70|md5(utf16le(\$pass))|2303b15bfa48c74a74758135a0df1201|
|100|SHA1|b89eaac7e61417341b710b727768294d0e6a277b|
|110|sha1(\$pass.\$salt)|2fc5a684737ce1bf7b3b239df432416e0dd07357:2014|
|120|sha1(\$salt.\$pass)|cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024|
|130|sha1(utf16le(\$pass).\$salt)|c57f6ac1b71f45a07dbd91a59fa47c23abcd87c2:631225|
|140|sha1(\$salt.utf16le(\$pass))|5db61e4cd8776c7969cfd62456da639a4c87683a:8763434884872|
|150|HMAC-SHA1 (key = \$pass)|c898896f3f70f61bc3fb19bef222aa860e5ea717:1234|
|160|HMAC-SHA1 (key = \$salt)|d89c92b4400b15c39e462a8caa939ab40c3aeeea:1234|
|170|sha1(utf16le(\$pass))|b9798556b741befdbddcbf640d1dd59d19b1e193|
|200|MySQL323|7196759210defdc0|
|300|MySQL4.1/MySQL5|fcf7c1b8749cf99d88e5f34271d636178fb5d130|
|400|phpass, WordPress (MD5),
 Joomla (MD5)|\$P\$984478476IagS59wHZvyQMArzfx58u.|
|400|phpass, phpBB3 (MD5)|\$H\$984478476IagS59wHZvyQMArzfx58u.|
|500|md5crypt, MD5 (Unix), Cisco-IOS \$1\$ (MD5) [^2]|\$1\$28772684\$iEwNOgGugqO9.bIz5sk8k/|
|501|Juniper IVE|3u+UR6n8AgABAAAAHxxdXKmiOmUoqKnZlf8lTOhlPYy93EAkbPfs5+49YLFd/B1+omSKbW7DoqNM40/EeVnwJ8kYoXv9zy9D5C5m5A==|
|600|BLAKE2b-512|\$BLAKE2\$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e|
|900|MD4|afe04867ec7a3845145579a95f72eca7|
|1000|NTLM|b4b9b02e6f09a9bd760f388b67351e2b|
|1100|Domain Cached Credentials (DCC), MS Cache|4dd8965d1d476fa0d026722989a6b772:3060147285011|
|1300|SHA2-224|e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198|
|1400|SHA2-256|127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935|
|1410|sha256(\$pass.\$salt)|c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528|
|1420|sha256(\$salt.\$pass)|eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617|
|1430|sha256(utf16le(\$pass).\$salt)|4cc8eb60476c33edac52b5a7548c2c50ef0f9e31ce656c6f4b213f901bc87421:890128|
|1440|sha256(\$salt.utf16le(\$pass))|a4bd99e1e0aba51814e81388badb23ecc560312c4324b2018ea76393ea1caca9:12345678|
|1450|HMAC-SHA256 (key = \$pass)|abaf88d66bf2334a4a8b207cc61a96fb46c3e38e882e6f6f886742f688b8588c:1234|
|1460|HMAC-SHA256 (key = \$salt)|8efbef4cec28f228fa948daaf4893ac3638fbae81358ff9020be1d7a9a509fc6:1234|
|1470|sha256(utf16le(\$pass))|9e9283e633f4a7a42d3abc93701155be8afe5660da24c8758e7d3533e2f2dc82|
|1500|descrypt, DES (Unix), Traditional DES|48c/R8JAv757A|
|1600|Apache \$apr1\$ MD5, md5apr1, MD5 (APR) [^2]|\$apr1\$71850310\$gh9m4xcAn3MGxogwX/ztb.|
|1700|SHA2-512|82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f|
|1710|sha512(\$pass.\$salt)|e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260|
|1720|sha512(\$salt.\$pass)|976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127|
|1730|sha512(utf16le(\$pass).\$salt)|13070359002b6fbb3d28e50fba55efcf3d7cc115fe6e3f6c98bf0e3210f1c6923427a1e1a3b214c1de92c467683f6466727ba3a51684022be5cc2ffcb78457d2:341351589|
|1740|sha512(\$salt.utf16le(\$pass))|bae3a3358b3459c761a3ed40d34022f0609a02d90a0d7274610b16147e58ece00cd849a0bd5cf6a92ee5eb5687075b4e754324dfa70deca6993a85b2ca865bc8:1237015423|
|1750|HMAC-SHA512 (key = \$pass)|94cb9e31137913665dbea7b058e10be5f050cc356062a2c9679ed0ad6119648e7be620e9d4e1199220cd02b9efb2b1c78234fa1000c728f82bf9f14ed82c1976:1234|
|1760|HMAC-SHA512 (key = \$salt)|7cce966f5503e292a51381f238d071971ad5442488f340f98e379b3aeae2f33778e3e732fcc2f7bdc04f3d460eebf6f8cb77da32df25500c09160dd3bf7d2a6b:1234|
|1770|sha512(utf16le(\$pass))|79bba09eb9354412d0f2c037c22a777b8bf549ab12d49b77d5b25faa839e4378d8f6fa11aceb6d9413977ae5ad5d011568bad2de4f998d75fd4ce916eda83697|
|1800|sha512crypt \$6\$, SHA512 (Unix) [^2]|\$6\$52450745\$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/|
|2000|STDOUT|n/a|
|2100|Domain Cached Credentials 2 (DCC2), MS Cache 2|\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f|
|2400|Cisco-PIX MD5|dRRVnUmUHXOTt9nk|
|2410|Cisco-ASA MD5|02dMBMYkTdC5Ziyp:36|
|2500|WPA-EAPOL-PBKDF2 [^1]|[https://hashcat.net/misc/example\_hashes/hashcat.hccapx](https://hashcat.net/misc/example_hashes/hashcat.hccapx "https://hashcat.net/misc/example_hashes/hashcat.hccapx")|
|2501|WPA-EAPOL-PMK [^14]|[https://hashcat.net/misc/example\_hashes/hashcat-pmk.hccapx](https://hashcat.net/misc/example_hashes/hashcat-pmk.hccapx "https://hashcat.net/misc/example_hashes/hashcat-pmk.hccapx")|
|2600|md5(md5(\$pass))|a936af92b0ae20b1ff6c3347a72e5fbe|
|3000|LM|299bd128c1101fd6|
|3100|Oracle H: Type (Oracle 7+)|7A963A529D2E3229:3682427524|
|3200|bcrypt \$2\*\$, Blowfish (Unix)|\$2a\$05\$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6|
|3500|md5(md5(md5(\$pass)))|9882d0778518b095917eb589f6998441|
|3710|md5(\$salt.md5(\$pass))|95248989ec91f6d0439dbde2bd0140be:1234|
|3800|md5(\$salt.\$pass.\$salt)|2e45c4b99396c6cb2db8bda0d3df669f:1234|
|3910|md5(md5(\$pass).md5(\$salt))|250920b3a5e31318806a032a4674df7e:1234|
|4010|md5(\$salt.md5(\$salt.\$pass))|30d0cf4a5d7ed831084c5b8b0ba75b46:1234|
|4110|md5(\$salt.md5(\$pass.\$salt))|b4cb5c551a30f6c25d648560408df68a:1234|
|4300|md5(strtoupper(md5(\$pass)))|b8c385461bb9f9d733d3af832cf60b27|
|4400|md5(sha1(\$pass))|288496df99b33f8f75a7ce4837d1b480|
|4500|sha1(sha1(\$pass))|3db9184f5da4e463832b086211af8d2314919951|
|4510|sha1(sha1(\$pass).\$salt)|9138d472fce6fe50e2a32da4eec4ecdc8860f4d5:hashcat1|
|4520|sha1(\$salt.sha1(\$pass))|a0f835fdf57d36ebd8d0399cc44e6c2b86a1072b:511358214352751667201107073531735211566650747315|
|4700|sha1(md5(\$pass))|92d85978d884eb1d99a51652b1139c8279fa8663|
|4710|sha1(md5(\$pass).\$salt)|53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1|
|4800|iSCSI CHAP authentication, MD5(CHAP) [^7]|afd09efdd6f8ca9f18ec77c5869788c3:01020304050607080910111213141516:01|
|4900|sha1(\$salt.\$pass.\$salt)|85087a691a55cbb41ae335d459a9121d54080b80:488387841|
|5000|sha1(sha1(\$salt.\$pass.\$salt))|05ac0c544060af48f993f9c3cdf2fc03937ea35b:232725102020|
|5100|Half MD5|8743b52063cd8409|
|5200|Password Safe v3|[https://hashcat.net/misc/example\_hashes/hashcat.psafe3](https://hashcat.net/misc/example_hashes/hashcat.psafe3 "https://hashcat.net/misc/example_hashes/hashcat.psafe3")|
|5300|IKE-PSK MD5|[https://hashcat.net/misc/example\_hashes/hashcat.ikemd5](https://hashcat.net/misc/example_hashes/hashcat.ikemd5 "https://hashcat.net/misc/example_hashes/hashcat.ikemd5")|
|5400|IKE-PSK SHA1|[https://hashcat.net/misc/example\_hashes/hashcat.ikesha1](https://hashcat.net/misc/example_hashes/hashcat.ikesha1 "https://hashcat.net/misc/example_hashes/hashcat.ikesha1")|
|5500|NetNTLMv1 / NetNTLMv1+ESS|u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c|
|5600|NetNTLMv2|admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030|
|5700|Cisco-IOS type 4 (SHA256)|2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI|
|5800|Samsung Android Password/PIN|0223b799d526b596fe4ba5628b9e65068227e68e:f6d45822728ddb2c|
|6000|RIPEMD-160|012cb9b334ec1aeb71a9c8ce85586082467f7eb6|
|6100|Whirlpool|7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258|
|6211|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_aes.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes.tc")|
|6211|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent.tc")|
|6211|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_twofish.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish.tc")|
|6212|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_aes-twofish.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish.tc")|
|6213|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_aes-twofish-serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish-serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish-serpent.tc")|
|6212|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-AES|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_serpent-aes.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-aes.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-aes.tc")|
|6213|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_serpent-twofish-aes.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-twofish-aes.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-twofish-aes.tc")|
|6212|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_twofish-serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish-serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish-serpent.tc")|
|6221|TrueCrypt 5.0+ SHA512 + AES|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_aes.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_aes.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_aes.tc")|
|6221|TrueCrypt 5.0+ SHA512 + Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent.tc")|
|6221|TrueCrypt 5.0+ SHA512 + Twofish|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_twofish.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_twofish.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_twofish.tc")|
|6222|TrueCrypt 5.0+ SHA512 + AES-Twofish|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_aes-twofish.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_aes-twofish.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_aes-twofish.tc")|
|6223|TrueCrypt 5.0+ SHA512 + AES-Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_aes-twofish-serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_aes-twofish-serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_aes-twofish-serpent.tc")|
|6222|TrueCrypt 5.0+ SHA512 + Serpent-AES|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_serpent-aes.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent-aes.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent-aes.tc")|
|6223|TrueCrypt 5.0+ SHA512 + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_serpent-twofish-aes.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent-twofish-aes.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent-twofish-aes.tc")|
|6222|TrueCrypt 5.0+ SHA512 + Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_sha512\_twofish-serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_sha512_twofish-serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_sha512_twofish-serpent.tc")|
|6231|TrueCrypt 5.0+ Whirlpool + AES|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_aes.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes.tc")|
|6231|TrueCrypt 5.0+ Whirlpool + Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent.tc")|
|6231|TrueCrypt 5.0+ Whirlpool + Twofish|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_twofish.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_twofish.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_twofish.tc")|
|6232|TrueCrypt 5.0+ Whirlpool + AES-Twofish|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_aes-twofish.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes-twofish.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes-twofish.tc")|
|6233|TrueCrypt 5.0+ Whirlpool + AES-Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_aes-twofish-serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes-twofish-serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes-twofish-serpent.tc")|
|6232|TrueCrypt 5.0+ Whirlpool + Serpent-AES|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_serpent-aes.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent-aes.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent-aes.tc")|
|6233|TrueCrypt 5.0+ Whirlpool + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_serpent-twofish-aes.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent-twofish-aes.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent-twofish-aes.tc")|
|6232|TrueCrypt 5.0+ Whirlpool + Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/hashcat\_whirlpool\_twofish-serpent.tc](https://hashcat.net/misc/example_hashes/hashcat_whirlpool_twofish-serpent.tc "https://hashcat.net/misc/example_hashes/hashcat_whirlpool_twofish-serpent.tc")|
|6241|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_aes\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes_boot.tc")|
|6241|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_serpent\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent_boot.tc")|
|6241|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_twofish\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish_boot.tc")|
|6242|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_aes-twofish\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish_boot.tc")|
|6243|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish-Serpent + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_aes-twofish-serpent\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish-serpent_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish-serpent_boot.tc")|
|6242|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-AES + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_serpent-aes\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-aes_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-aes_boot.tc")|
|6243|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-Twofish-AES + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_serpent-twofish-aes\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-twofish-aes_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-twofish-aes_boot.tc")|
|6242|TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish-Serpent + boot|[https://hashcat.net/misc/example\_hashes/hashcat\_ripemd160\_twofish-serpent\_boot.tc](https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish-serpent_boot.tc "https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish-serpent_boot.tc")|
|6300|AIX {smd5}|{smd5}a5/yTL/u\$VfvgyHx1xUlXZYBocQpQY0|
|6400|AIX {ssha256}|{ssha256}06\$aJckFGJAB30LTe10\$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2|
|6500|AIX {ssha512}|{ssha512}06\$bJbkFGJAB30L2e23\$bXiXjyH5YGIyoWWmEVwq67nCU5t7GLy9HkCzrodRCQCx3r9VvG98o7O3V0r9cVrX3LPPGuHqT5LLn0oGCuI1..|
|6600|1Password, agilekeychain|[https://hashcat.net/misc/example\_hashes/hashcat.agilekeychain](https://hashcat.net/misc/example_hashes/hashcat.agilekeychain "https://hashcat.net/misc/example_hashes/hashcat.agilekeychain")|
|6700|AIX {ssha1}|{ssha1}06\$bJbkFGJAB30L2e23\$dCESGOsP7jaIIAJ1QAcmaGeG.kr|
|6800|LastPass + LastPass sniffed[^4]|a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com|
|6900|GOST R 34.11-94|df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9|
|7000|FortiGate (FortiOS)|AK1AAECAwQFBgcICRARNGqgeC3is8gv2xWWRony9NJnDgE=|
|7200|GRUB 2|grub.pbkdf2.sha512.10000.7d391ef48645f626b427b1fae06a7219b5b54f4f02b2621f86b5e36e83ae492bd1db60871e45bc07925cecb46ff8ba3db31c723c0c6acbd4f06f60c5b246ecbf.26d59c52b50df90d043f070bd9cbcd92a74424da42b3666fdeb08f1a54b8f1d2f4f56cf436f9382419c26798dc2c209a86003982b1e5a9fcef905f4dfaa4c524|
|7300|IPMI2 RAKP HMAC-SHA1|b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef|
|7400|sha256crypt \$5\$, SHA256 (Unix) [^2]|\$5\$rounds=5000\$GX7BopJZJxPc/KEK\$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD|
|7500|Kerberos 5, etype 23, AS-REQ Pre-Auth|\$krb5pa\$23\$user\$realm\$salt\$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835|
|7700|SAP CODVN B (BCODE)|USER\$C8B48F26B87B7EA7|
|7701|SAP CODVN B (BCODE) from RFC\_READ\_TABLE|027642760180\$77EC386300000000|
|7800|SAP CODVN F/G (PASSCODE)|USER\$ABCAD719B17E7F794DF7E686E563E9E2D24DE1D0|
|7801|SAP CODVN F/G (PASSCODE) from RFC\_READ\_TABLE|604020408266\$32837BA7B97672BA4E5A00000000000000000000|
|7900|Drupal7|\$S\$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf|
|8000|Sybase ASE|0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2|
|8100|Citrix NetScaler (SHA1)|1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea|
|8200|1Password, cloudkeychain|[https://hashcat.net/misc/example\_hashes/hashcat.cloudkeychain](https://hashcat.net/misc/example_hashes/hashcat.cloudkeychain "https://hashcat.net/misc/example_hashes/hashcat.cloudkeychain")|
|8300|DNSSEC (NSEC3)|7b5n74kq8r441blc2c5qbbat19baj79r:.lvdsiqfj.net:33164473:1|
|8400|WBB3 (Woltlab Burning Board)|8084df19a6dc81e2597d051c3d8b400787e2d5a9:6755045315424852185115352765375338838643|
|8500|RACF|\$racf\$\*USER\*FC2577C6EBE6265B|
|8600|Lotus Notes/Domino 5|3dd2e1e5ac03e230243d58b8c5ada076|
|8700|Lotus Notes/Domino 6|(GDpOtD35gGlyDksQRxEU)|
|8800|Android FDE \<= 4.3|[https://hashcat.net/misc/example\_hashes/hashcat.android43fde](https://hashcat.net/misc/example_hashes/hashcat.android43fde "https://hashcat.net/misc/example_hashes/hashcat.android43fde")|
|8900|scrypt|SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=|
|9000|Password Safe v2|[https://hashcat.net/misc/example\_hashes/hashcat.psafe2.dat](https://hashcat.net/misc/example_hashes/hashcat.psafe2.dat "https://hashcat.net/misc/example_hashes/hashcat.psafe2.dat")|
|9100|Lotus Notes/Domino 8|(HsjFebq0Kh9kH7aAZYc7kY30mC30mC3KmC30mCluagXrvWKj1)|
|9200|Cisco-IOS \$8\$ (PBKDF2-SHA256)|\$8\$TnGX/fE4KGHOVU\$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk|
|9300|Cisco-IOS \$9\$ (scrypt)|\$9\$2MJBozw/9R3UsU\$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6|
|9400|MS Office 2007|\$office\$\*2007\*20\*128\*16\*411a51284e0d0200b131a8949aaaa5cc\*117d532441c63968bee7647d9b7df7d6\*df1d601ccf905b375575108f42ef838fb88e1cde|
|9500|MS Office 2010|\$office\$\*2010\*100000\*128\*16\*77233201017277788267221014757262\*b2d0ca4854ba19cf95a2647d5eee906c\*e30cbbb189575cafb6f142a90c2622fa9e78d293c5b0c001517b3f5b82993557|
|9600|MS Office 2013|\$office\$\*2013\*100000\*256\*16\*7dd611d7eb4c899f74816d1dec817b3b\*948dc0b2c2c6c32f14b5995a543ad037\*0b7ee0e48e935f937192a59de48a7d561ef2691d5c8a3ba87ec2d04402a94895|
|9700|MS Office ⇐ 2003 MD5 + RC4, oldoffice\$0, oldoffice\$1|\$oldoffice\$1\*04477077758555626246182730342136\*b1b72ff351e41a7c68f6b45c4e938bd6\*0d95331895e99f73ef8b6fbc4a78ac1a|
|9710|MS Office ⇐ 2003 \$0/\$1, MD5 + RC4, collider \#1|\$oldoffice\$0\*55045061647456688860411218030058\*e7e24d163fbd743992d4b8892bf3f2f7\*493410dbc832557d3fe1870ace8397e2|
|9720|MS Office ⇐ 2003 \$0/\$1, MD5 + RC4, collider \#2|\$oldoffice\$0\*55045061647456688860411218030058\*e7e24d163fbd743992d4b8892bf3f2f7\*493410dbc832557d3fe1870ace8397e2:91b2e062b9|
|9800|MS Office ⇐ 2003 SHA1 + RC4, oldoffice\$3, oldoffice\$4|\$oldoffice\$3\*83328705222323020515404251156288\*2855956a165ff6511bc7f4cd77b9e101\*941861655e73a09c40f7b1e9dfd0c256ed285acd|
|9810|MS Office ⇐ 2003 \$3, SHA1 + RC4, collider \#1|\$oldoffice\$3\*83328705222323020515404251156288\*2855956a165ff6511bc7f4cd77b9e101\*941861655e73a09c40f7b1e9dfd0c256ed285acd|
|9820|MS Office ⇐ 2003 \$3, SHA1 + RC4, collider \#2|\$oldoffice\$3\*83328705222323020515404251156288\*2855956a165ff6511bc7f4cd77b9e101\*941861655e73a09c40f7b1e9dfd0c256ed285acd:b8f63619ca|
|9900|Radmin2|22527bee5c29ce95373c4e0f359f079b|
|10000|Django (PBKDF2-SHA256)|pbkdf2\_sha256\$20000\$H0dPx8NeajVu\$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=|
|10100|SipHash|ad61d78c06037cd9:2:4:81533218127174468417660201434054|
|10200|CRAM-MD5|\$cram\_md5\$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==\$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==|
|10300|SAP CODVN H (PWDSALTEDHASH) iSSHA-1|{x-issha, 1024}C0624EvGSdAMCtuWnBBYBGA0chvqAflKY74oEpw/rpY=|
|10400|PDF 1.1 - 1.3 (Acrobat 2 - 4)|\$pdf\$1\*2\*40\*-1\*0\*16\*51726437280452826511473255744374\*32\*9b09be05c226214fa1178342673d86f273602b95104f2384b6c9b709b2cbc058\*32\*0000000000000000000000000000000000000000000000000000000000000000|
|10410|PDF 1.1 - 1.3 (Acrobat 2 - 4), collider \#1|\$pdf\$1\*2\*40\*-1\*0\*16\*01221086741440841668371056103222\*32\*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74\*32\*0000000000000000000000000000000000000000000000000000000000000000|
|10420|PDF 1.1 - 1.3 (Acrobat 2 - 4), collider \#2|\$pdf\$1\*2\*40\*-1\*0\*16\*01221086741440841668371056103222\*32\*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74\*32\*0000000000000000000000000000000000000000000000000000000000000000:6a8aedccb7|
|10500|PDF 1.4 - 1.6 (Acrobat 5 - 8)|\$pdf\$2\*3\*128\*-1028\*1\*16\*da42ee15d4b3e08fe5b9ecea0e02ad0f\*32\*c9b59d72c7c670c42eeb4fca1d2ca15000000000000000000000000000000000\*32\*c4ff3e868dc87604626c2b8c259297a14d58c6309c70b00afdfb1fbba10ee571|
|10600|PDF 1.7 Level 3 (Acrobat 9)|\$pdf\$5\*5\*256\*-1028\*1\*16\*20583814402184226866485332754315\*127\*f95d927a94829db8e2fbfbc9726ebe0a391b22a084ccc2882eb107a74f7884812058381440218422686648533275431500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\*127\*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\*32\*0000000000000000000000000000000000000000000000000000000000000000\*32\*0000000000000000000000000000000000000000000000000000000000000000|
|10700|PDF 1.7 Level 8 (Acrobat 10 - 11)|\$pdf\$5\*6\*256\*-1028\*1\*16\*21240790753544575679622633641532\*127\*2d1ecff66ea354d3d34325a6503da57e03c199c21b13dd842f8d515826054d8d2124079075354457567962263364153200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\*127\*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\*32\*0000000000000000000000000000000000000000000000000000000000000000\*32\*0000000000000000000000000000000000000000000000000000000000000000|
|10800|SHA2-384|07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42|
|10810|sha384(\$pass.\$salt)|ca1c843a7a336234baf9db2e10bc38824ce523402fbd7741286b1602bdf6cb869a45289bb9fb706bd404b9f3842ff729:2746460797049820734631508|
|10820|sha384(\$salt.\$pass)|63f63d7f82d4a4cb6b9ff37a6bc7c5ec39faaf9c9078551f5cbf7960e76ded87b643d37ac53c45bc544325e7ff83a1f2:93362|
|10830|sha384(utf16le(\$pass).\$salt)|3516a589d2ed4071bf5e36f22e11212b3ad9050b9094b23067103d51e99dcb25c4dc397dba8034fed11a8184acfbb699:577730514588712|
|10840|sha384(\$salt.utf16le(\$pass))|316e93ea8e04de3e5a909c53d36923a31a16c1b9e89b44201d6082f87ca49c5bca53cad65f685207db3ea2ccc7ca40f8:700067651|
|10870|sha384(utf16le(\$pass))|48e61d68e93027fae35d405ed16cd01b6f1ae66267833b4a7aa1759e45bab9bba652da2e4c07c155a3d8cf1d81f3a7e8|
|10900|PBKDF2-HMAC-SHA256|sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt|
|10901|RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)|{PBKDF2\_SHA256}AAAgADkxMjM2NTIzMzgzMjQ3MjI4MDAwNTk5OTAyOTk4NDI2MjkyMzAzNjg0NjQwOTMxNjI3OTMzNjg0MDI0OTY5NTe5ULagRTYpLaUoeqJMg8x9W/DXu+9VTFaVhaYvebYrY+sOqn1ZMRnws22C1uAkiE2tFM8qN+xw5xe7OmCPZ203NuruK4oB33QlsKIEz4ppm0TR94JB9PJx7lIQwFHD3FUNUNryj4jk6UYyJ4+V1Z9Ug/Iy/ylQBJgfs5ihzgxHYZrfp1wUCXFzlZG9mxmziPm8VFnAhaX4+FBAZvLAx33jpbKOwEg7TmwP2VJ8BNFLQRqwYdlqIjQlAhncXH+dqIF9VdM4MonAA0hx76bMvFTP7LF5VO1IqVmcuYz7YG9v4KKRjnvoUUqOj6okUBQTay3EzsdFVnUW1FemYOccJd5|
|11000|PrestaShop|810e3d12f0f10777a679d9ca1ad7a8d9:M2uZ122bSHJ4Mi54tXGY0lqcv1r28mUluSkyw37ou5oia4i239ujqw0l|
|11100|PostgreSQL CRAM (MD5)|\$postgres\$postgres\*f0784ea5\*2091bb7d4725d1ca85e8de6ec349baf6|
|11200|MySQL CRAM (SHA1)|\$mysqlna\$1c24ab8d0ee94d70ab1f2e814d8f0948a14d10b9\*437e93572f18ae44d9e779160c2505271f85821d|
|11300|Bitcoin/Litecoin wallet.dat|\$bitcoin\$96\$d011a1b6a8d675b7a36d0cd2efaca32a9f8dc1d57d6d01a58399ea04e703e8bbb44899039326f7a00f171a7bbc854a54\$16\$1563277210780230\$158555\$96\$628835426818227243334570448571536352510740823233055715845322741625407685873076027233865346542174\$66\$625882875480513751851333441623702852811440775888122046360561760525|
|11400|SIP digest authentication (MD5)|\$sip\$\*192.168.100.100\*192.168.100.121\*username\*asterisk\*REGISTER\*sip\*192.168.100.121\*\*2b01df0b\*\*\*\*MD5\*ad0520061ca07c120d7e8ce696a6df2d|
|11500|CRC32 [^5]|c762de4a:00000000|
|11600|7-Zip|\$7z\$0\$19\$0\$salt\$8\$f6196259a7326e3f0000000000000000\$185065650\$112\$98\$f3bc2a88062c419a25acd40c0c2d75421cf23263f69c51b13f9b1aada41a8a09f9adeae45d67c60b56aad338f20c0dcc5eb811c7a61128ee0746f922cdb9c59096869f341c7a9cb1ac7bb7d771f546b82cf4e6f11a5ecd4b61751e4d8de66dd6e2dfb5b7d1022d2211e2d66ea1703f96|
|11700|GOST R 34.11-2012 (Streebog) 256-bit, big-endian|57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36|
|11750|HMAC-Streebog-256 (key = \$pass), big-endian|0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337|
|11760|HMAC-Streebog-256 (key = \$salt), big-endian|d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337|
|11800|GOST R 34.11-2012 (Streebog) 512-bit, big-endian|5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3|
|11850|HMAC-Streebog-512 (key = \$pass), big-endian|be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337|
|11860|HMAC-Streebog-512 (key = \$salt), big-endian|bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337|
|11900|PBKDF2-HMAC-MD5|md5:1000:MTg1MzA=:Lz84VOcrXd699Edsj34PP98+f4f3S0rTZ4kHAIHoAjs=|
|12000|PBKDF2-HMAC-SHA1|sha1:1000:MzU4NTA4MzIzNzA1MDQ=:19ofiY+ahBXhvkDsp0j2ww==|
|12100|PBKDF2-HMAC-SHA512|sha512:1000:ODQyMDEwNjQyODY=:MKaHNWXUsuJB3IEwBHbm3w==|
|12200|eCryptfs|\$ecryptfs\$0\$1\$7c95c46e82f364b3\$60bba503f0a42d0c|
|12300|Oracle T: Type (Oracle 12+)|78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225|
|12400|BSDi Crypt, Extended DES|\_9G..8147mpcfKT8g0U.|
|12500|RAR3-hp|\$RAR3\$\*0\*45109af8ab5f297a\*adbf6c5385d7a40373e8f77d7b89d317|
|12600|ColdFusion 10+|aee9edab5653f509c4c63e559a5e967b4c112273bc6bd84525e630a3f9028dcb:5136256866783777334574783782810410706883233321141647265340462733|
|12700|Blockchain, My Wallet|\$blockchain\$288\$5420055827231730710301348670802335e45a6f5f631113cb1148a6e96ce645ac69881625a115fd35256636d0908217182f89bdd53256a764e3552d3bfe68624f4f89bb6de60687ff1ebb3cbf4e253ee3bea0fe9d12d6e8325ddc48cc924666dc017024101b7dfb96f1f45cfcf642c45c83228fe656b2f88897ced2984860bf322c6a89616f6ea5800aadc4b293ddd46940b3171a40e0cca86f66f0d4a487aa3a1beb82569740d3bc90bc1cb6b4a11bc6f0e058432cc193cb6f41e60959d03a84e90f38e54ba106fb7e2bfe58ce39e0397231f7c53a4ed4fd8d2e886de75d2475cc8fdc30bf07843ed6e3513e218e0bb75c04649f053a115267098251fd0079272ec023162505725cc681d8be12507c2d3e1c9520674c68428df1739944b8ac|
|12800|MS-AzureSync PBKDF2-HMAC-SHA256|v1;PPH1\_MD4,84840328224366186645,100,005a491d8bf3715085d69f934eef7fb19a15ffc233b5382d9827910bc32f3506|
|12900|Android FDE (Samsung DEK)|38421854118412625768408160477112384218541184126257684081604771129b6258eb22fc8b9d08e04e6450f72b98725d7d4fcad6fb6aec4ac2a79d0c6ff738421854118412625768408160477112|
|13000|RAR5|\$rar5\$16\$74575567518807622265582327032280\$15\$f8b4064de34ac02ecabfe9abdf93ed6a\$8\$9843834ed0f7c754|
|13100|Kerberos 5, etype 23, TGS-REP|\$krb5tgs\$23\$\*user\$realm\$test/spn\*\$63386d22d359fe42230300d56852c9eb\$891ad31d09ab89c6b3b8c5e5de6c06a7f49fd559d7a9a3c32576c8fedf705376cea582ab5938f7fc8bc741acf05c5990741b36ef4311fe3562a41b70a4ec6ecba849905f2385bb3799d92499909658c7287c49160276bca0006c350b0db4fd387adc27c01e9e9ad0c20ed53a7e6356dee2452e35eca2a6a1d1432796fc5c19d068978df74d3d0baf35c77de12456bf1144b6a750d11f55805f5a16ece2975246e2d026dce997fba34ac8757312e9e4e6272de35e20d52fb668c5ed|
|13200|AxCrypt 1|\$axcrypt\$\*1\*10000\*aaf4a5b4a7185551fea2585ed69fe246\*45c616e901e48c6cac7ff14e8cd99113393be259c595325e|
|13300|AxCrypt 1 in-memory SHA1 [^13]|\$axcrypt\_sha1\$b89eaac7e61417341b710b727768294d0e6a277b|
|13400|KeePass 1 AES / without keyfile|\$keepass\$\*1\*50000\*0\*375756b9e6c72891a8e5645a3338b8c8\*82afc053e8e1a6cfa39adae4f5fe5e59f545a54d6956593d1709b39cacd7f796\*c698fbfc7d1b71431d10611e2216ab21\*24a63140f4eb3bfd7d59b7694eea38d1d93a43bc3af989755d2b326286c4d510\*1\*192\*1a65072f436e9da0c9e832eca225a04ab78821b55d9f550860ade2ef8126a2c4050cf4d033374abd3dac6d0c5907c6cbb033643b203825c12e6c9853b5ac17a4809559fe723e01b4a2ab87cc83c8ba7ee4a757b8a0cf1674106f21f6675cba12064443d65436650df10ea0923c4cadfd4bfe341a6f4fa23a1a67f7d12a489fc5410ef6db9f6607905de491d3b3b915852a1b6c231c96366cbdee5ea9bd7f73ffd2f7a579215528ae1bf0ea540947ebfe39ca84bc6cbeded4f8e8fb6ed8f32dd5|
|13400|KeePass 2 AES / without keyfile|\$keepass\$\*2\*6000\*222\*a279e37c38b0124559a83fa452a0269d56dc4119a5866d18e76f1f3fd536d64d\*7ec7a06bc975ea2ae7c8dcb99e826a308564849b6b25d858cbbc78475af3733f\*d477c849bf2278b7a1f626c81e343553\*38c8ec186141c2705f2bcb334a730933ed3b0ee11391e1100fbaf429f6c99078\*1ada85fe78cf36ab0537562a787dd83e446f13cd3d9a60fd495003de3537b702|
|13400|KeePass 1 Twofish / with keyfile|\$keepass\$\*1\*6000\*1\*31c087828b0bb76362c10cae773aacdf\*6d6c78b4f82ecbcd3b96670cf490914c25ea8c31bc3aeb3fc56e65fac16d721f\*a735ec88c01816bc66200c8e17ee9110\*08334be8523f4b69bd4e2328db854329bfc81e2ea5a46d8ccf3bccf7c03d879d\*1\*1360\*f1e2c6c47f88c2abf4e79dbe73339b77778233a6c7d7f49f6b7d5db6a4885ff33585e221f5e94e8f7cc84ddcbe9c61a3d40c4f503a4ec7e91edca5745454588eebb4f0dc4d251c0d88eb5fae5d5b651d16e56ef830f412cb7fccf643de4963b66852d3a775489b5abb394b6fa325c3dbb4a55dd06d44c5fc911f1305e55accf0dc0eb172788f5400aab3c867cc6c5ddb7cd3e57bb78a739416985a276825171f5a19750dede055aa3e5fca9b11e3606beae97d68e593631a2efd88cdeb9f43b5ac1d1d9f0164f0fb022ea44a4a48061629c83d8f5bc594e3655ee684102fe706d1e96178bb805105fe1c5326c951401a6e7c9a0b8b572e7b74c3fb25e8700a2e0e70b4621ae3878805397ea1b873ea5218fdaa4fc5d11cdf7ea3579601eca3750fa347edc08569b1f51606d35920253f85f33e6a757a585adf079173161af919f7ea0d78ca6ca1513d01855057373c4f9fe22aba1fc4b18708d329500c127b865a528435e9e00d0a80554ae6eaf4d58bf85a959f37d0854b36c782991c36120b41ee2d9905b18d525b6bffef310e90dbfbe9be853614e6559737f1141f725902f59ee02789c6490c16adf0957e36dc4101c57ba35acb4ca9ec60f5585b60e74342921bbc7e56df5ad942b6deb7936532439b1dae39b9709cf282239c57b434d6f65ba277012ccddce32a217964f974c16f96d8b078ceaad43de9f3d5309279843f2f347ad8ae6eab3a998bb99a421b22b806e2f2302f9dcf3ba54e3d3f1ee64ef3b202194912eec202c2f44847ad5293b03b6b22df35f505670a79219efc399c6a4fa3fd4be7953e5df9baf94101c0a7036b82b6950ab2b722e38aec47bf1c7ffb4e82f43b9ca18d2a8b0b2a7b92015b01d07a429d2660902185cf143f871ff49dde73acf7c3bfd9c124733bd90ffe0fd1cc9090d56dd70bd62f9df1bfa4748ea3438f669d5691c61ec7fbc9d53ab4d8c2dda2cf203f7a5a7fac72eb2efe1d9a27b8c5b14e07a55c530dfd7b7c69dcf478590b7b364f5379f92a0762be0005c4cbc5285d7828248159286fe6d29c02c7de04e96e737a2d30ce75ff774982433f75ca16f09ad668e5b13f0a2e84886773d8fff67f71c1a9dab13f78e5b2da9b1eed9ab2208934a6da7eab32b3e8da1599d6cfa7e9c19ad8efc85dd9a2a4b95832c435381c2fe7e44c58045ce91e40d58c36924b38b19cbafd696bac8761229de9099ce31ee1c93a98aa0cb2a7c60b71b7f1998690e5eae623827727cfe7e8eed94ffc927a1e15aac32292daccda4f0d35383ce87f7e872fc3fe8f01f4a44de4f7b76257abc9c056ab8ae0d96d2dc3a154408c28a2e7befbd515cb5013cbfed31af456ac2b596b5d8095420c411b981d48741dc7ed1e8de4e428bd5e5a553348e2890b1ed12b7dc88261ab921a12da43e6344bbb4a0e0ce2b84c2d1d6c1f51b88202743433ac24340ae00cf27d43346240f4dc5e35ec29fcf1bf6de3bcc09ee8db3f49c3b6615bd8796bbe2cf4b914766779408e772123d9e51cc92ed5dedafa427fd767198cb97674eded4e4df84716aec75cbe7a54620c283fa60780be3cd66ea4167f46cdea1506be92a5102317c8ab8be097c993d82bd831818fe7cb1fbfecc3432d93e0f6d36da8a65ed15c78e623d59980be7ff54bdb1786de2ca9e7a11f0fe067db9ec42ade3bbaad10adae5ea77ba76fa2d0723a35891bde91da540a58e343c23afa9e22b38a66171eb9dbbd55f9e0f014e9de3943388fe0990cc801bbb978c02bf680b3c63a747e22a6317440c40e6844987e936c88c25f49e601ec3486ab080165b5e01dbee47a0a385dfba22ec5ed075f94052bdddabde761bbcc79852402c5b22ded89af4c602922099e37d71b7f87f4ffa614b4ca106fca6b062cba350be1fd12c6812db82f3e02a81e42\*1\*64\*bbc3babf62557aa4dfba705e24274e1aebf43907fe12f52eaf5395066f7cbdba|
|13400|Keepass 2 AES / with keyfile|\$keepass\$\*2\*6000\*222\*15b6b685bae998f2f608c909dc554e514f2843fbac3c7c16ea3600cc0de30212\*c417098b445cfc7a87d56ba17200836f30208d38f75a4169c0280bab3b10ca2a\*0d15a81eadccc58b1d3942090cd0ba66\*57c4aa5ac7295a97da10f8b2f2d2bfd7a98b0faf75396bc1b55164a1e1dc7e52\*2b822bb7e7d060bb42324459cb24df4d3ecd66dc5fc627ac50bf2d7c4255e4f8\*1\*64\*aaf72933951a03351e032b382232bcafbeeabc9bc8e6988b18407bc5b8f0e3cc|
|13500|PeopleSoft PS\_TOKEN|b5e335754127b25ba6f99a94c738e24cd634c35a:aa07d396f5038a6cbeded88d78d1d6c907e4079b3dc2e12fddee409a51cc05ae73e8cc24d518c923a2f79e49376594503e6238b806bfe33fa8516f4903a9b4|
|13600|WinZip|\$zip2\$\*0\*3\*0\*e3222d3b65b5a2785b192d31e39ff9de\*1320\*e\*19648c3e063c82a9ad3ef08ed833\*3135c79ecb86cd6f48fc\*\$/zip2\$|
|13711|VeraCrypt PBKDF2-HMAC-RIPEMD160 + AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_aes\_13711.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes_13711.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes_13711.vc")|
|13712|VeraCrypt PBKDF2-HMAC-RIPEMD160 + AES-Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_aes-twofish\_13712.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes-twofish_13712.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes-twofish_13712.vc")|
|13711|VeraCrypt PBKDF2-HMAC-RIPEMD160 + Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_serpent\_13711.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent_13711.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent_13711.vc")|
|13712|VeraCrypt PBKDF2-HMAC-RIPEMD160 + Serpent-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_serpent-aes\_13712.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent-aes_13712.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent-aes_13712.vc")|
|13713|VeraCrypt PBKDF2-HMAC-RIPEMD160 + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_serpent-twofish-aes\_13713.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent-twofish-aes_13713.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent-twofish-aes_13713.vc")|
|13711|VeraCrypt PBKDF2-HMAC-RIPEMD160 + Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_twofish\_13711.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_twofish_13711.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_twofish_13711.vc")|
|13712|VeraCrypt PBKDF2-HMAC-RIPEMD160 + Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_twofish-serpent\_13712.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_twofish-serpent_13712.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_twofish-serpent_13712.vc")|
|13751|VeraCrypt PBKDF2-HMAC-SHA256 + AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_aes\_13751.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes_13751.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes_13751.vc")|
|13752|VeraCrypt PBKDF2-HMAC-SHA256 + AES-Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_aes-twofish\_13752.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes-twofish_13752.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes-twofish_13752.vc")|
|13751|VeraCrypt PBKDF2-HMAC-SHA256 + Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_serpent\_13751.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent_13751.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent_13751.vc")|
|13752|VeraCrypt PBKDF2-HMAC-SHA256 + Serpent-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_serpent-aes\_13752.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-aes_13752.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-aes_13752.vc")|
|13753|VeraCrypt PBKDF2-HMAC-SHA256 + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_serpent-twofish-aes\_13753.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-twofish-aes_13753.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-twofish-aes_13753.vc")|
|13751|VeraCrypt PBKDF2-HMAC-SHA256 + Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_twofish\_13751.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish_13751.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish_13751.vc")|
|13752|VeraCrypt PBKDF2-HMAC-SHA256 + Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_twofish-serpent\_13752.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish-serpent_13752.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish-serpent_13752.vc")|
|13721|VeraCrypt PBKDF2-HMAC-SHA512 + AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha512\_aes\_13721.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_aes_13721.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_aes_13721.vc")|
|13722|VeraCrypt PBKDF2-HMAC-SHA512 + AES-Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha512\_aes-twofish\_13722.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_aes-twofish_13722.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_aes-twofish_13722.vc")|
|13721|VeraCrypt PBKDF2-HMAC-SHA512 + Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha512\_serpent\_13721.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent_13721.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent_13721.vc")|
|13722|VeraCrypt PBKDF2-HMAC-SHA512 + Serpent-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha512\_serpent-aes\_13722.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent-aes_13722.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent-aes_13722.vc")|
|13723|VeraCrypt PBKDF2-HMAC-SHA512 + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha512\_serpent-twofish-aes\_13723.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent-twofish-aes_13723.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent-twofish-aes_13723.vc")|
|13721|VeraCrypt PBKDF2-HMAC-SHA512 + Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha512\_twofish\_13721.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_twofish_13721.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_twofish_13721.vc")|
|13722|VeraCrypt PBKDF2-HMAC-SHA512 + Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha512\_twofish-serpent\_13722.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_twofish-serpent_13722.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_twofish-serpent_13722.vc")|
|13731|VeraCrypt PBKDF2-HMAC-Whirlpool + AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_whirlpool\_aes\_13731.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_aes_13731.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_aes_13731.vc")|
|13732|VeraCrypt PBKDF2-HMAC-Whirlpool + AES-Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_whirlpool\_aes-twofish\_13732.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_aes-twofish_13732.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_aes-twofish_13732.vc")|
|13731|VeraCrypt PBKDF2-HMAC-Whirlpool + Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_whirlpool\_serpent\_13731.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent_13731.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent_13731.vc")|
|13732|VeraCrypt PBKDF2-HMAC-Whirlpool + Serpent-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_whirlpool\_serpent-aes\_13732.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent-aes_13732.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent-aes_13732.vc")|
|13733|VeraCrypt PBKDF2-HMAC-Whirlpool + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_whirlpool\_serpent-twofish-aes\_13733.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent-twofish-aes_13733.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent-twofish-aes_13733.vc")|
|13731|VeraCrypt PBKDF2-HMAC-Whirlpool + Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_whirlpool\_twofish\_13731.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_twofish_13731.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_twofish_13731.vc")|
|13732|VeraCrypt PBKDF2-HMAC-Whirlpool + Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_whirlpool\_twofish-serpent\_13732.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_twofish-serpent_13732.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_twofish-serpent_13732.vc")|
|13741|VeraCrypt PBKDF2-HMAC-RIPEMD160 + boot-mode + AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_aes\_boot.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes_boot.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes_boot.vc")|
|13742|VeraCrypt PBKDF2-HMAC-RIPEMD160 + boot-mode + AES-Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_aes-twofish\_boot.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes-twofish_boot.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes-twofish_boot.vc")|
|13743|VeraCrypt PBKDF2-HMAC-RIPEMD160 + boot-mode + AES-Twofish-Serpent|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_ripemd160\_aes-twofish-serpent\_boot.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes-twofish-serpent_boot.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes-twofish-serpent_boot.vc")|
|13761|VeraCrypt PBKDF2-HMAC-SHA256 + boot-mode + Twofish|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_twofish\_boot.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish_boot.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish_boot.vc")|
|13762|VeraCrypt PBKDF2-HMAC-SHA256 + boot-mode + Serpent-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_serpent-aes\_boot.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-aes_boot.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-aes_boot.vc")|
|13763|VeraCrypt PBKDF2-HMAC-SHA256 + boot-mode + Serpent-Twofish-AES|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_serpent-twofish-aes\_boot.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-twofish-aes_boot.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-twofish-aes_boot.vc")|
|13761|VeraCrypt PBKDF2-HMAC-SHA256 + boot-mode + PIM + AES [^16]|[https://hashcat.net/misc/example\_hashes/vc/hashcat\_sha256\_aes\_boot\_pim500.vc](https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes_boot_pim500.vc "https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes_boot_pim500.vc")|
|13771|VeraCrypt Streebog-512 + XTS 512 bit|TBD|
|13772|VeraCrypt Streebog-512 + XTS 1024 bit|TBD|
|13773|VeraCrypt Streebog-512 + XTS 1536 bit|TBD|
|13800|Windows Phone 8+ PIN/password|95fc4680bcd2a5f25de3c580cbebadbbf256c1f0ff2e9329c58e36f8b914c11f:4471347156480581513210137061422464818088437334031753080747625028271635402815635172140161077854162657165115624364524648202480341513407048222056541500234214433548175101668212658151115765112202168288664210443352443335235337677853484573107775345675846323265745|
|13900|OpenCart|6e36dcfc6151272c797165fce21e68e7c7737e40:472433673|
|14000|DES (PT = \$salt, key = \$pass) [^8]|a28bc61d44bb815c:1172075784504605|
|14100|3DES (PT = \$salt, key = \$pass) [^9]|37387ff8d8dafe15:8152001061460743|
|14400|sha1(CX)|fd9149fb3ae37085dc6ed1314449f449fbf77aba:87740665218240877702|
|14500|Linux Kernel Crypto API (2.4)|\$cryptoapi\$9\$2\$03000000000000000000000000000000\$00000000000000000000000000000000\$d1d20e91a8f2e18881dc79369d8af761|
|14600|LUKS [^10]|[https://hashcat.net/misc/example\_hashes/hashcat\_luks\_testfiles.7z](https://hashcat.net/misc/example_hashes/hashcat_luks_testfiles.7z "https://hashcat.net/misc/example_hashes/hashcat_luks_testfiles.7z")|
|14700|iTunes backup \< 10.0 [^11]|\$itunes\_backup\$\*9\*b8e3f3a970239b22ac199b622293fe4237b9d16e74bad2c3c3568cd1bd3c471615a6c4f867265642\*10000\*4542263740587424862267232255853830404566\*\*|
|14800|iTunes backup \>= 10.0 [^11]|\$itunes\_backup\$\*10\*8b715f516ff8e64442c478c2d9abb046fc6979ab079007d3dbcef3ddd84217f4c3db01362d88fa68\*10000\*2353363784073608264337337723324886300850\*10000000\*425b4bb4e200b5fd4c66979c9caca31716052063|
|14900|Skip32 (PT = \$salt, key = \$pass) [^12]|c9350366:44630464|
|15000|FileZilla Server \>= 0.9.55|632c4952b8d9adb2c0076c13b57f0c934c80bdc14fc1b4c341c2e0a8fd97c4528729c7bd7ed1268016fc44c3c222445ebb880eca9a6638ea5df74696883a2978:0608516311148050266404072407085605002866301131581532805665756363|
|15100|Juniper/NetBSD sha1crypt|\$sha1\$15100\$jiJDkz0E\$E8C7RQAD3NetbSDz7puNAY.5Y2jr|
|15200|Blockchain, My Wallet, V2|\$blockchain\$v2\$5000\$288\$06063152445005516247820607861028813ccf6dcc5793dc0c7a82dcd604c5c3e8d91bea9531e628c2027c56328380c87356f86ae88968f179c366da9f0f11b09492cea4f4d591493a06b2ba9647faee437c2f2c0caaec9ec795026af51bfa68fc713eaac522431da8045cc6199695556fc2918ceaaabbe096f48876f81ddbbc20bec9209c6c7bc06f24097a0e9a656047ea0f90a2a2f28adfb349a9cd13852a452741e2a607dae0733851a19a670513bcf8f2070f30b115f8bcb56be2625e15139f2a357cf49d72b1c81c18b24c7485ad8af1e1a8db0dc04d906935d7475e1d3757aba32428fdc135fee63f40b16a5ea701766026066fb9fb17166a53aa2b1b5c10b65bfe685dce6962442ece2b526890bcecdeadffbac95c3e3ad32ba57c9e|
|15300|DPAPI masterkey file v1 + local context|\$DPAPImk\$1\*1\*S-15-21-466364039-425773974-453930460-1925\*des3\*sha1\*24000\*b038489dee5ad04e3e3cab4d957258b5\*208\*cb9b5b7d96a0d2a00305ca403d3fd9c47c561e35b4b2cf3aebfd1d3199a6481d56972be7ebd6c291b199e6f1c2ffaee91978706737e9b1209e6c7d3aa3d8c3c3e38ad1ccfa39400d62c2415961c17fd0bd6b0f7bbd49cc1de1a394e64b7237f56244238da8d37d78|
|15400|ChaCha20 [^20]|\$chacha20\$\*0400000000000003\*16\*0200000000000001\*5152535455565758\*6b05fe554b0bc3b3|
|15500|JKS Java Key Store Private Keys (SHA1)|\$jksprivk\$\*5A3AA3C3B7DD7571727E1725FB09953EF3BEDBD9\*0867403720562514024857047678064085141322\*81\*C3\*50DDD9F532430367905C9DE31FB1\*test|
|15600|Ethereum Wallet, PBKDF2-HMAC-SHA256|\$ethereum\$p\*262144\*3238383137313130353438343737383736323437353437383831373034343735\*06eae7ee0a4b9e8abc02c9990e3730827396e8531558ed15bb733faf12a44ce1\*e6d5891d4f199d31ec434fe25d9ecc2530716bc3b36d5bdbc1fab7685dda3946|
|15700|Ethereum Wallet, SCRYPT|\$ethereum\$s\*262144\*1\*8\*3436383737333838313035343736303637353530323430373235343034363130\*8b58d9d15f579faba1cd13dd372faeb51718e7f70735de96f0bcb2ef4fb90278\*8de566b919e6825a65746e266226316c1add8d8c3d15f54640902437bcffc8c3|
|15900|DPAPI masterkey file v2 + Active Directory domain context|\$DPAPImk\$2\*2\*S-15-21-423929668-478423897-489523715-1834\*aes256\*sha512\*8000\*740866e4105c77f800f02d367dd96699\*288\*ebc2907e16245dfe6c902ad4be70a079e62204c8a947498455056d150e6babb3c90b1616a8dff0e390dd26dda1978dffcbd7b9d7d1ea5c6d3e4df36db4d977051ec01fd6f0882a597c51834cb86445cad50c716f48b37cfd24339d8b43da771526fb01376798251edaa868fa2b1fa85c4142864b899987d4bbdc87b53433ed945fa4ab49c7f9d4d01df3ae19f25013b2|
|16000|Tripcode|pfaRCwDe0U|
|16100|TACACS+|\$tacacs-plus\$0\$5fde8e68\$4e13e8fb33df\$c006|
|16200|Apple Secure Notes|\$ASN\$\*1\*20000\*80771171105233481004850004085037\*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41|
|16300|Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256|\$ethereum\$w\*e94a8e49deac2d62206bf9bfb7d2aaea7eb06c1a378cfc1ac056cc599a569793c0ecc40e6a0c242dee2812f06b644d70f43331b1fa2ce4bd6cbb9f62dd25b443235bdb4c1ffb222084c9ded8c719624b338f17e0fd827b34d79801298ac75f74ed97ae16f72fccecf862d09a03498b1b8bd1d984fc43dd507ede5d4b6223a582352386407266b66c671077eefc1e07b5f42508bf926ab5616658c984968d8eec25c9d5197a4a30eed54c161595c3b4d558b17ab8a75ccca72b3d949919d197158ea5cfbc43ac7dd73cf77807dc2c8fe4ef1e942ccd11ec24fe8a410d48ef4b8a35c93ecf1a21c51a51a08f3225fbdcc338b1e7fdafd7d94b82a81d88c2e9a429acc3f8a5974eafb7af8c912597eb6fdcd80578bd12efddd99de47b44e7c8f6c38f2af3116b08796172eda89422e9ea9b99c7f98a7e331aeb4bb1b06f611e95082b629332c31dbcfd878aed77d300c9ed5c74af9cd6f5a8c4a261dd124317fb790a04481d93aec160af4ad8ec84c04d943a869f65f07f5ccf8295dc1c876f30408eac77f62192cbb25842470b4a5bdb4c8096f56da7e9ed05c21f61b94c54ef1c2e9e417cce627521a40a99e357dd9b7a7149041d589cbacbe0302db57ddc983b9a6d79ce3f2e9ae8ad45fa40b934ed6b36379b780549ae7553dbb1cab238138c05743d0103335325bd90e27d8ae1ea219eb8905503c5ad54fa12d22e9a7d296eee07c8a7b5041b8d56b8af290274d01eb0e4ad174eb26b23b5e9fb46ff7f88398e6266052292acb36554ccb9c2c03139fe72d3f5d30bd5d10bd79d7cb48d2ab24187d8efc3750d5a24980fb12122591455d14e75421a2074599f1cc9fdfc8f498c92ad8b904d3c4307f80c46921d8128\*f3abede76ac15228f1b161dd9660bb9094e81b1b\*d201ccd492c284484c7824c4d37b1593|
|16400|CRAM-MD5 Dovecot|{CRAM-MD5}5389b33b9725e5657cb631dc50017ff1535ce4e2a1c414009126506fc4327d0d|
|16500|JWT (JSON Web Token)|eyJhbGciOiJIUzI1NiJ9.eyIzNDM2MzQyMCI6NTc2ODc1NDd9.f1nXZ3V\_Hrr6ee-AFCTLaHRnrkiKmio2t3JqwL32guY|
|16600|Electrum Wallet (Salt-Type 1-3)|\$electrum\$1\*44358283104603165383613672586868\*c43a6632d9f59364f74c395a03d8c2ea|
|16700|FileVault 2|\$fvde\$1\$16\$84286044060108438487434858307513\$20000\$f1620ab93192112f0a23eea89b5d4df065661f974b704191|
|16800|WPA-PMKID-PBKDF2 [^1]|2582a8281bf9d4308d6f5731d0e61c61\*4604ba734d4e\*89acf0e761f4\*ed487162465a774bfba60eb603a39f3a|
|16801|WPA-PMKID-PMK [^15]|2582a8281bf9d4308d6f5731d0e61c61\*4604ba734d4e\*89acf0e761f4|
|16900|Ansible Vault|\$ansible\$0\*0\*6b761adc6faeb0cc0bf197d3d4a4a7d3f1682e4b169cae8fa6b459b3214ed41e\*426d313c5809d4a80a4b9bc7d4823070\*d8bad190c7fbc7c3cb1c60a27abfb0ff59d6fb73178681c7454d94a0f56a4360|
|17200|PKZIP (Compressed)|\$pkzip2\$1\*1\*2\*0\*e3\*1c5\*eda7a8de\*0\*28\*8\*e3\*eda7\*5096\*a9fc1f4e951c8fb3031a6f903e5f4e3211c8fdc4671547bf77f6f682afbfcc7475d83898985621a7af9bccd1349d1976500a68c48f630b7f22d7a0955524d768e34868880461335417ddd149c65a917c0eb0a4bf7224e24a1e04cf4ace5eef52205f4452e66ded937db9545f843a68b1e84a2e933cc05fb36d3db90e6c5faf1bee2249fdd06a7307849902a8bb24ec7e8a0886a4544ca47979a9dfeefe034bdfc5bd593904cfe9a5309dd199d337d3183f307c2cb39622549a5b9b8b485b7949a4803f63f67ca427a0640ad3793a519b2476c52198488e3e2e04cac202d624fb7d13c2\*\$/pkzip2\$|
|17210|PKZIP (Uncompressed)|\$pkzip2\$1\*1\*2\*0\*1d1\*1c5\*eda7a8de\*0\*28\*0\*1d1\*eda7\*5096\*1dea673da43d9fc7e2be1a1f4f664269fceb6cb88723a97408ae1fe07f774d31d1442ea8485081e63f919851ca0b7588d5e3442317fff19fe547a4ef97492ed75417c427eea3c4e146e16c100a2f8b6abd7e5988dc967e5a0e51f641401605d673630ea52ebb04da4b388489901656532c9aa474ca090dbac7cf8a21428d57b42a71da5f3d83fed927361e5d385ca8e480a6d42dea5b4bf497d3a24e79fc7be37c8d1721238cbe9e1ea3ae1eb91fc02aabdf33070d718d5105b70b3d7f3d2c28b3edd822e89a5abc0c8fee117c7fbfbfd4b4c8e130977b75cb0b1da080bfe1c0859e6483c42f459c8069d45a76220e046e6c2a2417392fd87e4aa4a2559eaab3baf78a77a1b94d8c8af16a977b4bb45e3da211838ad044f209428dba82666bf3d54d4eed82c64a9b3444a44746b9e398d0516a2596d84243b4a1d7e87d9843f38e45b6be67fd980107f3ad7b8453d87300e6c51ac9f5e3f6c3b702654440c543b1d808b62f7a313a83b31a6faaeedc2620de7057cd0df80f70346fe2d4dccc318f0b5ed128bcf0643e63d754bb05f53afb2b0fa90b34b538b2ad3648209dff587df4fa18698e4fa6d858ad44aa55d2bba3b08dfdedd3e28b8b7caf394d5d9d95e452c2ab1c836b9d74538c2f0d24b9b577\*\$/pkzip2\$|
|17220|PKZIP (Compressed Multi-File)|\$pkzip2\$3\*1\*1\*0\*8\*24\*a425\*8827\*d1730095cd829e245df04ebba6c52c0573d49d3bbeab6cb385b7fa8a28dcccd3098bfdd7\*1\*0\*8\*24\*2a74\*882a\*51281ac874a60baedc375ca645888d29780e20d4076edd1e7154a99bde982152a736311f\*2\*0\*e3\*1c5\*eda7a8de\*0\*29\*8\*e3\*eda7\*5096\*1455781b59707f5151139e018bdcfeebfc89bc37e372883a7ec0670a5eafc622feb338f9b021b6601a674094898a91beac70e41e675f77702834ca6156111a1bf7361bc9f3715d77dfcdd626634c68354c6f2e5e0a7b1e1ce84a44e632d0f6e36019feeab92fb7eac9dda8df436e287aafece95d042059a1b27d533c5eab62c1c559af220dc432f2eb1a38a70f29e8f3cb5a207704274d1e305d7402180fd47e026522792f5113c52a116d5bb25b67074ffd6f4926b221555234aabddc69775335d592d5c7d22462b75de1259e8342a9ba71cb06223d13c7f51f13be2ad76352c3b8ed\*\$/pkzip2\$|
|17225|PKZIP (Mixed Multi-File)|\$pkzip2\$3\*1\*1\*0\*0\*24\*3e2c\*3ef8\*0619e9d17ff3f994065b99b1fa8aef41c056edf9fa4540919c109742dcb32f797fc90ce0\*1\*0\*8\*24\*431a\*3f26\*18e2461c0dbad89bd9cc763067a020c89b5e16195b1ac5fa7fb13bd246d000b6833a2988\*2\*0\*23\*17\*1e3c1a16\*2e4\*2f\*0\*23\*1e3c\*3f2d\*54ea4dbc711026561485bbd191bf300ae24fa0997f3779b688cdad323985f8d3bb8b0c\*\$/pkzip2\$|
|17230|PKZIP (Mixed Multi-File Checksum-Only)|\$pkzip2\$8\*1\*1\*0\*8\*24\*a425\*8827\*3bd479d541019c2f32395046b8fbca7e1dca218b9b5414975be49942c3536298e9cc939e\*1\*0\*8\*24\*2a74\*882a\*537af57c30fd9fd4b3eefa9ce55b6bff3bbfada237a7c1dace8ebf3bb0de107426211da3\*1\*0\*8\*24\*2a74\*882a\*5f406b4858d3489fd4a6a6788798ac9b924b5d0ca8b8e5a6371739c9edcfd28c82f75316\*1\*0\*8\*24\*2a74\*882a\*1843aca546b2ea68bd844d1e99d4f74d86417248eb48dd5e956270e42a331c18ea13f5ed\*1\*0\*8\*24\*2a74\*882a\*aca3d16543bbfb2e5d2659f63802e0fa5b33e0a1f8ae47334019b4f0b6045d3d8eda3af1\*1\*0\*8\*24\*2a74\*882a\*fbe0efc9e10ae1fc9b169bd060470bf3e39f09f8d83bebecd5216de02b81e35fe7e7b2f2\*1\*0\*8\*24\*2a74\*882a\*537886dbabffbb7cac77deb01dc84760894524e6966183b4478a4ef56f0c657375a235a1\*1\*0\*8\*24\*eda7\*5096\*40eb30ef1ddd9b77b894ed46abf199b480f1e5614fde510855f92ae7b8026a11f80e4d5f\*\$/pkzip2\$|
|17300|SHA3-224|412ef78534ba6ab0e9b1607d3e9767a25c1ea9d5e83176b4c2817a6c|
|17400|SHA3-256|d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd|
|17500|SHA3-384|983ba28532cc6320d04f20fa485bcedb38bddb666eca5f1e5aa279ff1c6244fe5f83cf4bbf05b95ff378dd2353617221|
|17600|SHA3-512|7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e|
|17700|Keccak-224|e1dfad9bafeae6ef15f5bbb16cf4c26f09f5f1e7870581962fc84636|
|17800|Keccak-256|203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6|
|17900|Keccak-384|5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701|
|18000|Keccak-512|2fbf5c9080f0a704de2e915ba8fdae6ab00bbc026b2c1c8fa07da1239381c6b7f4dfd399bf9652500da723694a4c719587dd0219cb30eabe61210a8ae4dc0b03|
|18100|TOTP (HMAC-SHA1)|597056:3600|
|18200|Kerberos 5, etype 23, AS-REP|\$krb5asrep\$23\$user@domain.com:3e156ada591263b8aab0965f5aebd837\$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac|
|18300|Apple File System (APFS)|\$fvde\$2\$16\$58778104701476542047675521040224\$20000\$39602e86b7cea4a34f4ff69ff6ed706d68954ee474de1d2a9f6a6f2d24d172001e484c1d4eaa237d|
|18400|Open Document Format (ODF) 1.2 (SHA-256, AES)|\$odf\$\*1\*1\*100000\*32\*751854d8b90731ce0579f96bea6f0d4ac2fb2f546b31f1b6af9a5f66952a0bf4\*16\*2185a966155baa9e2fb597298febecbc\*16\*c18eaae34bcbbe9119be017fe5f8b52d\*0\*051e0f1ce0e866f2b771029e03a6c7119aad132af54c4e45824f16f61f357a40407ab82744fe6370c7b2346075fcd4c2e58ab244411b3ab1d532a46e2321599ef13c3d3472fc2f14d480d8c33215e473da67f90540279d3ef1f62dde314fa222796046e496c951235ddf88aa754620b7810d22ebc8835c90dce9276946f52b8ea7d95d2f86e4cc725366a8b3edacc2ce88518e535991a5f84d5ea8795dc02bfb731b5f202ecaf7d4b245d928c4248709fcdf3fba2acf1a08be0c1eee7dbeda07e8c3a6983565635e99952b8ad79d31c965f245ae90b5cc3dba6387898c66fa35cad9ac9595c41b62e68efcdd73185b38e220cf004269b77ec6974474b03b7569afc3b503a2bf8b2d035756f3f4cb880d9ba815e5c944508a0bde214076c35bf0e0814a96d21ccaa744c9056948ed935209f5c7933841d2ede3d28dd84da89d477d4a0041ce6d8ddab891d929340db6daa921d69b46fd5aee306d0bcef88c38acbb495d0466df7e2f744e3d10201081215c02db5dd479a4cda15a3338969c7baec9d3d2c378a8dd30449319b149dc3b4e7f00996a59fcb5f243d0df2cbaf749241033f7865aefa960adfeb8ebf205b270f90b1f82c34f80d5a8a0db7aec89972a32f5daa2a73c5895d1fced01b3ab8e576bd2630eff01cad97781f4966d4b528e1b15f011f28ae907a352073c96b203adc7742d2b79b2e2f440b17e7856ae119e08d15d8bdf951f6d4a3f9b516da2d9a8f9dd93488f8e0119f3da19138ab787f0d7098a652cccd914aa0ff81d375bd6a5a165acc936f591639059287975cfc3ca4342e5f9501b3249a76d14e56d6d56b319e036bc0449ac7b5afa24ffbea11babed8183edf8d4fdca1c3f0d23bfd4a02797627d556634f1a9304e03737604bd86f6b5a26aa687d6df73383e0f7dfe62a131e8dbb8c3f4f13d24857dd29d76984eac6c45df7428fc79323ffa1f4e7962d705df74320141ed1f16d1ad483b872168df60315ffadbfa1b7f4afaed8a0017421bf5e05348cb5c707a5e852d6fee6077ec1c33bc707bcd97b7701ee05a03d6fa78b0d31c8c97ea16e0edf434961bd5cc7cbb7eb2553730f0405c9bd21cee09b3f7c1bc57779fdfc15f3935985737a1b522004c4436b631a39a66e8577a03f5020e6aa41952c0662c8c57f66caa483b47af38b8cb5d457245fd3241749e17433e6f929233e8862d7c584111b1991b2d6e94278e7e6e1908cee5a83d94c78b75a84a695d25aeb9fdde72174fe6dd75e8d406671f44892a385a4a1e249f61ebc993e985607423a0a5742e668d52c1ebf5cecae7c2b7908f4627b92ec49354a9ccff8cb5763ad074a00e65a485a41bf4c25ce7e6fae49358a58547b1c0ca79713e297310c0a367c3de196f1dd685ca4be643bdf1e4f6b034211d020557e37a3b6614d061010b4a3416b6b279728c245d3322|
|18500|sha1(md5(md5(\$pass)))|888a2ffcb3854fba0321110c5d0d434ad1aa2880|
|18600|Open Document Format (ODF) 1.1 (SHA-1, Blowfish)|\$odf\$\*0\*0\*1024\*16\*bff753835f4ea15644b8a2f8e4b5be3d147b9576\*8\*ee371da34333b69d\*16\*a902eff54a4d782a26a899a31f97bef4\*0\*dae7e41fbc3a500d3ce152edd8876c4f38fb17d673ee2ac44ef1e0e283622cd2ae298a82d8d98f2ea737247881fc353e73a2f535c6e13e0cdc60821c1a61c53a4b0c46ff3a3b355d7b793fad50de15999fc7c1194321d1c54316c3806956c4a3ade7daabb912a2a36398eba883af088b3cb69b43365d9ba9fce3fb0c1524f73947a7e9fc1bf3adb5f85a367035feacb5d97c578b037144c2793f34aa09dcd04bdaa455aee0d4c52fe377248611dd56f2bd4eb294673525db905f5d905a28dec0909348e6bf94bcebf03ddd61a48797cd5728ce6dbb71037b268f526e806401abcf495f6edd0b5d87118671ec690d4627f86a43e51c7f6d42a75a56eec51204d47e115e813ed4425c97b16b195e02ce776c185194b9de43ae89f356e29face016cb393d6fb93af8ea305d921d5592dd184051ac790b9b90266f52b8d53ce1cb1d762942d6d5bbd0e3821be21af9fa6874ba0c60e64f41d3e5b6caca1c53b575afdc5d8f6a3edbf874dbe009c6cb296466fe9637aed4aed8a43a95ea7d26b4090ad33d4ee7a83844b0893e8bc0f04944205fb9576cb5720f019028cd75ca9ac47b3e5fa231354d74135564df43b659cfaea7e195c4a896e0e0e0c85dc9ce3a9ce9ba552bc2a6dbac4901c19558818e1957ed72d78662bb5ba53475ca584371f1825ae0c92322a4404e63c2baad92665aac29b5c6f96e1e6338d48fb0aef4d0b686063974f58b839484f8dcf0a02537cba67a7d2c4de13125d74820cb07ec72782035af1ea6c4db61c77016d1c021b63c8b07adb4e8510f5c41bbc501f60f3dd16462399b52eb146787e38e700147c7aa23ac4d5d22d9d1c93e67a01c92a197d4765cbf8d56a862a1205abb450a182913a69b8d5334a59924f86fb3ccd0dcfe7426053e26ba26b57c05f38d85863fff1f81135b0366e8cd8680663ae8aaf7d005317b849d5e08be882708fa0d8d02d47e89150124b507c34845c922b95e62aa0b3fef218773d7aeb572c67b35ad8787f31ecc6e1846b673b8ba6172223176eabf0020b6aa3aa71405b40b2fc2127bf9741a103f1d8eca21bf27328cdf15153f2f223eff7b831a72ed8ecacf4ea8df4ea44f3a3921e5a88fb2cfa355ece0f05cbc88fdd1ecd368d6e3b2dfabd999e5b708f1bccaeebb296c9d7b76659967742fe966aa6871cbbffe710b0cd838c6e02e6eb608cb5c81d066b60b5b3604396331d97d4a2c4c2317406e48c9f5387a2c72511d1e6899bd450e9ca88d535755bcfddb53a6df118cd9cdc7d8b4b814f7bc17684d8e5975defaa25d06f410ed0724c16b8f69ec3869bc1f05c71483666968d1c04509875dadd72c6182733d564eb1a7d555dc34f6b817c5418626214d0b2c3901c5a46f5b20fddfdf9f71a7dfd75b9928778a3f65e1832dff22be973c2b259744d500a3027c2a2e08972eaaad4c5c4ec871|
|18700|Java Object hashCode()|29937c08|
|18800|Blockchain, My Wallet, Second Password (SHA256)|YnM6WYERjJfhxwepT7zV6odWoEUz1X4esYQb4bQ3KZ7bbZAyOTc1MDM3OTc1NjMyODA0ECcAAD3vFoc=|
|18900|Android Backup|\$ab\$5\*0\*10000\*b8900e4885ff9cad8f01ee1957a43bd633fea12491440514ae27aa83f2f5c006ec7e7fa0bce040add619919b4eb60608304b7d571a2ed87fd58c9ad6bc5fcf4c\*7d254d93e16be9312fb1ccbfc6265c40cb0c5eab7b605a95a116e2383fb1cf12b688223f96221dcd2bf5410d4ca6f90e0789ee00157fa91658b42665d6b6844c\*fc9f6be604d1c59ac32664ec2c5b9b30\*00c4972149af3adcc235899e9d20611ea6e8de2212afcb9fcfefde7e35b691c2d0994eb47e4f9a260526ba47f4caea71af9c7fadcd5685d50126276f6acdd59966528b13ccc26036a0eaba2f2451aa64b05766d0edd03c988dcf87e2a9eec52d|
|19000|QNX /etc/shadow (MD5)|@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050|
|19100|QNX /etc/shadow (SHA256)|@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604|
|19200|QNX /etc/shadow (SHA512)|@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159|
|19300|sha1(\$salt1.\$pass.\$salt2)|630d2e918ab98e5fad9c61c0e4697654c4c16d73:18463812876898603420835420139870031762867:4449516425193605979760642927684590668549584534278112685644182848763890902699756869283142014018311837025441092624864168514500447147373198033271040848851687108629922695275682773136540885737874252666804716579965812709728589952868736177317883550827482248620334|
|19500|Ruby on Rails Restful-Authentication|d7d5ea3e09391da412b653ae6c8d7431ec273ea2:238769868762:8962783556527653675|
|19600|Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96)|\$krb5tgs\$17\$user\$realm\$ae8434177efd09be5bc2eff8\$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e|
|19700|Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)|\$krb5tgs\$18\$user\$realm\$8efd91bb01cc69dd07e46009\$7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0|
|19800|Kerberos 5, etype 17, Pre-Auth|\$krb5pa\$17\$hashcat\$HASHCATDOMAIN.COM\$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333|
|19900|Kerberos 5, etype 18, Pre-Auth|\$krb5pa\$18\$hashcat\$HASHCATDOMAIN.COM\$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770|
|20011|DiskCryptor SHA512 + XTS 512 bit (AES)|[https://hashcat.net/misc/example\_hashes/dc/hashcat\_aes.dc](https://hashcat.net/misc/example_hashes/dc/hashcat_aes.dc "https://hashcat.net/misc/example_hashes/dc/hashcat_aes.dc")|
|20011|DiskCryptor SHA512 + XTS 512 bit (Twofish)|[https://hashcat.net/misc/example\_hashes/dc/hashcat\_twofish.dc](https://hashcat.net/misc/example_hashes/dc/hashcat_twofish.dc "https://hashcat.net/misc/example_hashes/dc/hashcat_twofish.dc")|
|20011|DiskCryptor SHA512 + XTS 512 bit (Serpent)|[https://hashcat.net/misc/example\_hashes/dc/hashcat\_serpent.dc](https://hashcat.net/misc/example_hashes/dc/hashcat_serpent.dc "https://hashcat.net/misc/example_hashes/dc/hashcat_serpent.dc")|
|20012|DiskCryptor SHA512 + XTS 1024 bit (AES-Twofish)|[https://hashcat.net/misc/example\_hashes/dc/hashcat\_aes\_twofish.dc](https://hashcat.net/misc/example_hashes/dc/hashcat_aes_twofish.dc "https://hashcat.net/misc/example_hashes/dc/hashcat_aes_twofish.dc")|
|20012|DiskCryptor SHA512 + XTS 1024 bit (Twofish-Serpent)|[https://hashcat.net/misc/example\_hashes/dc/hashcat\_twofish\_serpent.dc](https://hashcat.net/misc/example_hashes/dc/hashcat_twofish_serpent.dc "https://hashcat.net/misc/example_hashes/dc/hashcat_twofish_serpent.dc")|
|20012|DiskCryptor SHA512 + XTS 1024 bit (Serpent-AES)|[https://hashcat.net/misc/example\_hashes/dc/hashcat\_serpent\_aes.dc](https://hashcat.net/misc/example_hashes/dc/hashcat_serpent_aes.dc "https://hashcat.net/misc/example_hashes/dc/hashcat_serpent_aes.dc")|
|20013|DiskCryptor SHA512 + XTS 1536 bit (AES-Twofish-Serpent)|[https://hashcat.net/misc/example\_hashes/dc/hashcat\_aes\_twofish\_serpent.dc](https://hashcat.net/misc/example_hashes/dc/hashcat_aes_twofish_serpent.dc "https://hashcat.net/misc/example_hashes/dc/hashcat_aes_twofish_serpent.dc")|
|20200|Python passlib pbkdf2-sha512|\$pbkdf2-sha512\$25000\$LyWE0HrP2RsjZCxlDGFMKQ\$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH.SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw|
|20300|Python passlib pbkdf2-sha256|\$pbkdf2-sha256\$29000\$x9h7j/Ge8x6DMEao1VqrdQ\$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A|
|20400|Python passlib pbkdf2-sha1|\$pbkdf2\$131000\$r5WythYixPgfQ2jt3buXcg\$8Kdr.QQEOaZIXNOrrru36I/.6Po|
|20500|PKZIP Master Key|f1eff5c0368d10311dcfc419|
|20510|PKZIP Master Key (6 byte optimization) [^17]|f1eff5c0368d10311dcfc419|
|20600|Oracle Transportation Management (SHA256)|otm\_sha256:1000:1234567890:S5Q9Kc0ETY6ZPyQU+JYY60oFjaJuZZaSinggmzU8PC4=|
|20710|sha256(sha256(\$pass).\$salt)|bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824:7218532375810603|
|20720|sha256(\$salt.sha256(\$pass))|bae9edada8358fcebcd811f7d362f46277fb9d488379869fba65d79701d48b8b:869dc2ed80187919|
|20800|sha256(md5(\$pass))|74ee1fae245edd6f27bf36efc3604942479fceefbadab5dc5c0b538c196eb0f1|
|20900|md5(sha1(\$pass).md5(\$pass).sha1(\$pass))|100b3a4fc1dc8d60d9bf40688d8b740a|
|21000|BitShares v0.x - sha512(sha512\_bin(pass))|caec04bdf7c17f763a9ec7439f7c9abda112f1bfc9b1bb684fef9b6142636979b9896cfc236896d821a69a961a143dd19c96d59777258201f1bbe5ecc2a2ecf5|
|21100|sha1(md5(\$pass.\$salt))|aade80a61c6e3cd3cac614f47c1991e0a87dd028:6|
|21200|md5(sha1(\$salt).md5(\$pass))|e69b7a7fe1bf2ad9ef116f79551ee919:baa038987e582431a6d|
|21300|md5(\$salt.sha1(\$salt.\$pass))|799dc7d9aa4d3f404cc21a4936dbdcde:68617368636174|
|21400|sha256(sha256\_bin(\$pass))|0cc1b58a543f372327aa0281e97ab56e345267ee46feabf7709515debb7ec43c|
|21500|SolarWinds Orion|\$solarwinds\$0\$admin\$fj4EBQewCQUZ7IYHl0qL8uj9kQSBb3m7N4u0crkKK0Uj9rbbAnSrBZMXO7oWx9KqL3sCzwncvPZ9hyDV9QCFTg==|
|21501|SolarWinds Orion v2|\$solarwinds\$1\$3pHkk55NTYpAeV3EJjcAww==\$N4Ii2PxXX/bTZZwslQLIKrp0wvfZ5aN9hpyiR896ozJMJTPO1Q7BK1Eht8Vhl4kXq/42Vn2zp3qYeAkRuqsuEw==|
|21600|Web2py pbkdf2-sha512|pbkdf2(1000,20,sha512)\$744943\$c5f8cdef76e3327c908d8d96d4abdb3d8caba14c|
|21700|Electrum Wallet (Salt-Type 4)|\$electrum\$4\*03eae309d8bda5dcbddaae8145469193152763894b7260a6c4ba181b3ac2ed5653\*8c594086a64dc87a9c1f8a69f646e31e8d3182c3c722def4427aa20684776ac26092c6f60bf2762e27adfa93fe1e952dcb8d6362224b9a371953aa3a2edb596ce5eb4c0879c4353f2cc515ec6c9e7a6defa26c5df346d18a62e9d40fcc606bc8c34322bf2212f77770a683788db0baf4cb43595c2a27fe5ff8bdcb1fd915bcd725149d8ee8f14c71635fecb04da5dde97584f4581ceb7d907dceed80ae5daa8352dda20b25fd6001e99a96b7cf839a36cd3f5656304e6998c18e03dd2fb720cb41386c52910c9cb83272c3d50f3a6ff362ab8389b0c21c75133c971df0a75b331796371b060b32fe1673f4a041d7ae08bbdeffb45d706eaf65f99573c07972701c97766b4d7a8a03bba0f885eb3845dfd9152286e1de1f93e25ce04c54712509166dda80a84c2d34652f68e6c01e662f8b1cc7c15103a4502c29332a4fdbdda470c875809e15aab3f2fcb061ee96992ad7e8ab9da88203e35f47d6e88b07a13b0e70ef76de3be20dc06facbddc1e47206b16b44573f57396265116b4d243e77d1c98bc2b28aa3ec0f8d959764a54ecdd03d8360ff2823577fe2183e618aac15b30c1d20986841e3d83c0bfabcedb7c27ddc436eb7113db927e0beae7522b04566631a090b214660152a4f4a90e19356e66ee7309a0671b2e7bfde82667538d193fc7e397442052c6c611b6bf0a04f629a1dc7fa9eb44bfad1bfc6a0bce9f0564c3b483737e447720b7fd038c9a961a25e9594b76bf8c8071c83fcacd689c7469f698ee4aee4d4f626a73e21ce4967e705e4d83e1145b4260330367d8341c84723a1b02567ffbab26aac3afd1079887b4391f05d09780fc65f8b4f68cd51391c06593919d7eafd0775f83045b8f5c2e59cef902ff500654ea29b7623c7594ab2cc0e05ffe3f10abc46c9c5dac824673c307dcbff5bc5f3774141ff99f6a34ec4dd8a58d154a1c72636a2422b8fafdef399dec350d2b91947448582d52291f2261d264d29399ae3c92dc61769a49224af9e7c98d74190f93eb49a44db7587c1a2afb5e1a4bec5cdeb8ad2aac9728d5ae95600c52e9f063c11cdb32b7c1d8435ce76fcf1fa562bd38f14bf6c303c70fb373d951b8a691ab793f12c0f3336d6191378bccaed32923bba81868148f029e3d5712a2fb9f610997549710716db37f7400690c8dfbed12ff0a683d8e4d0079b380e2fd856eeafb8c6eedfac8fb54dacd6bd8a96e9f8d23ea87252c1a7c2b53efc6e6aa1f0cc30fbaaf68ee7d46666afc15856669cd9baebf9397ff9f322cce5285e68a985f3b6aadce5e8f14e9f9dd16764bc4e9f62168aa265d8634ab706ed40b0809023f141c36717bd6ccef9ec6aa6bfd2d00bda9375c2fee9ebba49590a166\*1b0997cf64bb2c2ff88cb87bcacd9729d404bd46db18117c20d94e67c946fedc|
|21800|Electrum Wallet (Salt-Type 5)|\$electrum\$5\*02170fee7c35f1ef3b229edc90fbd0793b688a0d6f41137a97aab2343d315cce16\*94cf72d8f5d774932b414a3344984859e43721268d2eb35fa531de5a2fc7024b463c730a54f4f46229dd9fede5034b19ac415c2916e9c16b02094f845795df0c397ff76d597886b1f9e014ad1a8f64a3f617d9900aa645b3ba86f16ce542251fc22c41d93fa6bc118be96d9582917e19d2a299743331804cfc7ce2c035367b4cbcfb70adfb1e10a0f2795769f2165d8fd13daa8b45eeac495b5b63e91a87f63b42e483f84a881e49adecacf6519cb564694b42dd9fe80fcbc6cdb63cf5ae33f35255266f5c2524dd93d3cc15eba0f2ccdc3c109cc2d7e8f711b8b440f168caf8b005e8bcdfe694148e94a04d2a738f09349a96600bd8e8edae793b26ebae231022f24e96cb158db141ac40400a9e9ef099e673cfe017281537c57f82fb45c62bdb64462235a6eefb594961d5eb2c46537958e4d04250804c6e9f343ab7a0db07af6b8a9d1a6c5cfcd311b8fb8383ac9ed9d98d427d526c2f517fc97473bd87cb59899bd0e8fb8c57fa0f7e0d53daa57c972cf92764af4b1725a5fb8f504b663ec519731929b3caaa793d8ee74293eee27d0e208a60e26290bc546e6fa9ed865076e13febfea249729218c1b5752e912055fbf993fbac5df2cca2b37c5e0f9c30789858ceeb3c482a8db123966775aeed2eee2fc34efb160d164929f51589bff748ca773f38978bff3508d5a7591fb2d2795df983504a788071f469d78c88fd7899cabbc5804f458653d0206b82771a59522e1fa794d7de1536c51a437f5d6df5efd6654678e5794ca429b5752e1103340ed80786f1e9da7f5b39af628b2212e4d88cd36b8a7136d50a6b6e275ab406ba7c57cc70d77d01c4c16e9363901164fa92dc9e9b99219d5376f24862e775968605001e71b000e2c7123b4b43f3ca40db17efd729388782e46e64d43ccb947db4eb1473ff1a3836b74fe312cd1a33b73b8b8d80c087088932277773c329f2f66a01d6b3fc1e651c56959ebbed7b14a21b977f3acdedf1a0d98d519a74b50c39b3052d840106da4145345d86ec0461cddafacc2a4f0dd646457ad05bf04dcbcc80516a5c5ed14d2d639a70e77b686f19cbfb63f546d81ae19cc8ba35cce3f3b5b9602df25b678e14411fecec87b8347f5047513df415c6b1a3d39871a6bcb0f67d9cf8311596deae45fd1d84a04fd58f1fd55c5156b7309af09094c99a53674809cb87a45f95a2d69f9997a38085519cb4e056f9efd56672a2c1fe927d5ea8eec25b8aff6e56f9a2310f1a481daf407b8adf16201da267c59973920fd21bb087b88123ef98709839d6a3ee34efb8ccd5c15ed0e46cff3172682769531164b66c8689c35a26299dd26d09233d1f64f9667474141cf9c6a6de7f2bc52c3bb44cfe679ff4b912c06df406283836b3581773cb76d375304f46239da5996594a8d03b14c02f1b35a432dc44a96331242ae31174\*33a7ee59d6d17ed1ee99dc0a71771227e6f3734b17ba36eb589bdced56244135|
|22000|WPA-PBKDF2-PMKID+EAPOL [^1]|WPA\*01\*4d4fe7aac3a2cecab195321ceb99a7d0\*fc690c158264\*f4747f87f9f4\*686173686361742d6573736964\*\*\*|
|22001|WPA-PMK-PMKID+EAPOL [^18]|WPA\*01\*5ce7ebe97a1bbfeb2822ae627b726d5b\*27462da350ac\*accd10fb464e\*686173686361742d6573736964\*\*\*|
|22100|BitLocker|\$bitlocker\$1\$16\$6f972989ddc209f1eccf07313a7266a2\$1048576\$12\$3a33a8eaff5e6f81d907b591\$60\$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb|
|22200|Citrix NetScaler (SHA512)|2f9282ade42ce148175dc3b4d8b5916dae5211eee49886c3f7cc768f6b9f2eb982a5ac2f2672a0223999bfd15349093278adf12f6276e8b61dacf5572b3f93d0b4fa886ce|
|22300|sha256(\$salt.\$pass.\$salt)|755a8ce4e0cf0baee41d714aa35c9fca803106608f718f973eab006578285007:11265|
|22400|AES Crypt (SHA256)|\$aescrypt\$1\*efc648908ca7ec727f37f3316dfd885c\*eff5c87a35545406a57b56de57bd0554\*3a66401271aec08cbd10cf2070332214093a33f36bd0dced4a4bb09fab817184\*6a3c49fea0cafb19190dc4bdadb787e73b1df244c51780beef912598bd3bdf7e|
|22500|MultiBit Classic .key (MD5)|\$multibit\$1\*e5912fe5c84af3d5\*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de|
|22600|Telegram Desktop \< v2.1.14 (PBKDF2-HMAC-SHA1)|\$telegram\$1\*4000\*913a7e42143b4eed0fb532dacfa04e3a0eae036ae66dd02de76323046c575531\*cde5f7a3bda3812b4a3cd4df1269c6be18ca7536981522c251cab531c274776804634cdca5313dc8beb9895f903a40d874cd50dbb82e5e4d8f264820f3f2e2111a5831e1a2f16b1a75b2264c4b4485dfe0f789071130160af205f9f96aef378ee05602de2562f8c3b136a75ea01f54f4598af93f9e7f98eb66a5fd3dabaa864708fe0e84b59b77686974060f1533e3acc5367bc493915b5614603cf5601cfa0a6b8eae4c4bd24948176dd7ff470bc0863f35fdfce31a667c70e37743f662bc9c5ec86baff3ebb6bf7de96bcdfaca18baf9617a979424f792ef6e65e346ea2cbc1d53377f47c3fc681d7eda8169e6e20cd6a22dd94bf24933b8ffc4878216fa9edc7c72a073446a14b63e12b223f840217a7eac51b6afcc15bfa12afd3e85d3bd|
|22700|MultiBit HD (scrypt)|\$multibit\$2\*2e311aa2cc5ec99f7073cacc8a2d1938\*e3ad782e7f92d66a3cdfaec43a46be29\*5d1cabd4f4a50ba125f88c47027fff9b|
|22911|RSA/DSA/EC/OpenSSH Private Keys (\$0\$)|\$sshng\$0\$8\$7532262427635482\$1224\$e1b1690703b83fd0ab6677c89a00dfce57fc2f345ebd2b2993bf0d8bb267449d08839213dc234dd23c7a181077e00080ced2700a161c4352ce5574b9758926f09106157715b6d756cf6dd844e473c6bb3c2b591cdbf684394a49935f7d62bcc324c1392aee499e3d6235db0556d27adc6e35ef4654ee5fc72e60dff605484e75c6fd6ae29cb476f8a658dbcce9f9591a9dad023f6d9aa223c3d56261e056c5cafa93438937e0762b989cd10e6280a09488be07423c549514ff9686338e72dbe6bdc5015944739a9f183cacf04c1c141dc8c8d8aa8636c85a6c0578a5983ed33d5ff5ee6a66a54d86defd1c4f9d6a59446861bf4cc7bd667bc92b9d328c154f442d1d03d4d370dcc065a1d5420c5b71e4c35a457e11a0c9f489636559a2ac53bb4cfee2b0058f8a9d1ccc38a844ee0d1ff5d6938427bf24d6e4c69f10e6ebce9187d51e867ac3b362b9c6149712e8378a9ac91d1aab1a7a5f088ddbdead0cc754c30961b7a71284b5c6658f7219632de6007d5145a1ae062f807234230ff73a3436ce28ae3bfa0f880d1e49ec8a288da18db14905bc7a7b061a51c429876db81ad528efb469ba2bf46c7344aadc7d082efc83ede3894bf6b1738151e642f6f60a41069ad862d2f4f8d55733bd6d85086d1d9bb1913a9d4680ea0b49f712c590a3c18b91ef745b9bdf461af67879d94f9672de4abe0b7d2e4efba1f8bb6ffbb4a095742d5cff0e225b1b5e166854bb9821e4283d97f80855c81efea1eb3e7881a6049186650bfbf68f30302c069883668e373c12ce9a39de8d7c1be22a717d9c74410c45093aae03c5de8cc0ec662fe3bb81bf952e17b854001bcad9b36cab2f473a609878a419b735c66f3732bd5540fb1cba9fe081f87cecf63a6243cd2049dfa25a763ef2e0633bfb13a411207d8ca1c8f3c0c30b8a7583436cad7bd8c28ba625b9c53dc280b314671b0a55d75a28d3b21de250e3c554b86ca5d32821ab912c6607687c4dc5b3214216a7409621ce6fb89bd5309a7dd8ec9ae4b751bdfb6b5d12d733a89d87722dbdb1b15df5463241f0f56c401e095ea5dee07c0ded1f11ffbd7c93a41add0cfd8c57b44f255fdfd1929cd7d068d6cf951ba8ab0d718996fec10aaa26a4314d4c1272f744adf3c7e4d710ae171c072a7c61c2b020a445cf32be3083d3bc62083f2385bbae4fadddf8714258b996abd574638891bb918e877fdef3a4856b910999a6dc9dbd13c0e938825cd895c96d39cb86bb283a53fac7090c71a9320c6a34af309d2218af64c895f5eff8eee28cf94e7a7437a0922d83bfa39f08bb40e354d9ace07aa586a446dc217ede98b6ca9637545cc11ef56732fc9cd3dc06e459d868137b75d39a87e6721a95f2b84e57c94ef703486a2857821e497b990c95080015d825b6dc63d666f66cfa35912e607c3b650d81dc98c0c53322796ff9249cdfe7a375e1d01607816a85bb43f3969767a9aaed07161344e714d7e875b40f3524f95e476e605dbd2ac51e36075701fa93b66f36470796ebf5d35690a297e19729f9ac59d98622e3ad3e45a2914bdd2b807446c8b430e54c1a607fd25a69bf469a61d2e3bc3697b786c047bc60dbeabe6372d71e9b7c9787bb2559c663a011f864ecf32793e65f4bdd76370d99f602ddcbc7e5aa7d2749f36e8d0f209a378782882bc06ee5b5014c2a6248469f0fe0fc5369383db0bc898c0760b8c40fe20342fa5b|
|22921|RSA/DSA/EC/OpenSSH Private Keys (\$6\$)|\$sshng\$6\$8\$7620048997557487\$1224\$13517a1204dc69528c474ef5cbb02d548698771f2a607c04ea54eb92f13dedba0f2185d2884b4db0c95ce6432856108ea2db858be443e0f8004ffcd60857e4ff1e42b17f056998ec5f96806a06e39cc6e6d7ef4ce8ae62b57b2ec0d0236c35cf4bc00dd6fda45e4788dcca0f0e44dddae1dad2d6e7b705d076f2f8fc5837eec4a002d9633bcad1f395ca8e85e78459abe293451567494d440c3f087bb7fe4d6588018f92ca327dda514a99d7b4b32434da0e3b1bf9344afb2fe29f8d8315a385fe8b81fd4c202c7d82cd9f0bb1600e59762ab6ea1b42e4e299f0a59ce510767e1e1138453d362d0a1aa6680e86b5aa0bd5c62165f4fe7c2867f9533578085adc36739d6c9cf7b36899aac39dcabac8b39194433423e8e18ba28496bbe14dd01231eb5b091ae9de0f7f9ea714c22edac394077fb758fe496e1880571ade399ac229457ddd98577f8a01a036ad3bc8b03a9fb02e26b4b76f6cb676eabe82d1606fca0c5fca62cd1d82c3df1ed58ab4acd4611b2827ebde722bc05e471a427225818aa36dabf5bf1203ccb0ebc8dec097e49f7f948bfe7b939e6d0ff1125b863c033768f588964f8b77ca1e2425751f873f80e5d6a0671f7860cf4a46533585094726c3afe5f7203fa4a01650fa9839772c713a033139cfc6a6e6f7dc62e5844d4c57ef4fc3321bc85d597a54bd6fe37e9e696cf3b5ec66f55232e0964dc5cf880d8a41a9891150618bd9c088fd9824af0d86f817f2c79429c3d56cd6eb41eb6120f9accc10a863f23a2bb6c57d4bd6193f2283ae0215e2e87e672a8438e2550c044fa9556bdb4afc40d8c2752ffbc6c95571756a3c230bb2fa95f519f8da238ef0857ecf860247a8b26e28269f9bad564e7d8bfba2eac9760b52449251cb35e183f5b309a09071535154c6f1013b58f305b544f3589c9eb0e9ac4267a84374a3eab49c53aa9bedbf97f8f19ebc212d8db74ee03554a3514140667fa4ce8e06aad3f32d1b00015be0e8979fe66736018589beee06d6f318851dbe8d9689e70202185d71fc5e5a3d2996ddb8ae1d7718c49855c6f8c43301e0915f324f30d0d9c6a8504a91ad5a7179aafb87ede58598394949910874850994abe815817359152ff6a7c8cc6f19524dfc5e50ddfd038a2275bf809e3c8f05ed3e3137ebd62d91cd3578533787c3847e3c5e07e5a891480e5ceabcf6c344e7bec8b640ab9a03e90b846b35d2f46ba150accef32d2597b064810b15fd54fca6d2b146feabcd05c0b51617ae95e36f6817a62c3ff42c5c2f6f1d20a8a1fd334d3b7d3f83bba057b79d9b5508bb0cb706ba00acb0ab797401fdcfac80b5b6e38e51aec0b38f33ff4690425ca28d88a2e876591521230150b4e20a4a82e50061cee9c0705100bfe5fdbd8ef27aec20387cf32455ef305bce2a91ae6da91fc41376b97149e9b41c901b24811df9272ff09718923b8d94e8e459a164a22b0eca47653f3efcbf08188c5da78cd9fb9eda1761094f9d8bc3d479e9f40c7d79ebaaba2a5c632329f20a9962040ff8f512b42c5f32a8460d87b8e93c6f980a1562c436eea1c8994fbf671dda3c4ccd3c142acfcdde2ab61227289ad408213ac8e22d9ef487f36925f5ba3b8e7e913d25c4a8592c861d13f03b615bc2760aabc61d68db80d35296a3312fdf4b56c0fbee5ab3fea1cf9caf3960a564046939e8002d2dd909db446d85aeae9dd42a33fe28684f722172e6|
|22931|RSA/DSA/EC/OpenSSH Private Keys (\$1, \$3\$)|\$sshng\$1\$16\$14987802644369864387956120434709\$1232\$ffa56007ed83e49fdc439c776a9dec9656521385073bf71931a2c6503c93917e560cc98940c8cdcf2c709265e9ba20783a3bacc63423a98e40ea8999182613e1f5a80084719ca0e5c390299de1ea947df41f2ff1489bddfe13c6128612c5c82b7fc1ef5105ea28adda7b415729c66fb6cbc4b6b51ef518f74e1971f88e0cfabd69e8c4270678e360149ce15716fef4736df296a20d2607ef269a3c69896fc423683d6057e00064f84e04caf4d4663b51b307cfb1d1dbd6b3bf67764a08847c7b83fa5544e6a1e950f16acda8c8bac30675bc3cea9c7e06790ddc7cd1e4177b93bdd0d9edf9cdceb4a4444b437d967acdb92274a7b10d9cd1073ab4e9b5dd468aabe1f40a02b2e51f19840798c2311b625037eba5f0a0256638b42577385f4d4c730a9cedf4e244ce74656a21bf16756857866433dbb1feff9c4323d234d4235b72ed5a3adc3a6c9bae373472d64b7882d1762911326f330cb42d8ab7931f1ad2de56c4e6e8a6e838108cf9a2728ffa356796f63d94723b1d0aad5b4fcea16ab0730e7553804ad9ffb6ecdbdd925fca05ca1c076ed09a30df8a5add44a43c36b92248dc8dd4605bc2ee557e6e4438abf9ea7d047f764c55a5ba46a41719b9c55e54ad5fbfce6a89b9283c163d8464ecdda5aaf113d038b659950b8c79e87abad019eb77535cc8e63f760a4c87ca344a563475361766df718519b1b7e4b3ab511952fcc9b011f1d8971f9261509139b739afcc2c9acd006ee714dffc8c9a4df0d54770d70c8c28c27cdf9ee7301fd64530ef0ec3eb044fb891b193a7aaa9158625ed9f5a842c86ed09e5377d90a69aea4c5fd321bc3ac9b2a0d34509a5de0b72ac3f81304895c4381e01136b1e8654cec20c220c0ac6a1300f031ffc68ddeab554279024c122589b91556feef394a1663b42fb8460af5fe881cb1cd4984b84be75125411b1d3fc236dd81f99b872aad511d28944e91d2f8853f11be85b6930a15b4d0b3d215d76416970ade5726979c1d737980fb68ecb03d1196a69f4013dd2e296a75a4c69664b0162cb8b22af18c536a8ce51f39b1282f2fe07e6b034627f075cfb20dffee62817aabeea60befea1ac93ba608d957e4030e41be7bc55275bc4037300f6ba736370eb7c9240629853c95f9304b7ffd26a10d55ae735fa943e29aa9ed437b61955fc16cde9ea7a3658d831bdbc38befa45cec80da9ccb6d21da83ff666e32d7c5c0ca0ade2cd685407ee701c1c707fc5c80b22f3af42ac1353fcdc09a459086434db7c78792decdc91572363478a14d1256346a9ac6336b8183ed6252106aa546dd092c0bbb464cdb44ae165d67d1be135877587de3bbbd02b5ef6473f125366f6dae0536ebbe18ab8de8ce2ef3d26d6dd400319e7d07ae276b081e94446e9a72877cf23e9ba52406b1842e3a0dcf7bbdc63a1336b894be475613cc917eb47724f64e621bfc3053d7423e3e2fb141a3368dc8881fa20e040e9a6bc2e7348e923e4c20e506566b8663bf7d557e792cbe4adffcf9c520d58565d77f6bf1c9ed5fa3209f8047765d01b9c264e97a3ef9ff90766ad69a4f508041e168bf0f7419e54ec88bdc4c858231cdba60774a27cc459cd65b46e26a620a43033788c6e2ee8916670568d6e6c700515f2cbca3eef62028ce75245cf8f99cd6e0ba7839a7b335c797a06ff80571950ebec2fccebb89265025b3250e4a5c9c3a62f471324556fc4db044cebe97f62c86913|
|22941|RSA/DSA/EC/OpenSSH Private Keys (\$4\$)|\$sshng\$4\$16\$01684556100059289727957814500256\$1232\$b04d45fdfdf02a9ca91cbc9c53f9e59956822c72c718929aca9251cffd9ac48e48c490b7b6b6043df3a70cf5fbcc2f358b0e8b70d39155c93032b0fd79ec68f6cb8b7de8422ec95cb027a9eaacc453b0b99b5d3f8d6771d6b95b0242a1d8664de8598e8d6b6d6ee360fda5ae0106061a79e88ef2eef98a000b638f8fdc367155ec2d1120b366f74f0933efe5d174e7107db29dc8fb592b22b9837114415d78036c116b2d31b2080c7159442f2d1a61900f5ae4913548c8e7fc716dd4f812bc7e57b2dd5d3f56c6ae0e91c3bc2897d9341cb282d86b915d43cf20ad16fbd2056104529576142354a430281f5e458923ef8014ff9950351798bfcbbcb66cb98bb2cccea48c134b0e05e978d4308c82617869b207f0ed7b227893f2cdde2d6b6a98246de8a2494d5e018a84724780fbe8d1fa91c922908d18ccffbbbbc81e6578fe8bb5c8596a8cf689f3f12b810dee95887e12439e487313229a37913e3cd12bddba3bac94fab03aad8607f6034fa87f7a7a2ac74d0c0a6e6bc905f569221861e1e388cf379cda799d7b56eac58440d17fe97fa68a537d34317376c00dfa9a99e04725a0d2fcf27ee50463e725813c96fe2eed16de59e8a6944d903e11f7923d57ae6d4a1f8085ce19f4d180f13027806f3965fdf875ea092f103f28a5f42f356254958fa7eb0bca2389a6ad4e305640cc64501e6b16330b063037b1cf6fe64131f308e50d9d1dc687ffa487681941084ff21cb54c1b5903b7a78d9913595fa0124f1dde49b1bee2ea83837efe34e2cd6051a4a7a1437eaa84ad332ffd9946b952ed634948789d9541820a0f9c6f44ab6d3cad645743c76c54e79bfdc4fb8e43a0fd7d871baea98e78131bc530b6d736fa1ec5ac70438609497ab2ff8d516146b4b1b3488791cb84dccc0096b570e2ffb3a93cccefec0af7ce616a64466d2d4196941ba9e051dc00ed05e963a7b4a286973ee0b5df4fd92dfb0b229b10730d454832d945c6a596862212d109ce78ac14ffb5d775548b2f3e2ae4be059a24465cc10b7c810f8cc3db7cb327619cc104ebea575ac097d20701dc623f7aa893b785cc20851f3972390e00ab3355655f7d5bea323832c17d8e078e917843ef7fcaca349366092b6743bf7511d5fceb2d992fbd18574be532365be41ad80a114704a64a7aefdf98c907aa10e4d5c547dd8d21647ea9d5c975fe1b24525d94c3eb03e071742fd5f09f22da669b649fac9f87d8cf16c475d006421f69a9b2d5c4037ccc9bf9f0aa0e7df8ac5fcb0d88a528833f9640799026d2fe8694fa1a0307c5f24002172464b290bedd85667800edbff2f1de7119e5b65730a24922e42d53ef28b0a59817a298426dc72e29a85e59e3d777b19eb934bcd620a903aff72927cdbe7253f77694ab0ef970378b4347f6166ca2a40b23cc31970f0cbefd08d2d72bf2c3961d67c73a5a24f75a65e540dc5735520b0d81250af8980ddca3e22a9b25773afd27c76e564ff437d4208df14d802f1d0848390f45924cdd6ced3c9ffb726bb358b334ea0e0481acdd103f2db05f508f62588621d0b8fa274a69eba0d418d85086d9139391f7e28dc54fe9bab801f1fea854f27ad2e5907ae6f9a4b4527d16a8af3c8cbe2c6d82209dc6c7da060da58294eb00380598330c4c19d45581d09e04c0153a8559700b3a8ceab9b8124f84d397356cd9e38e3916afc1f63a3e1dfbc7df8dd0a7d0704e38a0ea523dfc2b9defd5|
|22951|RSA/DSA/EC/OpenSSH Private Keys (\$5\$)|\$sshng\$5\$16\$52935050547964524511665675049973\$1232\$febee392e88cea0086b3cdefd3efec8aedb6011ca4ca9884ef9776d09559109c328fd4daef62ea4094a588d90d4617bc0348cc1205ae140e5bdca4e81bf7a8ff4fcc9954d3548ba9a0d143a504750d04d41c455d6100b33dacc5f9a10036ae75be69a81471e945554a52ca12b95640a08f607eab70c4a750dc48917f3c9ee23c537e9b4a49728a9773a999dfd842cf9a38155029ea5d42f617dbec630889d078ffadaf3ff28eed65389a73528f3d0863fffd9a740edd59ca223595e330bca37ac5a003ac556d2b6232f9900fc8654586e73e7b2d83327d61b2fc561a78aacc8aff473bb3d18ddccae87d84de143a8a98550d955d01d4e6074ac62aa0af0bca58a0c53d0d7cf1a26345c1bd3eca7a0c0e711f5c7f942d50bc872be971d0c17dbc5a88f043a937ff5d28c5ef8d8d291e511d070b14a0cc696ee5088a944b113bc7e697cdc793e931c3f0f3a892b44aad1468e6c45becdcaa89febda17fcd5fe6ff430695e04b5b6271e032e3529315367e56337777a5b342c19d3ebc7441ac0f79b93749ad4526b8be0a5cf5756363aac93da6dc19dbfff15bacbbf2dae7a549afdab8e0589321ac0a612576bbfe06fde086075d1244450a3667f793ccc81fd5ccc5b1d08e6f447e3e0cd89b901049bedb1e65b23ede0d8f00ff1c984743b50342c50408e9060ed6a809a7b068972c9542cd91de0767c02a73d192ea600008bf4a6ef339c7f2db767346cc479e61abedb4ba4a67f72e91ac49a2e92bb4bacd97aed0b044c258e2004fa0fb8da3678a57d37187c1246c90a107540161462145fa7307a6d4db34694fb1b090f07bedb9ca0e71aefd3ce5601b87778fd6b66391c3c61d528a5965f91370f52a72f0622620329f96c5dd68561e0f6576f3a2bc5c21a95aed569edc4ed979746b32909178e550907c5f41d7b24480e81a874b931c23f13517ab5f9331f11819d982bf9e5b8a03034b47c8785f8902611eac26716976bccd51d19864f10ee1fbd62f8b0149c22ab06205a20f9f9fcb0a5279552a8923c3ace2e134f6b190653f430c1a4b82f762283028d9c0c8d1a3428731f4f405f40f947f297a43aa3ba2267bbc749a5677da92a63d51d24aa5ca3e9e1d35a8143d7b4bac481f0c56754e980a60cf2d330797fc81f6c6f405760f1257103ac6edf10976c9005f4a261f7aad055400c4f18dc445eb3a403740ad6c58afa4e8edb30fad907488baf0ede2eb3d3687d1e8724dd69c7bd14b90d4f113fc9f84a2c01ab00917f53cd879a4031b1c91a4d4d7d9e712a584959137001d331f6725dca81ea6cc55fac7fc0e8b578dec0983ca98c3789cdf83507e4c3ba056fdcbea26693a313077290d7c6695f4cc6de4848532f0149cc06dbf4c76d02944178520585923b636196ea2cbcacc43950b308fc7929e85de076a2ab65c9bd8ebb0c04c041281178a48d8d2165d315b3e74abf0a38505b71ae5b2a6e7f87861e174cff873a1f61980b53ef3acdd2ea6a25425b162e5dc0bc1aa2992585d2da1625a6593cc2d4fe8c86eeb4df0e27cda54685f7245e5c48063d489e8d93bd5303bebe633139dcdd04afa005d03d1185a64e8711c0b09d9d0b38b35d6ef1b1e35353a7a4396863650a3843c687a00396dd3db53e8d28baf29101abb9f628ba896b091618f24187f6eeb814e4b64130768fb37e89b9b3230e50a7e5aba852a983525c8f193deb1fe27b334cdc3bdfa4c301d04907ee29a848393|
|23001|SecureZIP AES-128|\$zip3\$\*0\*1\*128\*0\*b4630625c92b6e7848f6fd86\*df2f62611b3d02d2c7e05a48dad57c7d93b0bac1362261ab533807afb69db856676aa6e350320130b5cbf27c55a48c0f75739654ac312f1cf5c37149557fc88a92c7e3dde8d23edd2b839036e88092a708b7e818bf1b6de92f0efb5cce184cceb11db6b3ca0527d0bdf1f1137ee6660d9890928cd80542ac1f439515519147c14d965b5ba107c6227f971e3e115170bf\*0\*0\*0\*file.txt|
|23002|SecureZIP AES-192|\$zip3\$\*0\*1\*192\*0\*53ff2de8c280778e1e0ab997\*603eb37dbab9ea109e2c405e37d8cae1ec89e1e0d0b9ce5bf55d1b571c343b6a3df35fe381c30249cb0738a9b956ba8e52dfc5552894296300446a771032776c811ff8a71d9bb3c4d6c37016c027e41fea2d157d5b0ce17804b1d7c1606b7c1121d37851bd705e001f2cd755bbf305966d129a17c1d48ff8e87cfa41f479090cd456527db7d1d43f9020ad8e73f851a5\*0\*0\*0\*file.txt|
|23003|SecureZIP AES-256|\$zip3\$\*0\*1\*256\*0\*39bff47df6152a0214d7a967\*65ff418ffb3b1198cccdef0327c03750f328d6dd5287e00e4c467f33b92a6ef40a74bb11b5afad61a6c3c9b279d8bd7961e96af7b470c36fc186fd3cfe059107021c9dea0cf206692f727eeca71f18f5b0b6ee1f702b648bba01aa21c7b7f3f0f7d547838aad46868155a04214f22feef7b31d7a15e1abe6dba5e569c62ee640783bb4a54054c2c69e93ece9f1a2af9d\*0\*0\*0\*file.txt|
|23100|Apple Keychain|\$keychain\$\*74cd1efd49e54a8fdc8750288801e09fa26a33b1\*66001ad4e0498dc7\*5a084b7314971b728cb551ac40b2e50b7b5bd8b8496b902efe7af07538863a45394ead8399ec581681f7416003c49cc7|
|23200|XMPP SCRAM PBKDF2-SHA1|\$xmpp-scram\$0\$4096\$32\$bbc1467455fd9886f6c5d15200601735e159e807d53a1c80853b570321aaeceb\$8301c6e0245e4a986ed64a9b1803afb1854d9712|
|23300|Apple iWork|\$iwork\$2\$1\$1\$4000\$b31b7320d1e7a5ee\$01f54d6f9e5090eb16fef2b05f8242bc\$69561c985268326b7353fb22c3685a378341127557bd2bbea1bd10afb31f2127344707b662a2c29480c32b8b93dea0538327f604e5aa8733be83af25f370f7ac|
|23400|Bitwarden [^21]|\$bitwarden\$1\*100000\*bm9yZXBseUBoYXNoY2F0Lm5ldA==\*zAXL7noQxkIJG82vWuqyDsnoqnKAVU7gE/8IRI6BlMs=|
|23500|AxCrypt 2 AES-128|\$axcrypt\$\*2\*10000\*6d44c6d19076bce9920c5fb76b246c161926ce65abb93ec2003919d78898aadd5bc6e5754201ff25d681ad89fa2861d20ef7c3fd7bde051909dfef8adcb50491\*68f78a1b80291a42b2a117d6209d3eb3541a8d47ed6b970b2b8294b2bc78347fc2b494a0599f8cba6d45e88fd8fbc5b4dd7e888f6c9543e679489de132167222e130d5925278693ad8599284705fdf99360b2199ed0005be05867b9b7aa6bb4be76f5f979819eb27cf590a47d81830575b2af09dda756360c844b89c7dcec099cfdd27d2d0c95d24f143405f303e4843\*1000\*debdeb8ea7b9800b01855de09b105fdb8840efc1f67dc742283d13a5570165f8|
|23600|AxCrypt 2 AES-256|\$axcrypt\$\*2\*10000\*79bea2d51670484a065241c52613b41a33bf56d2dda9993770e8b0188e3bbf881bea6552a2986c70dc97240b0f91df2eecfa2c7044998041b3fbd58369cfef79\*4982f7a860d4e92079bc677c1f89304aa3a2d9ab8c81efaff6c78a12e2873a3a23e6ae6e23a7144248446d8b44e3e82b19a307b2105570a39e1a7bed70b77bbf6b3e85371fe5bb52d1d4c7fcb3d755b308796ab7c4ff270c9217f05477aff5e8e94e5e8af1fba3ce069ce6fc94ae7aeebcb3da270cab672e95c8042a848cefc70bde7201b52cba9a8a0615ac70315792\*1000\*e2438859e86f7b4076b0ee4044ad5d17c3bb1f5a05fcb1af28ed7326cf71ced2|
|23700|RAR3-p (Uncompressed)|\$RAR3\$\*1\*e54a73729887cb53\*49b0a846\*16\*14\*1\*34620bcca8176642a210b1051901921e\*30|
|23800|RAR3-p (Compressed)|\$RAR3\$\*1\*ad56eb40219c9da2\*834064ce\*32\*13\*1\*eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1\*33|
|23900|BestCrypt v3 Volume Encryption|\$bcve\$3\$08\$234b8182cee7098b\$35c12ef76a1e88175c4c222da3558310a0075bc7a06ecf46746d149c02a81fb8a97637d1103d2e13ddd5deaf982889594b18c12d7ca18a54875c5da4a47f90ae615ab94b8e3ed9e3c793d872a1b5ac35cfdb66c221d6d0853e9ff2e0f4435b43|
|24100|MongoDB ServerKey SCRAM-SHA-1|\$mongodb-scram\$\*0\*dXNlcg==\*10000\*4p+f1tKpK18hQqrVr0UGOw==\*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=|
|24200|MongoDB ServerKey SCRAM-SHA-256|\$mongodb-scram\$\*1\*dXNlcg==\*15000\*qYaA1K1ZZSSpWfY+yqShlcTn0XVcrNipxiYCLQ==\*QWVry9aTS/JW+y5CWCBr8lcEH9Kr/D4je60ncooPer8=|
|24300|sha1(\$salt.sha1(\$pass.\$salt))|94520b02c04e79e08a75a84c2a6e3ed4e3874fe8:ThisIsATestSalt|
|24410|PKCS\#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)|\$PEM\$1\$4\$f5662bd8383b4b40\$2048\$2993b585d3fb2e7b235ed13d90f637e2\$1232\$73984f2cba4d5e1d327a3f5a538a946099976ab865349091a452a838dc6855b6e539f920a078b14d949d8c739ea7ce26769dc0ba1619a9c0ee1864d1cfca9e61ddf6d9582439f2b65d00a3ff57c78d3176e9e88fc12da7acd421b624ba76f3d5f12926a3a9acd82f502d7638cfe2063fb2c773a56299ae1ec2c85641d33f5f8b3edfc6687fa9898325d384b3db7a7686704facb880c3898f69dd353a5d5d136b58a1e00e4711d3a01e0c632a5f3d5eff64c9e88166296b9b26f072a52bdc4893377e247b5cdb052f34e0b5d4de10a5dffe443a03b1a23f1edbcb00361334dbd6a6d31e16887b5290da2f865fbe1fef7b43c8f8f3432815ca860946560cb601ab83d417e6a4734aaf75692195566bde61e04610a9eff752c08f9ff85a48959daa7c65d03a0eca62e92bf10a55fb4834a49745a6c53d9c79d0591cb13cfa54f0d437d001b7924fd9dd69c98aa25e5d3f19649f79913bca827e7636ede04bf7c41ef54c42936b4eb93c75d941853dc7dda42b51ac5e4f5602fe2c3e62f252d28e02398943780598cf2bd41d183425daf34e86099c748eda2d5372029ebd089f619dab327ea728eb90342f2b48cd364e914a6078599afdb22a6fac6b55e1bf28b3284a0edc748b59c2eaa97e35d457d4c049f86fd3fc618c4c52f08776c0efb33011b96ef6f0b0e6ecf6d37dc20da8ab7d9b8154371c8e396d9b89ee02e6e6b013a0985b1f47c91f3b5a9e6c33736840e6044f46be1dbea4ec7730eccc6e993cb522bb220de4ed55156129f821d7df19439ab86990991cfd1992681716b5ff012ffa5519ad0baa01885f77f6a522469979f449232d408379558fcdfe5253371da835e0c77706dfa67ff28b1cd8d7fdf9e386899838532d8e57ec1ed3d31a96ae03f37b976fb6c503cc247113deaa070697728e3b36ce43de051ce13a4df91d22157c6281e8f9a16de007c6dddf03ffc79a9f4cfc3eaddd637a9a902fdba1c9e857a9ccd7c318db17cd40d8b588b5d97c7d03c0404473dd201aa5c6637e952c6299e35374127276b3eb4aeba754f3176fecea1731a0f917dd049fcdab34264a8c635ba90eec941aeb449a7eca263aaec9e46758bdf21caa896adb4652e9564d75c20e296fcdf28cbdeb702a1e7acf2374d24b51e6492b0bcc72a58748666a7278e2cb54fbdb68c6736ceb85dd92cd0465b19a65f7ad47e25658a34c3531db48c37ef279574e1892d80d80f3e9dee385ab65e6a4537f6e318817a785228160939d01632b8269858ce9092359048b09ae8b9c17ceb575216988bbeb91c1b5861c931f21e07d888ceb9b89d89d17608e2d5f0ae66b6e756f1eac9f80e13749f866ea6b741158296d3ced761999ad901a2121e233bf173865b6c0b32d68e6ef1d39bb411a1ee9d4d1cde870645b9922051b31cc0df640fb01d23c613091ba538999254b873fbb5996efdfbde5c933e1b6ef6d1c7d5e1a9bff6800c8625b07aba2c14143c1a33a0661c357e5db59a2f49aab35c13531774fb5b3795ed853d7f4e38910c7eeb3435353e2cfd0c94e61c16c8126928343f86222c5ef320b9e043d3cd357af4e065500f50e6bf9c260ca298bd5507c9498dbcea4ceec834449b7fb7249fdf199f66aa98d0a820b1057df1d67c43f49c6d18c3c902466b2b2b528075489261ef73bf711c7988fed65693798568bed43e4d70a800cd25b1773c455aaa153cea8f7013eae1e8f24c6793f590c8f6a112b46|
|24420|PKCS\#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)|\$PEM\$2\$4\$ed02960b8a10b1f1\$2048\$a634c482a95f23bd8fada558e1bac2cf\$1232\$50b21db4aededb96417a9b88131e6bc3727739b4aa1413417338efaa6a756f27c32db5c339d9c3ba61c746bbe3d6c5e0a023f965e70fb617e78a00890b8c7fc7c9f5e0ab39f35bf58ab40f6ed15441338134d041ca59783437ef681a51132c085abb3830df95e9f94d11da54d61679ca6e40136da96ffe205ce191002458143f03cba3aeca6b22a3f0689d5582b3e6c01baee7a04d875ed44bb84fa0ed0a3aae1ed392645cced385498eef4ec25bf6d1399f1487f3625fad9fee25aabf18edb1ce5e640e834d31251b882601f23c2b2d77a45c84e0fc8a3a42e3ff9f75e7ac815c57a7e943ad803ab3672f85a37c6b92d0813590d47a31788643449dce67f135363a0c14f089629a1274b124539535df5f50df5d4402f7a109738f56467725a8aa3884562c8b4c42c068c3502be86e20ac9c52c0daec22e47dcbefebe902b1dc791ed3cd069c7f9211e43f5a3274450f4b0f0b7c6f59adeca8b39ed130b6cbda7cf98e15bbba21fa1758a28dc2edf2e2f17fc353853dc881458e59184f5a8f6e09456e4d71d90135a8ce67350f7bcb3d900e75585e3a87c0c8482f3917347fcfad4fdb8915991cffd20dae1502d0f69d385244e489e50cc9f24b15a5f9d0b00d62805026db5378b5408d7d719786eb043659a452096736e4a7501548655df83045dc4e86bd3319f2982e6db2bbb239019202cebf2ca68c05b578ba95cef82397b145c80208cd7ffd9b0cd5fc3d0d7ea26401c8e11c28ab8d1a524b884962e7fee597943a5e38137abb8b26a7772f0ad6dad074dcfd0b5794822aa7e43d10cab2c95e63b6459706dc21a1cbbd7ae4c96b40ee4d7039cf84c416cb879b2d30b7ac5e1860dcd2ab5479c39b748f5fd9336934c9c1e8064ffb0906c0c2898479209d1a9c97c3cd1782d7514e94d01b242a371a2df5592d620ebd6e18e63ff24ee8ba182f17e6c578431d738e955a957469e8069a919fd3a15532d460201d4e38ac04ac494b9cde1731d4511bf8faf8420a9de4f8c7d3d721fc30d8c3664683fd91ad3515e97092fb652205fb087890cb594947f5372c9b0b27f08b4b57bf610f777fcf040e6e7b8cedf85113dfd909cbac4b774c7580686f2e1f261898da4c6804d573fb22248005f5e0d3b256a0f3dcb71c47b3d674352bda82c22a513e381f990b6100328185511de9b3352126c5aedb9b0bde15743b42e231ef7227c0fe478044ce69474a740366058f07e56dde7d6089cb76e606482e7ba206355fc0fa180c4a41ae781e4723120e3d5a1dd40224db2c959ecbc9bce88bfeed64082d07b111e88a2d8a6a6fe097c9a298a6c3f76beb5b3b5aecedbbbcd404aac8fd25c069c747338ca0c81e6b63d87fc4f0bc18a86b721e3a16e9875741e0313057de8476ee84e36efe557dc33a7d23a9426f2e359781147607ad79235c9d7846320fe2d963fac79a5c92ff3067595273931174d2173f63cfceb9f62a873e7c240d3c260bcfb02b2697911321a72455cacc6929133d0af2cdf6d59a63293ac508786a4850267f90993fff3b6c07bbf3af0e3c08638148101ae1495da3360614866e238c4f60ca00f615877be80cc708da5ea1c30032acffd0e55429ba29dca409349d901a49831db44c1e58b7530b383d3f7e1cac79200cad9bdf87451783f2ffdab09b230aab52b41fa42fdd9f1f05a3dda0fa16b011c51e330d044adf394bbbb7fa25efc860f3082e42824be3b96943afbe641fe6bb|
|24500|Telegram Desktop \>= v2.1.14 (PBKDF2-HMAC-SHA512)|\$telegram\$2\*100000\*77461dcb457ce9539f8e4235d33bd12455b4a38446e63b52ecdf2e7b65af4476\*f705dda3247df6d690dfc7f44d8c666979737cae9505d961130071bcc18eeadaef0320ac6985e4a116834c0761e55314464aae56dadb8f80ab8886c16f72f8b95adca08b56a60c4303d84210f75cfd78a3e1a197c84a747988ce2e1b247397b61041823bdb33932714ba16ca7279e6c36b75d3f994479a469b50a7b2c7299a4d7aadb775fb030d3bb55ca77b7ce8ac2f5cf5eb7bdbcc10821b8953a4734b448060246e5bb93f130d6d3f2e28b9e04f2a064820be562274c040cd849f1473d45141559fc45da4c54abeaf5ca40d2d57f8f8e33bdb232c7279872f758b3fb452713b5d91c855383f7cec8376649a53b83951cf8edd519a99e91b8a6cb90153088e35d9fed332c7253771740f49f9dc40c7da50352656395bbfeae63e10f754d24a|
|24600|SQLCipher|SQLCIPHER\*1\*64000\*25548249195677404156261816261456\*85b5e156e1cf1e0be5e9f4217186817b\*33435c230bbc7989bbd027630e3f47cd|
|24700|Stuffit5|66a75cb059|
|24800|Umbraco HMAC-SHA1|8uigXlGMNI7BzwLCJlDbcKR2FP4=|
|24900|Dahua Authentication MD5|GRuHbyVp|
|25000\*|SNMPv3 HMAC-MD5-96/HMAC-SHA1-96|\$SNMPv3\$0\$45889431\$30818f0201033011020409242fc0020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f4d4435040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411f319300201000201003018301606082b06010201010200060a2b06010401bf0803020a\$80001f88808106d566db57fd6000000000\$1b37c3ea872731f922959e90|
|25100\*|SNMPv3 HMAC-MD5-96|\$SNMPv3\$1\$45889431\$30818f0201033011020409242fc0020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f4d4435040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411f319300201000201003018301606082b06010201010200060a2b06010401bf0803020a\$80001f88808106d566db57fd6000000000\$1b37c3ea872731f922959e90|
|25200\*|SNMPv3 HMAC-SHA1-96|\$SNMPv3\$2\$45889431\$30818f02010330110204371780f3020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f534841040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204073557d50201000201003018301606082b06010201010200060a2b06010401bf0803020a\$80001f88808106d566db57fd6000000000\$81f14f1930589f26f6755f6b|
|25300|MS Office 2016 - SheetProtection|\$office\$2016\$0\$100000\$876MLoKTq42+/DLp415iZQ==\$TNDvpvYyvlSUy97UOLKNhXynhUDDA7H8kLql0ISH5SxcP6hbthdjaTo4Z3/MU0dcR2SAd+AduYb3TB5CLZ8+ow==|
|25400|PDF 1.4 - 1.6 (Acrobat 5 - 8) - edit password|\$pdf\$2\*3\*128\*-3904\*1\*16\*631ed33746e50fba5caf56bcc39e09c6\*32\*5f9d0e4f0b39835dace0d306c40cd6b700000000000000000000000000000000\*32\*842103b0a0dc886db9223b94afe2d7cd63389079b61986a4fcf70095ad630c24|
|25500|Stargazer Stellar Wallet XLM [^22]|\$stellar\$ZCtl/+vWiLL358Jz+xnP5A==\$GgmFU37DSX4evSMU\$CoMGXWHqDmLwxRAgORqjK/MyFEMAkMbqvDEDMjn4veVwpHab9m6Egcwp70qEJsRhjkHjCMWj9zX40tu9UK5QACuB8gD1r9Cu|
|25600|bcrypt(md5(\$pass)) / bcryptmd5|\$2a\$05\$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12yDN7/6I8ZV0q/1lEohLru|
|25700|MurmurHash|b69e7687:05094309|
|25800|bcrypt(sha1(\$pass)) / bcryptsha1|\$2a\$05\$Uo385Fa0g86uUXHwZxB90.qMMdRFExaXePGka4WGFv.86I45AEjmO|
|25900|KNX IP Secure - Device Authentication Code|\$knx-ip-secure-device-authentication-code\$\*3033\*fa7c0d787a9467c209f0a6e7cf16069ed704f3959dce19e45d7935c0a91bce41\*f927640d9bbe9a4b0b74dd3289ad41ec|
|26000|Mozilla key3.db|\$mozilla\$\*3DES\*b735d19e6cadb5136376a98c2369f22819d08c79\*2b36961682200a877f7d5550975b614acc9fefe3\*f03f3575fd5bdbc9e32232316eab7623|
|26100|Mozilla key4.db|\$mozilla\$\*AES\*5add91733b9b13310ea79a4b38de5c3f797c3bf1\*54c17e2a8a066cbdc55f2080c5e9f02ea3954d712cb34b4547f5186548f46512\*10000\*040e4b5a00f993e63f67a34f6cfc5704\*eae9c6c003e6d1b2aa8aa21630838808|
|26200|OpenEdge Progress Encode|lebVZteiEsdpkncc|
|26300|FortiGate256 (FortiOS256)|SH2MCKr6kt9rLQKbn/YTlncOnR6OtcJ1YL/h8hw2wWicjSRf3bbkSrL+q6cDpg=|
|26401|AES-128-ECB NOKDF (PT = \$salt, key = \$pass)|e7a32f3210455cc044f26117c4612aab:86046627772965328523223752173724|
|26402|AES-192-ECB NOKDF (PT = \$salt, key = \$pass)|2995e91b798ef51232a91579edb1d176:49869364034411376791729962721320|
|26403|AES-256-ECB NOKDF (PT = \$salt, key = \$pass)|264a4248c9522cb74d33fe26cb596895:61270210011294880287232432636227|
|26500|iPhone passcode (UID key + System Keybag)|\$uido\$77889b1bca161ce876d976a102c7bf82\$3090545724551425617156367874312887832777\$50000\$2d4c86b71c0c04129a47c6468e2437d1fecd88e232a7b15112d5364682dc391dbbbb921cf6e02664|
|26600|MetaMask Wallet|\$metamask\$AARgM5AgABE2eWgJcWAwQIAFmSYoASZVZBlAR4B0h2M=\$8HrVMqsjfFTusMbegh+KWg==\$7FPq7LjWe3t/TjDBtUwrJBpiG/Rdt+uf71dLCyUZd0pdtymBK6mSMZDyRfp/CzpjEPA1dU1BLDshcwM/1k6KdO//+mPWrgY4j49XTXIMnHNhJPfPv8s9rXiq8jLqetsStqtWmTZaD7fTtbzOYWR4gwQc98MxCnn/IrSnfCHungw1rLV5Xm0/hF7WfzFeEgcHknhJJP1xSeJCL9qI5DJ+lz7ksc0UVvHoiNJx8uvPBNkHpGQRNujwlnk=|
|26700\*|SNMPv3 HMAC-SHA224-128|\$SNMPv3\$3\$45889431\$308197020103301102047aa1a79e020300ffe30401010201030440303e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d3232340410000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204272f76620201000201003018301606082b06010201010200060a2b06010401bf0803020a\$80001f88808106d566db57fd6000000000\$2f7a3891dd2e27d3f567e4d6d0257962|
|26800\*|SNMPv3 HMAC-SHA256-192|\$SNMPv3\$4\$45889431\$30819f020103301102047fc51818020300ffe304010102010304483046041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d32353604180000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a22602040efec2600201000201003018301606082b06010201010200060a2b06010401bf0803020a\$80001f88808106d566db57fd6000000000\$36d655bfeb59e933845db47d719b68ac7bc59ec087eb89a0|
|99999|Plaintext|hashcat|

[^1] Password: “hashcat!”  
[^2] rounds=[\# of iterations] is **optional** e.g. $5$rounds=5000  
[^3] Same format as in 2: but the number of rounds **must** be specified  
[^4] The hash used here is **not** the one sent via e.g. the web interface to LastPass servers (pbkdf2\_sha256\_hex (pbkdf2\_sha256 (\$pass, \$email, \$iterations), \$pass, 1) but instead the one stored (by e.g. your browser or the pocket version) to disk. For instance, Opera and Chrome store the hash in local SQLite databases; Firefox uses files ending with “lpall.slps” - for Linux: 2nd line is interesting / base64 decode it; for Windows, see [here](https://hashcat.net/forum/thread-2701-post-16111.html#pid16111 "https://hashcat.net/forum/thread-2701-post-16111.html#pid16111") - and\_key.itr  
[^5] You can consider the second part as a “salt”. If it is equal to 00000000, the CRC32 code will be considered as “not salted”  
[^6] The raw sha256 output is used for base64() encoding (not the hexadecimal output)  
[^7] The format is hash:salt:id  
[^8] Password: “hashcat1”  
[^9] Password: “hashcat1hashcat1hashcat1”  
[^10] This file actually contains several examples of the different hash+cipher combinations. The password is stored in the pw file.  
[^11] You can use [itunes\_backup2hashcat](https://github.com/philsmd/itunes_backup2hashcat/ "https://github.com/philsmd/itunes_backup2hashcat/") to extract the hashes from the Manifest.plist file  
[^12] Password: “hashcat!!!”. Min/max password length is exactly 10 characters/bytes.
[^13] You can use [AxSuite by Fist0urs](https://github.com/Fist0urs/AxSuite "https://github.com/Fist0urs/AxSuite") to retrieve the hashes.  
[^14] Password: a288fcf0caaacda9a9f58633ff35e8992a01d9c10ba5e02efdf8cb5d730ce7bc  
[^15] Password: 5b13d4babb3714ccc62c9f71864bc984efd6a55f237c7a87fc2151e1ca658a9d  
[^16] PIM: 500  
[^17] full password in output is hashcat, but input provided must be without the first 6 bytes (therefore just: t)  
[^18] 88f43854ae7b1624fc2ab7724859e795130f4843c7535729e819cf92f39535dc  
[^19] use this SQL query to extract the hashes:

``` {.code}
SELECT user, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
```

[^20] Password: “hashcat\_hashcat\_hashcat\_hashcat\_”  
[^21] you can extract the hashes with [https://github.com/0x6470/bitwarden2hashcat](https://github.com/0x6470/bitwarden2hashcat "https://github.com/0x6470/bitwarden2hashcat")  
[^22] Password: lacoin  

# Specific Hash Types

|Hash-Mode|Hash-Name|Example|
|:--------|:--------|:------|
|11|Joomla \< 2.5.18|19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777|
|12|PostgreSQL|a6343a68d964ca596d9752250d54bb8a:postgres|
|21|osCommerce, xt:Commerce|374996a5e8a5e57fd97d893f7df79824:36|
|22|Juniper NetScreen/SSG (ScreenOS)|nNxKL2rOEkbBc9BFLsVGG6OtOUO/8n:user|
|23|Skype|3af0389f093b181ae26452015f4ae728:user|
|24|SolarWinds Serv-U|e983672a03adcc9767b24584338eb378|
|101|nsldap, SHA-1(Base64), Netscape LDAP SHA|{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=|
|111|nsldaps, SSHA-1(Base64), Netscape LDAP SSHA|{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==|
|112|Oracle S: Type (Oracle 11+)|ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130|
|121|SMF (Simple Machines Forum) \> v1.1|ecf076ce9d6ed3624a9332112b1cd67b236fdd11:17782686|
|122|macOS v10.4, macOS v10.5, macOS v10.6|1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683|
|124|Django (SHA-1)|sha1\$fe76b\$02d5916550edf7fc8c886f044887f4b1abf9b013|
|125|ArubaOS|5387280701327dc2162bdeb451d5a465af6d13eff9276efeba|
|131|MSSQL (2000)|0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578|
|132|MSSQL (2005)|0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe|
|133|PeopleSoft|uXmFVrdBvv293L9kDR3VnRmx4ZM=|
|141|Episerver 6.x \< .NET 4|\$episerver\$\*0\*bEtiVGhPNlZpcUN4a3ExTg==\*utkfN0EOgljbv5FoZ6+AcZD5iLk|
|1411|SSHA-256(Base64), LDAP {SSHA256}|{SSHA256}OZiz0cnQ5hgyel3Emh7NCbhBRCQ+HVBwYplQunHYnER7TLuV|
|1421|hMailServer|8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3|
|1441|Episerver 6.x \>= .NET 4|\$episerver\$\*1\*MDEyMzQ1Njc4OWFiY2RlZg==\*lRjiU46qHA7S6ZE7RfKUcYhB85ofArj1j7TrCtu3u6Y|
|1711|SSHA-512(Base64), LDAP {SSHA512}|{SSHA512}ALtwKGBdRgD+U0fPAy31C28RyKYx7+a8kmfksccsOeLknLHv2DBXYI7TDnTolQMBuPkWDISgZr2cHfnNPFjGZTEyNDU4OTkw|
|1722|macOS v10.7|648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d|
|1731|MSSQL (2012, 2014)|0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375|
|2611|vBulletin \< v3.8.5|16780ba78d2d5f02f3202901c1b6d975:568|
|2612|PHPS|\$PHPS\$34323438373734\$5b07e065b9d78d69603e71201c6cf29f|
|2711|vBulletin \>= v3.8.5|bf366348c53ddcfbd16e63edfdd1eee6:181264250056774603641874043270|
|2811|MyBB 1.2+, IPB2+ (Invision Power Board)|8d2129083ef35f4b365d5d87487e1207:47204|
|3711|MediaWiki B type|\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898|
|4521|Redmine|1fb46a8f81d8838f46879aaa29168d08aa6bf22d:3290afd193d90e900e8021f81409d7a9|
|4522|PunBB|4a2b722cc65ecf0f7797cdaea4bce81f66716eef:653074362104|
|4711|Huawei sha1(md5(\$pass).\$salt)|53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1|
|7100|macOS v10.8+ (PBKDF2-SHA512)|\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222|
|7401|MySQL \$A\$ (sha256crypt) [^19]|\$mysql\$A\$005\*F9CC98CE08892924F50A213B6BC571A2C11778C5\*625479393559393965414D45316477456B484F41316E64484742577A2E3162785353526B7554584647562F|
|12001|Atlassian (PBKDF2-HMAC-SHA1)|{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa|
|20711|AuthMe sha256|\$SHA\$7218532375810603\$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824|
|22301|Telegram Mobile App Passcode (SHA256)|\$telegram\$0\*518c001aeb3b4ae96c6173be4cebe60a85f67b1e087b045935849e2f815b5e41\*25184098058621950709328221838128|

# Legacy hash types

These hash types are only supported in [hashcat-legacy](/wiki/doku.php?id=hashcat-legacy "hashcat-legacy") or [oclHashcat](/wiki/doku.php?id=oclhashcat "oclhashcat").

|Hash-Mode|Hash-Name|Example|
|:--------|:--------|:------|
|123|EPi|0x326C6D7B4E4F794B79474E36704F35723958397163735263516265456E31 0xAFC55E260B8F45C0C6512BCE776C1AD8312B56E6|
|190|sha1(LinkedIn) [^24]|b89eaac7e61417341b710b727768294d0e6a277b|
|1431|base64(sha256(unicode(\$pass))) [^23]|npKD5jP0p6QtOryTcBFVvor+VmDaJMh1jn01M+Ly3II=|
|3300|MD5(Sun) [^23]|\$md5\$rounds=904\$iPPKEBnEkp3JV8uX\$0L6m7rOFTVFn.SGqo2M9W1|
|3610|md5(md5(\$salt).\$pass )[^23]|7b57255a15958ef898543ea6cc3313bc:1234|
|3720|md5(\$pass.md5(\$salt)) [^23]|10ce488714fdbde9453670e0e4cbe99c:1234|
|3721|WebEdition CMS [^23]|fa01af9f0de5f377ae8befb03865178e:​5678|
|4210|md5(\$username.0.\$pass) [^23]|09ea048c345ad336ebe38ae5b6c4de24:1234|
|4600|sha1(sha1(sha1(\$pass))) [^23]|dc57f246485e62d99a5110afc9264b4ccbfcf3cc|

[^23] Supported in [hashcat-legacy](/wiki/doku.php?id=hashcat-legacy "hashcat-legacy")  
[^24] Supported in [oclHashcat](/wiki/doku.php?id=oclhashcat "oclhashcat")  




Example hashes

If you get a “line length exception” error in hashcat, it is often because the hash mode that you have requested does not match the hash. To verify, you can test your commands against example hashes.

Unless otherwise noted, the password for all example hashes is hashcat.
Generic hash types
Hash-Mode 	Hash-Name 	Example
0 	MD5 	8743b52063cd84097a65d1633f5c74f5
10 	md5($pass.$salt) 	01dfae6e5d4d90d9892622325959afbe:7050461
20 	md5($salt.$pass) 	f0fda58630310a6dd91a7d8f0a4ceda2:4225637426
30 	md5(utf16le($pass).$salt) 	b31d032cfdcf47a399990a71e43c5d2a:144816
40 	md5($salt.utf16le($pass)) 	d63d0e21fdc05f618d55ef306c54af82:13288442151473
50 	HMAC-MD5 (key = $pass) 	fc741db0a2968c39d9c2a5cc75b05370:1234
60 	HMAC-MD5 (key = $salt) 	bfd280436f45fa38eaacac3b00518f29:1234
100 	SHA1 	b89eaac7e61417341b710b727768294d0e6a277b
110 	sha1($pass.$salt) 	2fc5a684737ce1bf7b3b239df432416e0dd07357:2014
120 	sha1($salt.$pass) 	cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024
130 	sha1(utf16le($pass).$salt) 	c57f6ac1b71f45a07dbd91a59fa47c23abcd87c2:631225
140 	sha1($salt.utf16le($pass)) 	5db61e4cd8776c7969cfd62456da639a4c87683a:8763434884872
150 	HMAC-SHA1 (key = $pass) 	c898896f3f70f61bc3fb19bef222aa860e5ea717:1234
160 	HMAC-SHA1 (key = $salt) 	d89c92b4400b15c39e462a8caa939ab40c3aeeea:1234
200 	MySQL323 	7196759210defdc0
300 	MySQL4.1/MySQL5 	fcf7c1b8749cf99d88e5f34271d636178fb5d130
400 	phpass, WordPress (MD5),
Joomla (MD5) 	$P$984478476IagS59wHZvyQMArzfx58u.
400 	phpass, phpBB3 (MD5) 	$H$984478476IagS59wHZvyQMArzfx58u.
500 	md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) 2 	$1$28772684$iEwNOgGugqO9.bIz5sk8k/
501 	Juniper IVE 	3u+UR6n8AgABAAAAHxxdXKmiOmUoqKnZlf8lTOhlPYy93EAkbPfs5+49YLFd/B1+omSKbW7DoqNM40/EeVnwJ8kYoXv9zy9D5C5m5A==
600 	BLAKE2b-512 	$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e
900 	MD4 	afe04867ec7a3845145579a95f72eca7
1000 	NTLM 	b4b9b02e6f09a9bd760f388b67351e2b
1100 	Domain Cached Credentials (DCC), MS Cache 	4dd8965d1d476fa0d026722989a6b772:3060147285011
1300 	SHA-224 	e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198
1400 	SHA-256 	127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
1410 	sha256($pass.$salt) 	c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528
1420 	sha256($salt.$pass) 	eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617
1430 	sha256(utf16le($pass).$salt) 	4cc8eb60476c33edac52b5a7548c2c50ef0f9e31ce656c6f4b213f901bc87421:890128
1440 	sha256($salt.utf16le($pass)) 	a4bd99e1e0aba51814e81388badb23ecc560312c4324b2018ea76393ea1caca9:12345678
1450 	HMAC-SHA256 (key = $pass) 	abaf88d66bf2334a4a8b207cc61a96fb46c3e38e882e6f6f886742f688b8588c:1234
1460 	HMAC-SHA256 (key = $salt) 	8efbef4cec28f228fa948daaf4893ac3638fbae81358ff9020be1d7a9a509fc6:1234
1500 	descrypt, DES (Unix), Traditional DES 	48c/R8JAv757A
1600 	Apache $apr1$ MD5, md5apr1, MD5 (APR) 2 	$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.
1700 	SHA-512 	82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f
1710 	sha512($pass.$salt) 	e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260
1720 	sha512($salt.$pass) 	976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127
1730 	sha512(utf16le($pass).$salt) 	13070359002b6fbb3d28e50fba55efcf3d7cc115fe6e3f6c98bf0e3210f1c6923427a1e1a3b214c1de92c467683f6466727ba3a51684022be5cc2ffcb78457d2:341351589
1740 	sha512($salt.utf16le($pass)) 	bae3a3358b3459c761a3ed40d34022f0609a02d90a0d7274610b16147e58ece00cd849a0bd5cf6a92ee5eb5687075b4e754324dfa70deca6993a85b2ca865bc8:1237015423
1750 	HMAC-SHA512 (key = $pass) 	94cb9e31137913665dbea7b058e10be5f050cc356062a2c9679ed0ad6119648e7be620e9d4e1199220cd02b9efb2b1c78234fa1000c728f82bf9f14ed82c1976:1234
1760 	HMAC-SHA512 (key = $salt) 	7cce966f5503e292a51381f238d071971ad5442488f340f98e379b3aeae2f33778e3e732fcc2f7bdc04f3d460eebf6f8cb77da32df25500c09160dd3bf7d2a6b:1234
1800 	sha512crypt $6$, SHA512 (Unix) 2 	$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/
2100 	Domain Cached Credentials 2 (DCC2), MS Cache 2 	$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f
2400 	Cisco-PIX MD5 	dRRVnUmUHXOTt9nk
2410 	Cisco-ASA MD5 	02dMBMYkTdC5Ziyp:36
2500 	WPA/WPA2 1 	https://hashcat.net/misc/example_hashes/hashcat.hccapx
2501* 	WPA/WPA2 PMK 	https://hashcat.net/misc/example_hashes/hashcat-pmk.hccapx
2600 	md5(md5($pass)) 	a936af92b0ae20b1ff6c3347a72e5fbe
3000 	LM 	299bd128c1101fd6
3100 	Oracle H: Type (Oracle 7+), DES(Oracle) 	7A963A529D2E3229:3682427524
3200 	bcrypt $2*$, Blowfish (Unix) 	$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6
3710 	md5($salt.md5($pass)) 	95248989ec91f6d0439dbde2bd0140be:1234
3800 	md5($salt.$pass.$salt) 	2e45c4b99396c6cb2db8bda0d3df669f:1234
3910 	md5(md5($pass).md5($salt)) 	250920b3a5e31318806a032a4674df7e:1234
4010 	md5($salt.md5($salt.$pass)) 	30d0cf4a5d7ed831084c5b8b0ba75b46:1234
4110 	md5($salt.md5($pass.$salt)) 	b4cb5c551a30f6c25d648560408df68a:1234
4300 	md5(strtoupper(md5($pass))) 	b8c385461bb9f9d733d3af832cf60b27
4400 	md5(sha1($pass)) 	288496df99b33f8f75a7ce4837d1b480
4500 	sha1(sha1($pass)) 	3db9184f5da4e463832b086211af8d2314919951
4520 	sha1($salt.sha1($pass)) 	a0f835fdf57d36ebd8d0399cc44e6c2b86a1072b:511358214352751667201107073531735211566650747315
4700 	sha1(md5($pass)) 	92d85978d884eb1d99a51652b1139c8279fa8663
4800 	iSCSI CHAP authentication, MD5(CHAP) 7 	afd09efdd6f8ca9f18ec77c5869788c3:01020304050607080910111213141516:01
4900 	sha1($salt.$pass.$salt) 	85087a691a55cbb41ae335d459a9121d54080b80:488387841
5000 	SHA-3 (Keccak) 	203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6
5100 	Half MD5 	8743b52063cd8409
5200 	Password Safe v3 	https://hashcat.net/misc/example_hashes/hashcat.psafe3
5300 	IKE-PSK MD5 	https://hashcat.net/misc/example_hashes/hashcat.ikemd5
5400 	IKE-PSK SHA1 	https://hashcat.net/misc/example_hashes/hashcat.ikesha1
5500 	NetNTLMv1 / NetNTLMv1+ESS 	u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
5600 	NetNTLMv2 	admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
5700 	Cisco-IOS type 4 (SHA256) 	2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI
5800 	Samsung Android Password/PIN 	0223b799d526b596fe4ba5628b9e65068227e68e:f6d45822728ddb2c
6000 	RIPEMD-160 	012cb9b334ec1aeb71a9c8ce85586082467f7eb6
6100 	Whirlpool 	7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258
6211 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes.tc
6211 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent.tc
6211 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish.tc
6212 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish.tc
6213 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish-Serpent 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish-serpent.tc
6212 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-AES 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-aes.tc
6213 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-Twofish-AES 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-twofish-aes.tc
6212 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish-Serpent 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish-serpent.tc
6221 	TrueCrypt 5.0+ SHA512 + AES 	https://hashcat.net/misc/example_hashes/hashcat_sha512_aes.tc
6221 	TrueCrypt 5.0+ SHA512 + Serpent 	https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent.tc
6221 	TrueCrypt 5.0+ SHA512 + Twofish 	https://hashcat.net/misc/example_hashes/hashcat_sha512_twofish.tc
6222 	TrueCrypt 5.0+ SHA512 + AES-Twofish 	https://hashcat.net/misc/example_hashes/hashcat_sha512_aes-twofish.tc
6223 	TrueCrypt 5.0+ SHA512 + AES-Twofish-Serpent 	https://hashcat.net/misc/example_hashes/hashcat_sha512_aes-twofish-serpent.tc
6222 	TrueCrypt 5.0+ SHA512 + Serpent-AES 	https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent-aes.tc
6223 	TrueCrypt 5.0+ SHA512 + Serpent-Twofish-AES 	https://hashcat.net/misc/example_hashes/hashcat_sha512_serpent-twofish-aes.tc
6222 	TrueCrypt 5.0+ SHA512 + Twofish-Serpent 	https://hashcat.net/misc/example_hashes/hashcat_sha512_twofish-serpent.tc
6231 	TrueCrypt 5.0+ Whirlpool + AES 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes.tc
6231 	TrueCrypt 5.0+ Whirlpool + Serpent 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent.tc
6231 	TrueCrypt 5.0+ Whirlpool + Twofish 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_twofish.tc
6232 	TrueCrypt 5.0+ Whirlpool + AES-Twofish 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes-twofish.tc
6233 	TrueCrypt 5.0+ Whirlpool + AES-Twofish-Serpent 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_aes-twofish-serpent.tc
6232 	TrueCrypt 5.0+ Whirlpool + Serpent-AES 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent-aes.tc
6233 	TrueCrypt 5.0+ Whirlpool + Serpent-Twofish-AES 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_serpent-twofish-aes.tc
6232 	TrueCrypt 5.0+ Whirlpool + Twofish-Serpent 	https://hashcat.net/misc/example_hashes/hashcat_whirlpool_twofish-serpent.tc
6241 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes_boot.tc
6241 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent_boot.tc
6241 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish_boot.tc
6242 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish_boot.tc
6243 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + AES-Twofish-Serpent + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_aes-twofish-serpent_boot.tc
6242 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-AES + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-aes_boot.tc
6243 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Serpent-Twofish-AES + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_serpent-twofish-aes_boot.tc
6242 	TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + Twofish-Serpent + boot 	https://hashcat.net/misc/example_hashes/hashcat_ripemd160_twofish-serpent_boot.tc
6300 	AIX {smd5} 	{smd5}a5/yTL/u$VfvgyHx1xUlXZYBocQpQY0
6400 	AIX {ssha256} 	{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2
6500 	AIX {ssha512} 	{ssha512}06$bJbkFGJAB30L2e23$bXiXjyH5YGIyoWWmEVwq67nCU5t7GLy9HkCzrodRCQCx3r9VvG98o7O3V0r9cVrX3LPPGuHqT5LLn0oGCuI1..
6600 	1Password, agilekeychain 	https://hashcat.net/misc/example_hashes/hashcat.agilekeychain
6700 	AIX {ssha1} 	{ssha1}06$bJbkFGJAB30L2e23$dCESGOsP7jaIIAJ1QAcmaGeG.kr
6800 	LastPass + LastPass sniffed4 	a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com
6900 	GOST R 34.11-94 	df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9
7000 	FortiGate (FortiOS) 	AK1AAECAwQFBgcICRARNGqgeC3is8gv2xWWRony9NJnDgE=
7100 	OSX v10.8+ (PBKDF2-SHA512) 	$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222
7200 	GRUB 2 	grub.pbkdf2.sha512.10000.7d391ef48645f626b427b1fae06a7219b5b54f4f02b2621f86b5e36e83ae492bd1db60871e45bc07925cecb46ff8ba3db31c723c0c6acbd4f06f60c5b246ecbf.26d59c52b50df90d043f070bd9cbcd92a74424da42b3666fdeb08f1a54b8f1d2f4f56cf436f9382419c26798dc2c209a86003982b1e5a9fcef905f4dfaa4c524
7300 	IPMI2 RAKP HMAC-SHA1 	b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef
7400 	sha256crypt $5$, SHA256 (Unix) 2 	$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD
7500 	Kerberos 5 AS-REQ Pre-Auth etype 23 	$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835
7700 	SAP CODVN B (BCODE) 	USER$C8B48F26B87B7EA7
7800 	SAP CODVN F/G (PASSCODE) 	USER$ABCAD719B17E7F794DF7E686E563E9E2D24DE1D0
7900 	Drupal7 	$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf
8000 	Sybase ASE 	0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2
8100 	Citrix NetScaler 	1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea
8200 	1Password, cloudkeychain 	https://hashcat.net/misc/example_hashes/hashcat.cloudkeychain
8300 	DNSSEC (NSEC3) 	7b5n74kq8r441blc2c5qbbat19baj79r:.lvdsiqfj.net:33164473:1
8400 	WBB3 (Woltlab Burning Board) 	8084df19a6dc81e2597d051c3d8b400787e2d5a9:6755045315424852185115352765375338838643
8500 	RACF 	$racf$*USER*FC2577C6EBE6265B
8600 	Lotus Notes/Domino 5 	3dd2e1e5ac03e230243d58b8c5ada076
8700 	Lotus Notes/Domino 6 	(GDpOtD35gGlyDksQRxEU)
8800 	Android FDE <= 4.3 	https://hashcat.net/misc/example_hashes/hashcat.android43fde
8900 	scrypt 	SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=
9000 	Password Safe v2 	https://hashcat.net/misc/example_hashes/hashcat.psafe2.dat
9100 	Lotus Notes/Domino 8 	(HsjFebq0Kh9kH7aAZYc7kY30mC30mC3KmC30mCluagXrvWKj1)
9200 	Cisco-IOS $8$ (PBKDF2-SHA256) 	$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk
9300 	Cisco-IOS $9$ (scrypt) 	$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6
9400 	MS Office 2007 	$office$*2007*20*128*16*411a51284e0d0200b131a8949aaaa5cc*117d532441c63968bee7647d9b7df7d6*df1d601ccf905b375575108f42ef838fb88e1cde
9500 	MS Office 2010 	$office$*2010*100000*128*16*77233201017277788267221014757262*b2d0ca4854ba19cf95a2647d5eee906c*e30cbbb189575cafb6f142a90c2622fa9e78d293c5b0c001517b3f5b82993557
9600 	MS Office 2013 	$office$*2013*100000*256*16*7dd611d7eb4c899f74816d1dec817b3b*948dc0b2c2c6c32f14b5995a543ad037*0b7ee0e48e935f937192a59de48a7d561ef2691d5c8a3ba87ec2d04402a94895
9700 	MS Office ⇐ 2003 MD5 + RC4, oldoffice$0, oldoffice$1 	$oldoffice$1*04477077758555626246182730342136*b1b72ff351e41a7c68f6b45c4e938bd6*0d95331895e99f73ef8b6fbc4a78ac1a
9800 	MS Office ⇐ 2003 SHA1 + RC4, oldoffice$3, oldoffice$4 	$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd
9900 	Radmin2 	22527bee5c29ce95373c4e0f359f079b
10000 	Django (PBKDF2-SHA256) 	pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=
10100 	SipHash 	ad61d78c06037cd9:2:4:81533218127174468417660201434054
10200 	CRAM-MD5 	$cram_md5$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==
10300 	SAP CODVN H (PWDSALTEDHASH) iSSHA-1 	{x-issha, 1024}C0624EvGSdAMCtuWnBBYBGA0chvqAflKY74oEpw/rpY=
10400 	PDF 1.1 - 1.3 (Acrobat 2 - 4) 	$pdf$1*2*40*-1*0*16*51726437280452826511473255744374*32*9b09be05c226214fa1178342673d86f273602b95104f2384b6c9b709b2cbc058*32*0000000000000000000000000000000000000000000000000000000000000000
10500 	PDF 1.4 - 1.6 (Acrobat 5 - 8) 	$pdf$2*3*128*-1028*1*16*da42ee15d4b3e08fe5b9ecea0e02ad0f*32*c9b59d72c7c670c42eeb4fca1d2ca15000000000000000000000000000000000*32*c4ff3e868dc87604626c2b8c259297a14d58c6309c70b00afdfb1fbba10ee571
10600 	PDF 1.7 Level 3 (Acrobat 9) 	$pdf$5*5*256*-1028*1*16*20583814402184226866485332754315*127*f95d927a94829db8e2fbfbc9726ebe0a391b22a084ccc2882eb107a74f7884812058381440218422686648533275431500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000
10700 	PDF 1.7 Level 8 (Acrobat 10 - 11) 	$pdf$5*6*256*-4*1*16*381692e488413f5502fa7314a78c25db*48*e5bf81a2a23c88f3dccb44bc7da68bb5606b653b733bcf9adaa5eb2c8ccf53abba66539044eb1957eda68469b1d0b9b5*48*b222df06deb308bf919d13447e688775fdcab972faed2c866dc023a126cb4cd4bbffab3683ecde243cf8d88967184680
10800 	SHA-384 	07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42
10900 	PBKDF2-HMAC-SHA256 	sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt
11000 	PrestaShop 	810e3d12f0f10777a679d9ca1ad7a8d9:M2uZ122bSHJ4Mi54tXGY0lqcv1r28mUluSkyw37ou5oia4i239ujqw0l
11100 	PostgreSQL CRAM (MD5) 	$postgres$postgres*f0784ea5*2091bb7d4725d1ca85e8de6ec349baf6
11200 	MySQL CRAM (SHA1) 	$mysqlna$1c24ab8d0ee94d70ab1f2e814d8f0948a14d10b9*437e93572f18ae44d9e779160c2505271f85821d
11300 	Bitcoin/Litecoin wallet.dat 	$bitcoin$96$d011a1b6a8d675b7a36d0cd2efaca32a9f8dc1d57d6d01a58399ea04e703e8bbb44899039326f7a00f171a7bbc854a54$16$1563277210780230$158555$96$628835426818227243334570448571536352510740823233055715845322741625407685873076027233865346542174$66$625882875480513751851333441623702852811440775888122046360561760525
11400 	SIP digest authentication (MD5) 	$sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*192.168.100.121**2b01df0b****MD5*ad0520061ca07c120d7e8ce696a6df2d
11500 	CRC32 5 	c762de4a:00000000
11600 	7-Zip 	$7z$0$19$0$salt$8$f6196259a7326e3f0000000000000000$185065650$112$98$f3bc2a88062c419a25acd40c0c2d75421cf23263f69c51b13f9b1aada41a8a09f9adeae45d67c60b56aad338f20c0dcc5eb811c7a61128ee0746f922cdb9c59096869f341c7a9cb1ac7bb7d771f546b82cf4e6f11a5ecd4b61751e4d8de66dd6e2dfb5b7d1022d2211e2d66ea1703f96
11700 	GOST R 34.11-2012 (Streebog) 256-bit 	57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36
11800 	GOST R 34.11-2012 (Streebog) 512-bit 	5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3
11900 	PBKDF2-HMAC-MD5 	md5:1000:MTg1MzA=:Lz84VOcrXd699Edsj34PP98+f4f3S0rTZ4kHAIHoAjs=
12000 	PBKDF2-HMAC-SHA1 	sha1:1000:MzU4NTA4MzIzNzA1MDQ=:19ofiY+ahBXhvkDsp0j2ww==
12100 	PBKDF2-HMAC-SHA512 	sha512:1000:ODQyMDEwNjQyODY=:MKaHNWXUsuJB3IEwBHbm3w==
12200 	eCryptfs 	$ecryptfs$0$1$7c95c46e82f364b3$60bba503f0a42d0c
12300 	Oracle T: Type (Oracle 12+) 	78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225
12400 	BSDiCrypt, Extended DES 	_9G..8147mpcfKT8g0U.
12500 	RAR3-hp 	$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317
12600 	ColdFusion 10+ 	aee9edab5653f509c4c63e559a5e967b4c112273bc6bd84525e630a3f9028dcb:5136256866783777334574783782810410706883233321141647265340462733
12700 	Blockchain, My Wallet 	$blockchain$288$5420055827231730710301348670802335e45a6f5f631113cb1148a6e96ce645ac69881625a115fd35256636d0908217182f89bdd53256a764e3552d3bfe68624f4f89bb6de60687ff1ebb3cbf4e253ee3bea0fe9d12d6e8325ddc48cc924666dc017024101b7dfb96f1f45cfcf642c45c83228fe656b2f88897ced2984860bf322c6a89616f6ea5800aadc4b293ddd46940b3171a40e0cca86f66f0d4a487aa3a1beb82569740d3bc90bc1cb6b4a11bc6f0e058432cc193cb6f41e60959d03a84e90f38e54ba106fb7e2bfe58ce39e0397231f7c53a4ed4fd8d2e886de75d2475cc8fdc30bf07843ed6e3513e218e0bb75c04649f053a115267098251fd0079272ec023162505725cc681d8be12507c2d3e1c9520674c68428df1739944b8ac
12800 	MS-AzureSync PBKDF2-HMAC-SHA256 	v1;PPH1_MD4,84840328224366186645,100,005a491d8bf3715085d69f934eef7fb19a15ffc233b5382d9827910bc32f3506
12900 	Android FDE (Samsung DEK) 	38421854118412625768408160477112384218541184126257684081604771129b6258eb22fc8b9d08e04e6450f72b98725d7d4fcad6fb6aec4ac2a79d0c6ff738421854118412625768408160477112
13000 	RAR5 	$rar5$16$74575567518807622265582327032280$15$f8b4064de34ac02ecabfe9abdf93ed6a$8$9843834ed0f7c754
13100 	Kerberos 5 TGS-REP etype 23 	$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$891ad31d09ab89c6b3b8c5e5de6c06a7f49fd559d7a9a3c32576c8fedf705376cea582ab5938f7fc8bc741acf05c5990741b36ef4311fe3562a41b70a4ec6ecba849905f2385bb3799d92499909658c7287c49160276bca0006c350b0db4fd387adc27c01e9e9ad0c20ed53a7e6356dee2452e35eca2a6a1d1432796fc5c19d068978df74d3d0baf35c77de12456bf1144b6a750d11f55805f5a16ece2975246e2d026dce997fba34ac8757312e9e4e6272de35e20d52fb668c5ed
13200 	AxCrypt 	$axcrypt$*1*10000*aaf4a5b4a7185551fea2585ed69fe246*45c616e901e48c6cac7ff14e8cd99113393be259c595325e
13300 	AxCrypt in-memory SHA1 13 	$axcrypt_sha1$b89eaac7e61417341b710b727768294d0e6a277b
13400 	KeePass 1 AES / without keyfile 	$keepass$*1*50000*0*375756b9e6c72891a8e5645a3338b8c8*82afc053e8e1a6cfa39adae4f5fe5e59f545a54d6956593d1709b39cacd7f796*c698fbfc7d1b71431d10611e2216ab21*24a63140f4eb3bfd7d59b7694eea38d1d93a43bc3af989755d2b326286c4d510*1*192*1a65072f436e9da0c9e832eca225a04ab78821b55d9f550860ade2ef8126a2c4050cf4d033374abd3dac6d0c5907c6cbb033643b203825c12e6c9853b5ac17a4809559fe723e01b4a2ab87cc83c8ba7ee4a757b8a0cf1674106f21f6675cba12064443d65436650df10ea0923c4cadfd4bfe341a6f4fa23a1a67f7d12a489fc5410ef6db9f6607905de491d3b3b915852a1b6c231c96366cbdee5ea9bd7f73ffd2f7a579215528ae1bf0ea540947ebfe39ca84bc6cbeded4f8e8fb6ed8f32dd5
13400 	KeePass 2 AES / without keyfile 	$keepass$*2*6000*222*a279e37c38b0124559a83fa452a0269d56dc4119a5866d18e76f1f3fd536d64d*7ec7a06bc975ea2ae7c8dcb99e826a308564849b6b25d858cbbc78475af3733f*d477c849bf2278b7a1f626c81e343553*38c8ec186141c2705f2bcb334a730933ed3b0ee11391e1100fbaf429f6c99078*1ada85fe78cf36ab0537562a787dd83e446f13cd3d9a60fd495003de3537b702
13400 	KeePass 1 Twofish / with keyfile 	$keepass$*1*6000*1*31c087828b0bb76362c10cae773aacdf*6d6c78b4f82ecbcd3b96670cf490914c25ea8c31bc3aeb3fc56e65fac16d721f*a735ec88c01816bc66200c8e17ee9110*08334be8523f4b69bd4e2328db854329bfc81e2ea5a46d8ccf3bccf7c03d879d*1*1360*f1e2c6c47f88c2abf4e79dbe73339b77778233a6c7d7f49f6b7d5db6a4885ff33585e221f5e94e8f7cc84ddcbe9c61a3d40c4f503a4ec7e91edca5745454588eebb4f0dc4d251c0d88eb5fae5d5b651d16e56ef830f412cb7fccf643de4963b66852d3a775489b5abb394b6fa325c3dbb4a55dd06d44c5fc911f1305e55accf0dc0eb172788f5400aab3c867cc6c5ddb7cd3e57bb78a739416985a276825171f5a19750dede055aa3e5fca9b11e3606beae97d68e593631a2efd88cdeb9f43b5ac1d1d9f0164f0fb022ea44a4a48061629c83d8f5bc594e3655ee684102fe706d1e96178bb805105fe1c5326c951401a6e7c9a0b8b572e7b74c3fb25e8700a2e0e70b4621ae3878805397ea1b873ea5218fdaa4fc5d11cdf7ea3579601eca3750fa347edc08569b1f51606d35920253f85f33e6a757a585adf079173161af919f7ea0d78ca6ca1513d01855057373c4f9fe22aba1fc4b18708d329500c127b865a528435e9e00d0a80554ae6eaf4d58bf85a959f37d0854b36c782991c36120b41ee2d9905b18d525b6bffef310e90dbfbe9be853614e6559737f1141f725902f59ee02789c6490c16adf0957e36dc4101c57ba35acb4ca9ec60f5585b60e74342921bbc7e56df5ad942b6deb7936532439b1dae39b9709cf282239c57b434d6f65ba277012ccddce32a217964f974c16f96d8b078ceaad43de9f3d5309279843f2f347ad8ae6eab3a998bb99a421b22b806e2f2302f9dcf3ba54e3d3f1ee64ef3b202194912eec202c2f44847ad5293b03b6b22df35f505670a79219efc399c6a4fa3fd4be7953e5df9baf94101c0a7036b82b6950ab2b722e38aec47bf1c7ffb4e82f43b9ca18d2a8b0b2a7b92015b01d07a429d2660902185cf143f871ff49dde73acf7c3bfd9c124733bd90ffe0fd1cc9090d56dd70bd62f9df1bfa4748ea3438f669d5691c61ec7fbc9d53ab4d8c2dda2cf203f7a5a7fac72eb2efe1d9a27b8c5b14e07a55c530dfd7b7c69dcf478590b7b364f5379f92a0762be0005c4cbc5285d7828248159286fe6d29c02c7de04e96e737a2d30ce75ff774982433f75ca16f09ad668e5b13f0a2e84886773d8fff67f71c1a9dab13f78e5b2da9b1eed9ab2208934a6da7eab32b3e8da1599d6cfa7e9c19ad8efc85dd9a2a4b95832c435381c2fe7e44c58045ce91e40d58c36924b38b19cbafd696bac8761229de9099ce31ee1c93a98aa0cb2a7c60b71b7f1998690e5eae623827727cfe7e8eed94ffc927a1e15aac32292daccda4f0d35383ce87f7e872fc3fe8f01f4a44de4f7b76257abc9c056ab8ae0d96d2dc3a154408c28a2e7befbd515cb5013cbfed31af456ac2b596b5d8095420c411b981d48741dc7ed1e8de4e428bd5e5a553348e2890b1ed12b7dc88261ab921a12da43e6344bbb4a0e0ce2b84c2d1d6c1f51b88202743433ac24340ae00cf27d43346240f4dc5e35ec29fcf1bf6de3bcc09ee8db3f49c3b6615bd8796bbe2cf4b914766779408e772123d9e51cc92ed5dedafa427fd767198cb97674eded4e4df84716aec75cbe7a54620c283fa60780be3cd66ea4167f46cdea1506be92a5102317c8ab8be097c993d82bd831818fe7cb1fbfecc3432d93e0f6d36da8a65ed15c78e623d59980be7ff54bdb1786de2ca9e7a11f0fe067db9ec42ade3bbaad10adae5ea77ba76fa2d0723a35891bde91da540a58e343c23afa9e22b38a66171eb9dbbd55f9e0f014e9de3943388fe0990cc801bbb978c02bf680b3c63a747e22a6317440c40e6844987e936c88c25f49e601ec3486ab080165b5e01dbee47a0a385dfba22ec5ed075f94052bdddabde761bbcc79852402c5b22ded89af4c602922099e37d71b7f87f4ffa614b4ca106fca6b062cba350be1fd12c6812db82f3e02a81e42*1*64*bbc3babf62557aa4dfba705e24274e1aebf43907fe12f52eaf5395066f7cbdba
13400 	Keepass 2 AES / with keyfile 	$keepass$*2*6000*222*15b6b685bae998f2f608c909dc554e514f2843fbac3c7c16ea3600cc0de30212*c417098b445cfc7a87d56ba17200836f30208d38f75a4169c0280bab3b10ca2a*0d15a81eadccc58b1d3942090cd0ba66*57c4aa5ac7295a97da10f8b2f2d2bfd7a98b0faf75396bc1b55164a1e1dc7e52*2b822bb7e7d060bb42324459cb24df4d3ecd66dc5fc627ac50bf2d7c4255e4f8*1*64*aaf72933951a03351e032b382232bcafbeeabc9bc8e6988b18407bc5b8f0e3cc
13500 	PeopleSoft PS_TOKEN 	b5e335754127b25ba6f99a94c738e24cd634c35a:aa07d396f5038a6cbeded88d78d1d6c907e4079b3dc2e12fddee409a51cc05ae73e8cc24d518c923a2f79e49376594503e6238b806bfe33fa8516f4903a9b4
13600 	WinZip 	$zip2$*0*3*0*b5d2b7bf57ad5e86a55c400509c672bd*d218*0**ca3d736d03a34165cfa9*$/zip2$
13711 	VeraCrypt PBKDF2-HMAC-RIPEMD160 + AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes_13711.vc
13712 	VeraCrypt PBKDF2-HMAC-RIPEMD160 + AES-Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_aes-twofish_13712.vc
13711 	VeraCrypt PBKDF2-HMAC-RIPEMD160 + Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent_13711.vc
13712 	VeraCrypt PBKDF2-HMAC-RIPEMD160 + Serpent-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent-aes_13712.vc
13713 	VeraCrypt PBKDF2-HMAC-RIPEMD160 + Serpent-Twofish-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_serpent-twofish-aes_13713.vc
13711 	VeraCrypt PBKDF2-HMAC-RIPEMD160 + Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_twofish_13711.vc
13712 	VeraCrypt PBKDF2-HMAC-RIPEMD160 + Twofish-Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_ripemd160_twofish-serpent_13712.vc
13751 	VeraCrypt PBKDF2-HMAC-SHA256 + AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes_13751.vc
13752 	VeraCrypt PBKDF2-HMAC-SHA256 + AES-Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_aes-twofish_13752.vc
13751 	VeraCrypt PBKDF2-HMAC-SHA256 + Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent_13751.vc
13752 	VeraCrypt PBKDF2-HMAC-SHA256 + Serpent-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-aes_13752.vc
13753 	VeraCrypt PBKDF2-HMAC-SHA256 + Serpent-Twofish-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_serpent-twofish-aes_13753.vc
13751 	VeraCrypt PBKDF2-HMAC-SHA256 + Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish_13751.vc
13752 	VeraCrypt PBKDF2-HMAC-SHA256 + Twofish-Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha256_twofish-serpent_13752.vc
13721 	VeraCrypt PBKDF2-HMAC-SHA512 + AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_aes_13721.vc
13722 	VeraCrypt PBKDF2-HMAC-SHA512 + AES-Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_aes-twofish_13722.vc
13721 	VeraCrypt PBKDF2-HMAC-SHA512 + Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent_13721.vc
13722 	VeraCrypt PBKDF2-HMAC-SHA512 + Serpent-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent-aes_13722.vc
13723 	VeraCrypt PBKDF2-HMAC-SHA512 + Serpent-Twofish-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_serpent-twofish-aes_13723.vc
13721 	VeraCrypt PBKDF2-HMAC-SHA512 + Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_twofish_13721.vc
13722 	VeraCrypt PBKDF2-HMAC-SHA512 + Twofish-Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_sha512_twofish-serpent_13722.vc
13731 	VeraCrypt PBKDF2-HMAC-Whirlpool + AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_aes_13731.vc
13732 	VeraCrypt PBKDF2-HMAC-Whirlpool + AES-Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_aes-twofish_13732.vc
13731 	VeraCrypt PBKDF2-HMAC-Whirlpool + Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent_13731.vc
13732 	VeraCrypt PBKDF2-HMAC-Whirlpool + Serpent-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent-aes_13732.vc
13733 	VeraCrypt PBKDF2-HMAC-Whirlpool + Serpent-Twofish-AES 	https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_serpent-twofish-aes_13733.vc
13731 	VeraCrypt PBKDF2-HMAC-Whirlpool + Twofish 	https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_twofish_13731.vc
13732 	VeraCrypt PBKDF2-HMAC-Whirlpool + Twofish-Serpent 	https://hashcat.net/misc/example_hashes/vc/hashcat_whirlpool_twofish-serpent_13732.vc
13800 	Windows Phone 8+ PIN/password 	95fc4680bcd2a5f25de3c580cbebadbbf256c1f0ff2e9329c58e36f8b914c11f:4471347156480581513210137061422464818088437334031753080747625028271635402815635172140161077854162657165115624364524648202480341513407048222056541500234214433548175101668212658151115765112202168288664210443352443335235337677853484573107775345675846323265745
13900 	OpenCart 	6e36dcfc6151272c797165fce21e68e7c7737e40:472433673
14000 	DES (PT = $salt, key = $pass) 8 	a28bc61d44bb815c:1172075784504605
14100 	3DES (PT = $salt, key = $pass) 9 	37387ff8d8dafe15:8152001061460743
14400 	sha1(CX) 	fd9149fb3ae37085dc6ed1314449f449fbf77aba:87740665218240877702
14600 	LUKS 10 	https://hashcat.net/misc/example_hashes/hashcat_luks_testfiles.7z
14700 	iTunes backup < 10.0 11 	$itunes_backup$*9*b8e3f3a970239b22ac199b622293fe4237b9d16e74bad2c3c3568cd1bd3c471615a6c4f867265642*10000*4542263740587424862267232255853830404566**
14800 	iTunes backup >= 10.0 11 	$itunes_backup$*10*8b715f516ff8e64442c478c2d9abb046fc6979ab079007d3dbcef3ddd84217f4c3db01362d88fa68*10000*2353363784073608264337337723324886300850*10000000*425b4bb4e200b5fd4c66979c9caca31716052063
14900 	Skip32 (PT = $salt, key = $pass) 12 	c9350366:44630464
15000 	FileZilla Server >= 0.9.55 	632c4952b8d9adb2c0076c13b57f0c934c80bdc14fc1b4c341c2e0a8fd97c4528729c7bd7ed1268016fc44c3c222445ebb880eca9a6638ea5df74696883a2978:0608516311148050266404072407085605002866301131581532805665756363
15100 	Juniper/NetBSD sha1crypt 	$sha1$15100$jiJDkz0E$E8C7RQAD3NetbSDz7puNAY.5Y2jr
15200 	Blockchain, My Wallet, V2 	$blockchain$v2$5000$288$06063152445005516247820607861028813ccf6dcc5793dc0c7a82dcd604c5c3e8d91bea9531e628c2027c56328380c87356f86ae88968f179c366da9f0f11b09492cea4f4d591493a06b2ba9647faee437c2f2c0caaec9ec795026af51bfa68fc713eaac522431da8045cc6199695556fc2918ceaaabbe096f48876f81ddbbc20bec9209c6c7bc06f24097a0e9a656047ea0f90a2a2f28adfb349a9cd13852a452741e2a607dae0733851a19a670513bcf8f2070f30b115f8bcb56be2625e15139f2a357cf49d72b1c81c18b24c7485ad8af1e1a8db0dc04d906935d7475e1d3757aba32428fdc135fee63f40b16a5ea701766026066fb9fb17166a53aa2b1b5c10b65bfe685dce6962442ece2b526890bcecdeadffbac95c3e3ad32ba57c9e
15300 	DPAPI master key file version 1 + local context 	$DPAPImk$1*1*S-15-21-466364039-425773974-453930460-1925*des3*sha1*24000*b038489dee5ad04e3e3cab4d957258b5*208*cb9b5b7d96a0d2a00305ca403d3fd9c47c561e35b4b2cf3aebfd1d3199a6481d56972be7ebd6c291b199e6f1c2ffaee91978706737e9b1209e6c7d3aa3d8c3c3e38ad1ccfa39400d62c2415961c17fd0bd6b0f7bbd49cc1de1a394e64b7237f56244238da8d37d78
15400 	ChaCha20 	$chacha20$*0400000000000003*9*0200000000000001*4a4b4c4d4e4f5051*676e31b5ad612c2b
15500 	JKS Java Key Store Private Keys (SHA1) 	$jksprivk$*5A3AA3C3B7DD7571727E1725FB09953EF3BEDBD9*0867403720562514024857047678064085141322*81*C3*50DDD9F532430367905C9DE31FB1*test
15600 	Ethereum Wallet, PBKDF2-HMAC-SHA256 	$ethereum$p*262144*3238383137313130353438343737383736323437353437383831373034343735*06eae7ee0a4b9e8abc02c9990e3730827396e8531558ed15bb733faf12a44ce1*e6d5891d4f199d31ec434fe25d9ecc2530716bc3b36d5bdbc1fab7685dda3946
15700 	Ethereum Wallet, SCRYPT 	$ethereum$s*262144*1*8*3436383737333838313035343736303637353530323430373235343034363130*8b58d9d15f579faba1cd13dd372faeb51718e7f70735de96f0bcb2ef4fb90278*8de566b919e6825a65746e266226316c1add8d8c3d15f54640902437bcffc8c3
15900 	DPAPI master key file version 2 + Active Directory domain context 	$DPAPImk$2*2*S-15-21-423929668-478423897-489523715-1834*aes256*sha512*8000*740866e4105c77f800f02d367dd96699*288*ebc2907e16245dfe6c902ad4be70a079e62204c8a947498455056d150e6babb3c90b1616a8dff0e390dd26dda1978dffcbd7b9d7d1ea5c6d3e4df36db4d977051ec01fd6f0882a597c51834cb86445cad50c716f48b37cfd24339d8b43da771526fb01376798251edaa868fa2b1fa85c4142864b899987d4bbdc87b53433ed945fa4ab49c7f9d4d01df3ae19f25013b2
16000* 	Tripcode 	pfaRCwDe0U
16100* 	TACACS+ 	$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006
16200* 	Apple Secure Notes 	$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41
16300* 	Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256 	$ethereum$w*e94a8e49deac2d62206bf9bfb7d2aaea7eb06c1a378cfc1ac056cc599a569793c0ecc40e6a0c242dee2812f06b644d70f43331b1fa2ce4bd6cbb9f62dd25b443235bdb4c1ffb222084c9ded8c719624b338f17e0fd827b34d79801298ac75f74ed97ae16f72fccecf862d09a03498b1b8bd1d984fc43dd507ede5d4b6223a582352386407266b66c671077eefc1e07b5f42508bf926ab5616658c984968d8eec25c9d5197a4a30eed54c161595c3b4d558b17ab8a75ccca72b3d949919d197158ea5cfbc43ac7dd73cf77807dc2c8fe4ef1e942ccd11ec24fe8a410d48ef4b8a35c93ecf1a21c51a51a08f3225fbdcc338b1e7fdafd7d94b82a81d88c2e9a429acc3f8a5974eafb7af8c912597eb6fdcd80578bd12efddd99de47b44e7c8f6c38f2af3116b08796172eda89422e9ea9b99c7f98a7e331aeb4bb1b06f611e95082b629332c31dbcfd878aed77d300c9ed5c74af9cd6f5a8c4a261dd124317fb790a04481d93aec160af4ad8ec84c04d943a869f65f07f5ccf8295dc1c876f30408eac77f62192cbb25842470b4a5bdb4c8096f56da7e9ed05c21f61b94c54ef1c2e9e417cce627521a40a99e357dd9b7a7149041d589cbacbe0302db57ddc983b9a6d79ce3f2e9ae8ad45fa40b934ed6b36379b780549ae7553dbb1cab238138c05743d0103335325bd90e27d8ae1ea219eb8905503c5ad54fa12d22e9a7d296eee07c8a7b5041b8d56b8af290274d01eb0e4ad174eb26b23b5e9fb46ff7f88398e6266052292acb36554ccb9c2c03139fe72d3f5d30bd5d10bd79d7cb48d2ab24187d8efc3750d5a24980fb12122591455d14e75421a2074599f1cc9fdfc8f498c92ad8b904d3c4307f80c46921d8128*f3abede76ac15228f1b161dd9660bb9094e81b1b*d201ccd492c284484c7824c4d37b1593
99999 	Plaintext 	hashcat

* In beta or not yet released
1 Password: “hashcat!”
2 Rounds=[# of iterations] is optional here, after signature, e.g. $5$rounds=5000
3 As in 2 but the number of rounds must be specified
4 The hash used here is not the one sent via e.g. the web interface to LastPass servers (pbkdf2_sha256_hex (pbkdf2_sha256 ($pass, $email, $iterations), $pass, 1) but instead the one stored (by e.g. your browser or the pocket version) to disk. For instance, Opera and Chrome store the hash in local SQLite databases; Firefox uses files ending with “lpall.slps” - for Linux: 2nd line is interesting / base64 decode it; for Windows, see here - and_key.itr
5 You can consider the second part as a “salt”. If it is equal to 00000000, the CRC32 code will be considered as “not salted”
6 The raw sha256 output is used for base64() encoding (not the hexadecimal output)
7 The format is hash:salt:id
8 Password: “hashcat1”
9 Password: “hashcat1hashcat1hashcat1”
10 This file actually contains several examples of the different hash+cipher combinations. The password is stored in the pw file.
11 You can use itunes_backup2hashcat to extract the hashes from the Manifest.plist file
12 Password: “hashcat!!!”. Min/max password length is exactly 10 characters/bytes.
13 You can use AxSuite by Fist0urs to retrieve the hashes.
14 Password: a288fcf0caaacda9a9f58633ff35e8992a01d9c10ba5e02efdf8cb5d730ce7bc
Specific hash types

These hash types are usually only found on a specific platform.
Hash-Mode 	Hash-Name 	Example
11 	Joomla < 2.5.18 	19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777
12 	PostgreSQL 	a6343a68d964ca596d9752250d54bb8a:postgres
21 	osCommerce, xt:Commerce 	374996a5e8a5e57fd97d893f7df79824:36
22 	Juniper NetScreen/SSG (ScreenOS) 	nNxKL2rOEkbBc9BFLsVGG6OtOUO/8n:user
23 	Skype 	3af0389f093b181ae26452015f4ae728:user
101 	nsldap, SHA-1(Base64), Netscape LDAP SHA 	{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=
111 	nsldaps, SSHA-1(Base64), Netscape LDAP SSHA 	{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==
112 	Oracle S: Type (Oracle 11+) 	ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130
121 	SMF (Simple Machines Forum) > v1.1 	ecf076ce9d6ed3624a9332112b1cd67b236fdd11:17782686
122 	OSX v10.4, OSX v10.5, OSX v10.6 	1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683
124 	Django (SHA-1) 	sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013
125 	ArubaOS 	5387280701327dc2162bdeb451d5a465af6d13eff9276efeba
131 	MSSQL (2000) 	0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578
132 	MSSQL (2005) 	0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe
133 	PeopleSoft 	uXmFVrdBvv293L9kDR3VnRmx4ZM=
141 	Episerver 6.x < .NET 4 	$episerver$*0*bEtiVGhPNlZpcUN4a3ExTg==*utkfN0EOgljbv5FoZ6+AcZD5iLk
1411 	SSHA-256(Base64), LDAP {SSHA256} 	{SSHA256}OZiz0cnQ5hgyel3Emh7NCbhBRCQ+HVBwYplQunHYnER7TLuV
1421 	hMailServer 	8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3
1441 	Episerver 6.x >= .NET 4 	$episerver$*1*MDEyMzQ1Njc4OWFiY2RlZg==*lRjiU46qHA7S6ZE7RfKUcYhB85ofArj1j7TrCtu3u6Y
1711 	SSHA-512(Base64), LDAP {SSHA512} 	{SSHA512}ALtwKGBdRgD+U0fPAy31C28RyKYx7+a8kmfksccsOeLknLHv2DBXYI7TDnTolQMBuPkWDISgZr2cHfnNPFjGZTEyNDU4OTkw
1722 	OSX v10.7 	648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d
1731 	MSSQL (2012, 2014) 	0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375
2611 	vBulletin < v3.8.5 	16780ba78d2d5f02f3202901c1b6d975:568
2612 	PHPS 	$PHPS$34323438373734$5b07e065b9d78d69603e71201c6cf29f
2711 	vBulletin >= v3.8.5 	bf366348c53ddcfbd16e63edfdd1eee6:181264250056774603641874043270
2811 	IPB2+ (Invision Power Board), MyBB 1.2+ 	8d2129083ef35f4b365d5d87487e1207:47204
3711 	MediaWiki B type 	$B$56668501$0ce106caa70af57fd525aeaf80ef2898
4521 	Redmine 	1fb46a8f81d8838f46879aaa29168d08aa6bf22d:3290afd193d90e900e8021f81409d7a9
4522 	PunBB 	4a2b722cc65ecf0f7797cdaea4bce81f66716eef:653074362104
12001 	Atlassian (PBKDF2-HMAC-SHA1)	{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa
Legacy hash types

These hash types are only supported in hashcat-legacy or oclHashcat.
Hash-Mode 	Hash-Name 	Example
123 	EPi 	0x326C6D7B4E4F794B79474E36704F35723958397163735263516265456E31 0xAFC55E260B8F45C0C6512BCE776C1AD8312B56E6
190 	sha1(LinkedIn) 2 	b89eaac7e61417341b710b727768294d0e6a277b
1431 	base64(sha256(unicode($pass))) 1 	npKD5jP0p6QtOryTcBFVvor+VmDaJMh1jn01M+Ly3II=
3300 	MD5(Sun) 1 	$md5$rounds=904$iPPKEBnEkp3JV8uX$0L6m7rOFTVFn.SGqo2M9W1
3500 	md5(md5(md5($pass))) 1 	9882d0778518b095917eb589f6998441
3610 	md5(md5($salt).$pass) 1 	7b57255a15958ef898543ea6cc3313bc:1234
3720 	md5($pass.md5($salt)) 1 	10ce488714fdbde9453670e0e4cbe99c:1234
3721 	WebEdition CMS 1 	fa01af9f0de5f377ae8befb03865178e:​5678
4210 	md5($username.0.$pass) 1 	09ea048c345ad336ebe38ae5b6c4de24:1234
4600 	sha1(sha1(sha1($pass))) 1 	dc57f246485e62d99a5110afc9264b4ccbfcf3cc

1 Supported in hashcat-legacy
2 Supported in oclHashcat
Except where otherwise noted, content on this wiki is licensed under the following license: Public Domain
