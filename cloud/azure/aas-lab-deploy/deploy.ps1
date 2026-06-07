#
# Author: @lydericlefebvre
# whatis: Automate the deployment on Azure of an Active Directory Lab
#           - with heterogeneous OS
#           - with domain users adding
#           - with users logon emulations
# Thanks: Based on automatedlab https://github.com/AutomatedLab/
#


#################
# PREREQUISITES #
#################
<#
    1. To deploy on Azure, you have to have an Azure account.
        You can have a free one, but limited to 4 Core (OK to deploy up to 4 VMs).
        https://azure.microsoft.com/en-us/free/
    2. Install automatedlab (msi setup)
        https://github.com/AutomatedLab/AutomatedLab/releases
    
    3. Install Azure Powershell
        Install-Module -Name Az -AllowClobber -Scope CurrentUser
#>


##############
# DEPLOYMENT #
##############
# Lab Name: must be uniq!
$labName = 'PawPatrolLab'

# Location: https://azure.microsoft.com/en-us/global-infrastructure/locations/
$azureDefaultLocation = 'West Europe'

# Lab definition
New-LabDefinition -Name $labName -DefaultVirtualizationEngine Azure

<#
    We add a lab Azure subscription.
        Depending on your connection, it can take 1 hour the first time it is launched because of LabSources sync.
        https://automatedlab.org/en/latest/Wiki/synclabsources/
        https://automatedlab.org/en/latest/AutomatedLab/en-us/Sync-LabAzureLabSources/
#>
Add-LabAzureSubscription -DefaultLocationName $azureDefaultLocation

# Network definition
Add-LabVirtualNetworkDefinition -Name $labName -AddressSpace 192.168.30.0/24

# Domain definition
Add-LabDomainDefinition -Name pawpatrol.local -AdminUser pawpatrolAdmin -AdminPassword 'P@wpAt6_##==='

# Lab install definition
Set-LabInstallationCredential -Username pawpatrolAdmin -Password 'P@wpAt6_##==='

# Default parameter values for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'pawpatrol.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.30.10'
}

# Domain Controller definition + Creating random users
$roles = Get-LabMachineRoleDefinition -Role RootDC
$postInstallActivity = @()
$postInstallActivity += Get-LabPostInstallationActivity -ScriptFileName 'New-ADLabAccounts 2.0.ps1' -DependencyFolder $labSources\PostInstallationActivities\PrepareFirstChildDomain
$postInstallActivity += Get-LabPostInstallationActivity -ScriptFileName PrepareRootDomain.ps1 -DependencyFolder $labSources\PostInstallationActivities\PrepareRootDomain
Add-LabMachineDefinition -Name DC1-2016 -Memory 2GB -Roles $roles -OperatingSystem 'Windows Server 2016 Datacenter' -IpAddress 192.168.30.10 -PostInstallationActivity $postInstallActivity

<#
    Other machines definitions
        /!\ IF YOU HAVE FREE SUBSCRIPTION, YOU CAN ONLY HAVE 4 VMs
        So feel free to comment, otherwise deployment will fail /!\
#>
Add-LabMachineDefinition -Name FS1-2019 -Memory 1GB -OperatingSystem 'Windows Server 2019 Datacenter' -IpAddress 192.168.30.50
Add-LabMachineDefinition -Name FS2-2016 -Memory 1GB -OperatingSystem 'Windows Server 2016 Datacenter' -IpAddress 192.168.30.51
Add-LabMachineDefinition -Name SQL-2012-R2 -Memory 1GB -OperatingSystem 'Windows Server 2012 R2 Datacenter (Server with a GUI)' -IpAddress 192.168.30.52
Add-LabMachineDefinition -Name WEB-2012-R2 -Memory 1GB -OperatingSystem 'Windows Server 2012 R2 Datacenter (Server with a GUI)' -IpAddress 192.168.30.53
Add-LabMachineDefinition -Name BAS-2012-R2 -Memory 1GB -OperatingSystem 'Windows Server 2012 R2 Datacenter (Server with a GUI)' -IpAddress 192.168.30.54
Add-LabMachineDefinition -Name RAD-2008-R2 -Memory 1GB -OperatingSystem 'Windows Server 2008 R2 Datacenter (Full Installation)' -IpAddress 192.168.30.55
Add-LabMachineDefinition -Name FS3-2008-R2 -Memory 1GB -OperatingSystem 'Windows Server 2008 R2 Datacenter (Full Installation)' -IpAddress 192.168.30.56

#Add-LabMachineDefinition -Name SQL-2012 -Memory 1GB -OperatingSystem 'Windows Server 2012 Datacenter (Server with a GUI)' -IpAddress 192.168.30.57
#Add-LabMachineDefinition -Name PC-10-PRO -Memory 1GB -OperatingSystem 'Windows 10 Pro' -IpAddress 192.168.30.58

# Launch lab installation
Install-Lab


####################
# POST-DEPLOYMENT  #
#  -> ADDING USERS #
####################
# We are adding the pawpatrol and make them DA!
Invoke-LabCommand -ActivityName AddPawPatrol -ComputerName (Get-LabVM -Role RootDC) -ScriptBlock {
	# Secure passwords definition
	$ryderPassword = "No job is too big, no pup is too sm@ll2!" | ConvertTo-SecureString -AsPlainText -Force
	$chasePassword = "Ch@se is on the case3!" | ConvertTo-SecureString -AsPlainText -Force
	$marshallPassword = "Re@dy for a ruff ruff rescue4!" | ConvertTo-SecureString -AsPlainText -Force
	$skyePassword = "Let's t@ke to the sky5!" | ConvertTo-SecureString -AsPlainText -Force
	$rockyPassword = "Don't lose it,@ reuse it6!" | ConvertTo-SecureString -AsPlainText -Force
	$rubblePassword = "Let's dig it7@!" | ConvertTo-SecureString -AsPlainText -Force
	$zumaPassword = "Let's dive in!@8" | ConvertTo-SecureString -AsPlainText -Force
	$everestPassword = "Ice or snow, I'm re@dy to go9!" | ConvertTo-SecureString -AsPlainText -Force

	# Adding domain users
	New-ADUser -Name ryder -AccountPassword $ryderPassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
	New-ADUser -Name chase -AccountPassword $chasePassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
	New-ADUser -Name marshall -AccountPassword $marshallPassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
	New-ADUser -Name skye -AccountPassword $skyePassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
	New-ADUser -Name rocky -AccountPassword $rockyPassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
	New-ADUser -Name rubble -AccountPassword $rubblePassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
	New-ADUser -Name zuma -AccountPassword $zumaPassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
	New-ADUser -Name everest -AccountPassword $everestPassword -Enabled $true -PassThru | % {Add-ADGroupMember -Identity "Domain Admins" -Members $_}
}


#######################
# POST-DEPLOYMENT     #
#  -> USERS EMULATION #
#######################
<#
    We try to emulate user logon by doing some runas on machines
        /!\ IF YOU HAVE FREE SUBSCRIPTION, YOU CAN ONLY HAVE 4 VMs
        You must comment every runas which aim previously commented machines /!\
#>

# DC1-2016's ryder runas
Invoke-LabCommand -ActivityName DC1-2016_RYDER_EMULATION -ComputerName (Get-LabVM -ComputerName DC1-2016) -ScriptBlock {
	$username = "pawpatrol\ryder"
    $password = "No job is too big, no pup is too sm@ll2!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# FS1-2019's marshall runas
Invoke-LabCommand -ActivityName FS1-2019_MARSHALL_EMULATION -ComputerName (Get-LabVM -ComputerName FS1-2019) -ScriptBlock {
	$username = "pawpatrol\marshall"
    $password = "Re@dy for a ruff ruff rescue4!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# FS2-2016's skye runas
Invoke-LabCommand -ActivityName FS2-2016_SKYE_EMULATION -ComputerName (Get-LabVM -ComputerName FS2-2016) -ScriptBlock {
	$username = "pawpatrol\skye"
    $password = "Let's t@ke to the sky5!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# SQL-2012-R2's chase runas 
Invoke-LabCommand -ActivityName SQL-2012-R2_CHASE_EMULATION -ComputerName (Get-LabVM -ComputerName SQL-2012-R2) -ScriptBlock {
	$username = "pawpatrol\chase"
    $password = "Ch@se is on the case3!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# BAS-2012-R2's rocky runas
Invoke-LabCommand -ActivityName BAS-2012-R2_ROCKY_EMULATION -ComputerName (Get-LabVM -ComputerName BAS-2012-R2) -ScriptBlock {
	$username = "pawpatrol\rocky"
    $password = "Don't lose it,@ reuse it6!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# WEB-2012-R2's everest runas 
Invoke-LabCommand -ActivityName WEB-2012-R2_EVEREST_EMULATION -ComputerName (Get-LabVM -ComputerName WEB-2012-R2) -ScriptBlock {
	$username = "pawpatrol\everest"
    $password = "Ice or snow, I'm re@dy to go9!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# RAD-2008-R2's everest runas
Invoke-LabCommand -ActivityName RAD-2008-R2_EVEREST_EMULATION -ComputerName (Get-LabVM -ComputerName RAD-2008-R2) -ScriptBlock {
	$username = "pawpatrol\everest"
    $password = "Ice or snow, I'm re@dy to go9!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# RAD-2008-R2's rocky runas
Invoke-LabCommand -ActivityName RAD-2008-R2_ROCKY_EMULATION -ComputerName (Get-LabVM -ComputerName RAD-2008-R2) -ScriptBlock {
	$username = "pawpatrol\rocky"
    $password = "Don't lose it,@ reuse it6!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}

# FS3-2008-R2's rubble runas
Invoke-LabCommand -ActivityName FS3-2008-R2_RUBBLE_EMULATION -ComputerName (Get-LabVM -ComputerName FS3-2008-R2) -ScriptBlock {
	$username = "pawpatrol\rubble"
    $password = "Let's dig it7@!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}
#>
<#
# SQL-2012's zuma runas
Invoke-LabCommand -ActivityName SQL-2012_ZUMA_EMULATION -ComputerName (Get-LabVM -ComputerName SQL-2012) -ScriptBlock {
	$username = "pawpatrol\zuma"
    $password = "Let's dive in!@8"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process Notepad.exe -Credential $credential
}
#>


# Get a deployment summary (passwords, etc)
Show-LabDeploymentSummary -Detailed


#########
# CLEAN #
#########
# Remove-Lab
