<#PSScriptInfo

.VERSION 2.0

.GUID a0539e07-fe20-4f41-81f2-a0acbb51a382

.AUTHOR Andriy Zarevych

.COMPANYNAME

.COPYRIGHT 2018 Andriy Zarevych

.TAGS ActiveDirectory LAPS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES ActiveDirectory

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<#
.SYNOPSIS
 Get LAPS Passwords information from Active Directory.
 Generates a CSV file with computer names and LAPS Passwords.

.DESCRIPTION
 Get LAPS Passwords information from Active Directory.
 Generates a CSV file with computer names and LAPS Passwords.
    ComputerName;OperatingSystem;Password;PasswordExpTime;DistinguishedName

 Requirement of the script:
    - Active Directory PowerShell Module
    - Needed rights to view AD LAPS Attributes: ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
   

 Usage:
    .\Get-ADComputers-LAPS-Password.ps1
    .\Get-ADComputers-LAPS-Password.ps1 -OU "OU=Computers,OU=IT Department,DC=myDomain,DC=com"
 

 Recommendation is to run this script as a schedule task to have backup your LAPS Passwords

 In Section Initialisations you may set default value:
 to set default value for OU
    [string]$OU =
 to set default name for a CSV file
    [string]$LogFileName = 
 to set default path for a CSV file
    [string]$LogFilePath = 


.PARAMETER OU
    Optional parameter to narrow the scope of the script

.PARAMETER LogFilePath
    Optional parameter to set path for log files

    Example: -LogFilePath "C:\Scripts"

.PARAMETER LogFileName
    Optional parameter to set name for log files


.EXAMPLE
   .\Get-ADComputers-LAPS-Password.ps1

   Description
   -----------
   Generates a CSV file with computer names and LAPS Passwords
   
.EXAMPLE
   .\Get-ADComputers-LAPS-Password.ps1 -OU "OU=Computers,OU=IT Department,DC=myDomain,DC=com"

   Description
   -----------
   Generates a CSV file with computer names and LAPS Passwords for computers in targed OU

.EXAMPLE
   .\Get-ADComputers-LAPS-Password.ps1 -OU "OU=Computers,OU=IT Department,DC=myDomain,DC=com" -LogFilePath "C:\Scripts" -LogFileName "LAPS-Passwords.csv"

   Description
   -----------
   Generates a CSV file with specific name and path


.NOTES
   File Name  : Get-ADComputers-LAPS-Password.ps1
   Version    : 2.0
   Date       : 2018.07.05
   Author     : Andriy Zarevych

   Find me on :
   * My Blog  :	https://angry-admin.blogspot.com/
   * LinkedIn :	https://linkedin.com/in/zarevych/
   * Github   :	https://github.com/zarevych

#>

#Requires -Modules ActiveDirectory
#Requires -Version 2.0

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[CmdletBinding()]

    Param(
    [Parameter(Mandatory=$false, HelpMessage="Enter OU, example: OU=Computers,OU=ITDep,DC=contoso,DC=com", ValueFromPipelineByPropertyName=$true)]    
    [string]$OU,
    [Parameter(Mandatory=$false, HelpMessage="Enter path for log file, example: C:\Scripts", ValueFromPipelineByPropertyName=$true)]    
    [string]$LogFilePath = ".\",
    [Parameter(Mandatory=$false, HelpMessage="Enter log file Name", ValueFromPipelineByPropertyName=$true)]    
    [string]$LogFileName = "LAPS-Password_$(Get-Date -f 'yyyy-MM-dd').csv"
    )

#----------------------------------------------------------[Declarations]----------------------------------------------------------

Import-Module ActiveDirectory

#To separating fields for report
$strDelimiter = ";"

if (-Not (Test-Path -PathType Container $LogFilePath)){
    $LogFilePath = New-Item -ItemType Directory -Force -Path $LogFilePath
}

if ($LogFilePath.Substring($LogFilePath.Length-1) -eq "\" -or $LogFilePath.Substring($LogFilePath.Length-1) -eq "/"){
   
}
else {
    $LogFilePath = $LogFilePath + "\"
}

$LogFile = $LogFilePath + $LogFileName

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Report file $LogFile

if (Test-Path $LogFile){
    #Remove-Item $LogFile
    Clear-Content $LogFile
}
else {
    $LogFile = New-Item -Path $LogFilePath -Name $LogFileName -ItemType File
}


#

write-host
write-host "Script start" $(Get-Date)
write-host

#Set scope
#Get computers info
if ($OU -ne "") {
    Write-Host "Organizational Unit:" $OU
    $Computers = Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property * -SearchBase $OU
    
}
else {
    Write-Host "Domain:" $env:userdnsdomain
    $Computers = Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property *
}

write-host "Report File Path:" $LogFile

#Write report header
$strToReport = "ComputerName" + $strDelimiter + "OperatingSystem" + $strDelimiter + "Password" + $strDelimiter + "ExpTime" + $strDelimiter + "DistinguishedName"
Add-Content $LogFile $strToReport

#Get LAPS Info
#Write report
foreach ($Computer in $Computers) {
    
    if ($Computer.'ms-Mcs-AdmPwd'){
   
        $strComputerPassword=$Computer.'ms-Mcs-AdmPwd'
        
        $strComputerExpTime = $Computer.'ms-MCS-AdmPwdExpirationTime'

        if ($strComputerExpTime -ge 0) {$strComputerExpTime = $([datetime]::FromFileTime([convert]::ToInt64($strComputerExpTime)))}
        
        $strComputerExpTime = "{0:yyyy-MM-dd HH:mm:ss}" -f [datetime]$strComputerExpTime

        $strToReport = $Computer.Name + $strDelimiter + $Computer.OperatingSystem + $strDelimiter + """$strComputerPassword""" + $strDelimiter + """$strComputerExpTime""" + $strDelimiter + $Computer.DistinguishedName

        Add-Content $LogFile $strToReport

    }

}

write-host
write-host "Script end" $(Get-Date)
write-host
