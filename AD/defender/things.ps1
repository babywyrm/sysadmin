
# disable
powershell -command 'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true'

# Or exclude
powershell -command 'Add-MpPreference -ExclusionPath "c:\temp" -ExclusionProcess "c:\temp\yourstuffs.exe"'

##
##
## Save this script as Manage-WindowsDefender.ps1

function Disable-WindowsDefender {
    # Disable Windows Defender Real-Time Protection
    Set-MpPreference -DisableRealtimeMonitoring $true
    Write-Output "Windows Defender real-time protection disabled."

    # Stop Windows Defender Antivirus Service
    sc stop WinDefend
    sc config WinDefend start= disabled
    Write-Output "Windows Defender service stopped and disabled."

    # Disable Windows Defender using Group Policy
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
    Write-Output "Windows Defender AntiSpyware disabled via Group Policy."
}

function Enable-WindowsDefender {
    # Enable Windows Defender Real-Time Protection
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Output "Windows Defender real-time protection enabled."

    # Start Windows Defender Antivirus Service
    sc config WinDefend start= auto
    sc start WinDefend
    Write-Output "Windows Defender service started and set to auto."

    # Enable Windows Defender using Group Policy
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
    Write-Output "Windows Defender AntiSpyware enabled via Group Policy."
}

# Example usage
# Disable-WindowsDefender
# Enable-WindowsDefender
Instructions
Save the Script:
Save the script above as Manage-WindowsDefender.ps1 on your system.

Run the Script:
Open PowerShell as an administrator and navigate to the directory where the script is saved.

Load the Functions:
Load the script into your PowerShell session:

powershell
Copy code
.\Manage-WindowsDefender.ps1
Use the Functions:
You can now call the functions Disable-WindowsDefender and Enable-WindowsDefender as needed.

powershell
Copy code
# To disable Windows Defender
Disable-WindowsDefender

# To enable Windows Defender
Enable-WindowsDefender
Example Commands
powershell
Copy code
# Navigate to the directory containing the script
cd C:\path\to\your\script

# Load the script
.\Manage-WindowsDefender.ps1

# Disable Windows Defender
Disable-WindowsDefender

# Enable Windows Defender
Enable-WindowsDefender
Additional Notes
Administrative Privileges: Ensure you are running PowerShell with administrative privileges to execute these commands.
Security Considerations: Disabling Windows Defender can leave your system vulnerable. Use these functions responsibly and only when necessary.
Verification: After running the functions, you can verify the status of Windows Defender settings using Get-MpPreference.
This script provides a convenient way to manage Windows Defender real-time protection and services through PowerShell.


##
##

# PowerShell script to add Windows Defender exclusions for WSL2 and JetBrains IDE performance issues
# 
# For context please read this thread:
# https://github.com/microsoft/WSL/issues/8995
# 
# How to use?
# - Save the Script: Open a text editor like Notepad and paste the PowerShell script into it. 
# - Save the file with a .ps1 extension, for example, Add_WindowsDefender_Exclusions.ps1.
# - Run PowerShell as Administrator: Search for "PowerShell" in the Start menu, right-click on it, and choose "Run as administrator".
# - Navigate to the Script's Location: Use the cd command to navigate to the directory where you saved the .ps1 file. 
# - Run the Script: Type .\Add_WindowsDefender_Exclusions.ps1 and press Enter. This will execute the script.
# - You will be prompted to enter your WSL distro (tested only on Ubuntu), username and IDE of choice

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator. Exiting."
    return
}

# Display IDE choices and prompt user to pick one
$ides = @("PhpStorm", "IntelliJ", "PyCharm", "RubyMine", "WebStorm", "DataGrip", "GoLand", "Rider", "Other")
$idePrompt = "Please select your IDE by typing the corresponding number:`n"
for ($i=0; $i -lt $ides.Length; $i++) {
    $idePrompt += "$i. $($ides[$i])`n"
}
$ideIndex = Read-Host $idePrompt
$selectedIDE = $ides[$ideIndex]

# Determine process based on IDE choice
$process = switch ($selectedIDE) {
    'PhpStorm' { "phpstorm64.exe" }
    'IntelliJ' { "idea64.exe" }
    'PyCharm'  { "pycharm64.exe" }
    'RubyMine' { "rubymine64.exe" }
    'WebStorm' { "webstorm64.exe" }
    'DataGrip' { "datagrip64.exe" }
    'GoLand'   { "goland64.exe" }
    'Rider'    { "rider64.exe" }
    'Other'    { Read-Host "Please enter the process name for your IDE (e.g., webstorm64.exe)" }
}
# Define folders to exclude, adjust if needed
$foldersToExclude = @(
    "C:\Users\$env:USERNAME\AppData\Local\JetBrains",
    "C:\Program Files\Docker",
    "C:\Program Files\JetBrains",
    "\\wsl$\$linuxDistro\home\$linuxUsername\src",
    "\\wsl.localhost\$linuxDistro\home\$linuxUsername\src"
)

# Define file types to exclude, adjust if needed
$fileTypesToExclude = @(
    "vhd",
    "vhdx"
)

# Define processes to exclude, adjust if needed
$processesToExclude = @(
    $process, # The process name based on the IDE choice
    "fsnotifier.exe",
    "jcef_helper.exe",
    "jetbrains-toolbox.exe",
    "docker.exe",
    "com.docker.*.*",
    "Desktop Docker.exe",
    "wsl.exe",
    "wslhost.exe",
    "vmmemWSL"
)

# Add Firewall Rule for WSL
# For details please read official documentation:
# https://www.jetbrains.com/help/idea/how-to-use-wsl-development-environment-in-product.html#debugging_system_settings
Write-Host "Adding firewall rules for WSL. This step may take a few minutes..."
try {
    New-NetFirewallRule -DisplayName "WSL" -Direction Inbound  -InterfaceAlias "vEthernet (WSL)"  -Action Allow
    Get-NetFirewallProfile -Name Public | Get-NetFirewallRule | Where-Object DisplayName -ILike "$($selectedIDE)*" | Disable-NetFirewallRule
} catch {
    Write-Host "Error adding firewall rule: $_"
}

# Add folder exclusions
Write-Host "Adding folder exclusions..."
foreach ($folder in $foldersToExclude) {
    Add-MpPreference -ExclusionPath $folder
}

# Add file type exclusions
Write-Host "Adding file type exclusions..."
foreach ($fileType in $fileTypesToExclude) {
    Add-MpPreference -ExclusionExtension $fileType
}

# Add process exclusions
Write-Host "Adding process exclusions..."
foreach ($process in $processesToExclude) {
    Add-MpPreference -ExclusionProcess $process
}

Write-Host "Script execution completed."

##
##


