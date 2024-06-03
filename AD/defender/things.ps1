

# Save this script as Manage-WindowsDefender.ps1

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





