## .\Invoke-WindowsClientHardening.ps1 -Mode Audit -Profile Balanced
## .\Invoke-WindowsClientHardening.ps1 -Mode Enforce -Profile Balanced
##
##

#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Modern Windows 10/11 client hardening baseline.

.DESCRIPTION
    Invoke-WindowsClientHardening.ps1 applies a modern, compatibility-conscious
    security baseline for Windows 10 and Windows 11 endpoints.

    The script is intended for:
      - Security labs
      - Blue-team validation
      - Endpoint hardening pilots
      - Small-business or workstation baselining
      - Pre-production testing before moving settings into Intune or Group Policy

    The script supports two execution modes:

      Audit:
        Does not modify the system. Reports current and desired values where
        practical and logs actions that would be taken.

      Enforce:
        Applies registry settings, Microsoft Defender settings, audit policy,
        firewall rules, and selected Windows optional feature changes.

    The script supports two profiles:

      Balanced:
        A practical default intended to improve security while minimizing
        usability and compatibility issues.

      Strict:
        Enables additional controls that may be appropriate for enterprise or
        high-risk systems, but may impact legacy applications, file sharing,
        remote administration, browser media permissions, or virtualization
        workflows.

    This script is designed as a local/bootstrap tool. For fleet deployment,
    prefer one or more of the following:
      - Microsoft Intune Security Baselines
      - Microsoft Intune Settings Catalog
      - Microsoft Defender for Endpoint Security Settings Management
      - Group Policy
      - Microsoft Security Compliance Toolkit
      - CIS Benchmarks
      - DISA STIG baselines

.PARAMETER Mode
    Audit or Enforce.

    Audit mode logs desired actions without changing the system.
    Enforce mode applies changes.

.PARAMETER Profile
    Balanced or Strict.

    Balanced is the recommended default.
    Strict enables additional settings that can be more disruptive.

.PARAMETER LogPath
    Path to the transcript log file.

.PARAMETER SkipBackup
    Skips registry export backups.

.PARAMETER BackupRoot
    Directory used to store registry backups.

.PARAMETER NoTranscript
    Disables PowerShell transcript logging for this run.

.EXAMPLE
    .\Invoke-WindowsClientHardening.ps1 -Mode Audit -Profile Balanced

    Reviews the current system against the Balanced profile without making
    changes.

.EXAMPLE
    .\Invoke-WindowsClientHardening.ps1 -Mode Enforce -Profile Balanced

    Applies the Balanced hardening baseline.

.EXAMPLE
    .\Invoke-WindowsClientHardening.ps1 -Mode Enforce -Profile Strict

    Applies the Strict hardening baseline. Test carefully before broad use.

.EXAMPLE
    .\Invoke-WindowsClientHardening.ps1 `
        -Mode Enforce `
        -Profile Balanced `
        -LogPath C:\Temp\hardening.log

    Applies the Balanced baseline and writes the transcript to C:\Temp.

.NOTES
    Author:
      Your Security Team

    Version:
      2026.04.26

    Supported OS:
      Windows 10 21H2+
      Windows 11 22H2+
      Windows Server is not the primary target.

    PowerShell:
      Windows PowerShell 5.1+

    Privileges:
      Must be run as Administrator.

    Reboot:
      Some changes require a reboot, including:
        - PowerShell v2 removal
        - SMBv1 removal
        - Credential Guard / VBS-related settings
        - LSASS PPL
        - driver integrity settings
        - some exploit protection settings

    Safety:
      Run in Audit mode first.
      Test in a lab or pilot ring.
      Keep registry backups.
      Do not blindly deploy Strict mode to production.

    Compatibility considerations:
      Strict mode may affect:
        - legacy SMB/NAS devices
        - unsigned or old drivers
        - older VPN clients
        - old Office macro workflows
        - browser-based screen/audio/video capture
        - WinRM-based management
        - virtualization products on older hardware

    Important:
      Tamper Protection is best managed by Intune, Microsoft Defender portal,
      or Microsoft Defender for Endpoint. Local registry changes may not enable
      or manage Tamper Protection reliably.

    Validation tools:
      - Microsoft Security Compliance Toolkit
      - CIS-CAT
      - Microsoft Defender Vulnerability Management
      - Intune policy reporting
      - Event Viewer
      - Get-MpPreference
      - Get-ProcessMitigation -System
      - auditpol /get /category:*

.LINK
    Microsoft Security Baselines:
    https://learn.microsoft.com/windows/security/threat-protection/windows-security-baselines

.LINK
    Microsoft Defender Attack Surface Reduction:
    https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference

.LINK
    Microsoft Security Compliance Toolkit:
    https://learn.microsoft.com/windows/security/threat-protection/security-compliance-toolkit-10

.LINK
    CIS Benchmarks:
    https://www.cisecurity.org/cis-benchmarks

.LINK
    DISA STIGs:
    https://public.cyber.mil/stigs/
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("Audit", "Enforce")]
    [string]$Mode = "Audit",

    [ValidateSet("Balanced", "Strict")]
    [string]$Profile = "Balanced",

    [string]$LogPath = "$env:ProgramData\WindowsHardening\Logs\hardening.log",

    [string]$BackupRoot = "$env:ProgramData\WindowsHardening\Backups",

    [switch]$SkipBackup,

    [switch]$NoTranscript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Script:State = [ordered]@{
    StartedAt       = Get-Date
    Mode            = $Mode
    Profile         = $Profile
    Hostname        = $env:COMPUTERNAME
    User            = "$env:USERDOMAIN\$env:USERNAME"
    Changes         = 0
    Errors          = 0
    Warnings        = 0
    AuditFindings   = 0
    RebootSuggested = $false
}

function Write-Section {
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    Write-Host ""
    Write-Host "================================================================"
    Write-Host " $Title"
    Write-Host "================================================================"
}

function Write-Info {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[INFO] $Message"
}

function Write-Audit {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[AUDIT] $Message"
    $Script:State.AuditFindings++
}

function Write-Change {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[SET] $Message"
    $Script:State.Changes++
}

function Write-SoftWarning {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Warning $Message
    $Script:State.Warnings++
}

function Write-SoftError {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Warning $Message
    $Script:State.Errors++
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-OsSummary {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem

        [pscustomobject]@{
            Caption      = $os.Caption
            Version      = $os.Version
            BuildNumber  = $os.BuildNumber
            Architecture = $os.OSArchitecture
            Manufacturer = $computer.Manufacturer
            Model        = $computer.Model
        }
    } catch {
        [pscustomobject]@{
            Caption      = "Unknown"
            Version      = "Unknown"
            BuildNumber  = "Unknown"
            Architecture = "Unknown"
            Manufacturer = "Unknown"
            Model        = "Unknown"
        }
    }
}

function Initialize-HardeningRun {
    Write-Section "Initialization"

    if (-not (Test-IsAdministrator)) {
        throw "This script must be run from an elevated PowerShell session."
    }

    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    if (-not $NoTranscript) {
        try {
            Start-Transcript -Path $LogPath -Append | Out-Null
        } catch {
            Write-SoftWarning "Could not start transcript: $($_.Exception.Message)"
        }
    }

    $os = Get-OsSummary

    Write-Info "Mode: $Mode"
    Write-Info "Profile: $Profile"
    Write-Info "Host: $env:COMPUTERNAME"
    Write-Info "User: $env:USERDOMAIN\$env:USERNAME"
    Write-Info "OS: $($os.Caption) $($os.Version) build $($os.BuildNumber)"
    Write-Info "Architecture: $($os.Architecture)"
    Write-Info "Hardware: $($os.Manufacturer) $($os.Model)"
    Write-Info "LogPath: $LogPath"

    if ($Mode -eq "Audit") {
        Write-Info "Audit mode selected. No changes will be applied."
    }

    if ($Profile -eq "Strict") {
        Write-SoftWarning "Strict profile may affect compatibility. Test first."
    }
}

function Backup-RegistryKeys {
    Write-Section "Registry backup"

    if ($SkipBackup) {
        Write-Info "Skipping registry backup because -SkipBackup was specified."
        return
    }

    if ($Mode -eq "Audit") {
        Write-Audit "Would back up registry keys to $BackupRoot."
        return
    }

    try {
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupDir = Join-Path -Path $BackupRoot -ChildPath $stamp

        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

        $keys = @(
            "HKLM\SOFTWARE\Policies",
            "HKCU\SOFTWARE\Policies",
            "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer",
            "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            "HKLM\SOFTWARE\Microsoft\Windows Defender",
            "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
        )

        foreach ($key in $keys) {
            $fileName = ($key -replace "\\", "_") + ".reg"
            $file = Join-Path -Path $backupDir -ChildPath $fileName

            Write-Info "Backing up $key to $file"
            & reg.exe export $key $file /y | Out-Null
        }

        Write-Change "Registry backup completed: $backupDir"
    } catch {
        Write-SoftError "Registry backup failed: $($_.Exception.Message)"
    }
}

function Get-RegValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            return $null
        }

        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        return $null
    }
}

function Set-RegValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Value,

        [ValidateSet("String", "DWord", "QWord", "MultiString", "ExpandString")]
        [string]$Type = "DWord"
    )

    try {
        $current = Get-RegValue -Path $Path -Name $Name

        if ($Mode -eq "Audit") {
            Write-Audit "$Path\$Name current=[$current] desired=[$Value]"
            return
        }

        if ($current -eq $Value) {
            Write-Info "$Path\$Name already set to [$Value]"
            return
        }

        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
            if (-not (Test-Path -Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }

            New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value $Value `
                -PropertyType $Type `
                -Force | Out-Null

            Write-Change "$Path\$Name = $Value"
        }
    } catch {
        Write-SoftError "Failed setting $Path\$Name : $($_.Exception.Message)"
    }
}

function Invoke-SafeAction {
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [switch]$SuggestReboot
    )

    try {
        if ($Mode -eq "Audit") {
            Write-Audit "Would run: $Description"
            return
        }

        if ($PSCmdlet.ShouldProcess($Description, "Execute")) {
            Write-Info "Running: $Description"
            & $ScriptBlock
            Write-Change $Description

            if ($SuggestReboot) {
                $Script:State.RebootSuggested = $true
            }
        }
    } catch {
        Write-SoftError "Failed: $Description : $($_.Exception.Message)"
    }
}

function Test-CommandAvailable {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Enable-DefenderBaseline {
    Write-Section "Microsoft Defender baseline"

    if (-not (Test-CommandAvailable -Name "Set-MpPreference")) {
        Write-SoftWarning "Defender PowerShell module not available. Skipping."
        return
    }

    Invoke-SafeAction -Description "Start Microsoft Defender service" -ScriptBlock {
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    }

    Invoke-SafeAction -Description "Enable Defender sandboxing" -ScriptBlock {
        [Environment]::SetEnvironmentVariable(
            "MP_FORCE_USE_SANDBOX",
            "1",
            "Machine"
        )
    } -SuggestReboot

    Invoke-SafeAction -Description "Update Defender signatures" -ScriptBlock {
        Update-MpSignature
    }

    Invoke-SafeAction -Description "Configure Defender preferences" -ScriptBlock {
        Set-MpPreference -PUAProtection Enabled
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples
        Set-MpPreference -EnableNetworkProtection Enabled
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableBlockAtFirstSeen $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
        Set-MpPreference -EnableControlledFolderAccess AuditMode
    }

    if ($Profile -eq "Strict") {
        Invoke-SafeAction -Description "Enable Controlled Folder Access" -ScriptBlock {
            Set-MpPreference -EnableControlledFolderAccess Enabled
        }
    }

    Write-Info "Tamper Protection should be managed through Intune or MDE."
}

function Set-DefenderAsrRules {
    Write-Section "Microsoft Defender Attack Surface Reduction rules"

    if (-not (Test-CommandAvailable -Name "Add-MpPreference")) {
        Write-SoftWarning "Defender PowerShell module not available. Skipping ASR."
        return
    }

    $action = if ($Mode -eq "Audit") { "AuditMode" } else { "Enabled" }

    $rules = [ordered]@{
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" =
            "Block Office child process creation"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" =
            "Block Office process injection"
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" =
            "Block Win32 API calls from Office macros"
        "3B576869-A4EC-4529-8536-B80A7769E899" =
            "Block Office executable content"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" =
            "Block obfuscated scripts"
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" =
            "Block executable content from email and webmail"
        "D3E037E1-3EB8-44C8-A917-57927947596D" =
            "Block JS/VBS launching downloaded executables"
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" =
            "Block credential stealing from LSASS"
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" =
            "Block untrusted and unsigned USB processes"
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" =
            "Block Adobe Reader child processes"
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" =
            "Block WMI persistence"
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" =
            "Block PSExec and WMI child process creation"
        "56A863A9-875E-4185-98A7-B882C64B5CE5" =
            "Block abuse of vulnerable signed drivers"
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" =
            "Use advanced ransomware protection"
    }

    if ($Profile -eq "Strict") {
        $rules["01443614-CD74-433A-B99E-2ECDC07BFC25"] =
            "Block executables unless prevalent, aged, or trusted"
        $rules["26190899-1602-49E8-8B27-EB1D0A1CE869"] =
            "Block Office communication app child processes"
    }

    foreach ($rule in $rules.GetEnumerator()) {
        $ruleId = $rule.Key
        $description = $rule.Value

        Invoke-SafeAction -Description "ASR: $description" -ScriptBlock {
            Add-MpPreference `
                -AttackSurfaceReductionRules_Ids $ruleId `
                -AttackSurfaceReductionRules_Actions $action
        }
    }
}

function Set-ExploitProtectionBaseline {
    Write-Section "Exploit protection"

    if (-not (Test-CommandAvailable -Name "Set-ProcessMitigation")) {
        Write-SoftWarning "Set-ProcessMitigation not available. Skipping."
        return
    }

    Invoke-SafeAction -Description "Set system exploit mitigations" -ScriptBlock {
        Set-ProcessMitigation `
            -System `
            -Enable DEP, EmulateAtlThunks, BottomUp, HighEntropy, SEHOP,
            SEHOPTelemetry, TerminateOnError
    } -SuggestReboot

    if ($Profile -eq "Strict") {
        Invoke-SafeAction -Description "Enable stricter exploit mitigations" -ScriptBlock {
            Set-ProcessMitigation `
                -System `
                -Enable CFG, ForceRelocateImages
        } -SuggestReboot
    }
}

function Set-GeneralWindowsHardening {
    Write-Section "General Windows hardening"

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "DisableSmartNameResolution" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "DisableIPSourceRouting" `
        -Value 2

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "EnableICMPRedirect" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        -Name "DisableIPSourceRouting" `
        -Value 2

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "EnableLUA" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "ConsentPromptBehaviorAdmin" `
        -Value 2

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "PromptOnSecureDesktop" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "SafeDllSearchMode" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "ProtectionMode" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
        -Name "SaveZoneInformation" `
        -Value 2

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        -Name "NoDataExecutionPrevention" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        -Name "NoHeapTerminationOnCorruption" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "PreXPSP2ShellProtocolBehavior" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        -Name "DisableWebPnPDownload" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        -Name "DisableHTTPPrinting" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
        -Name "fMinimizeConnections" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" `
        -Name "NoNameReleaseOnDemand" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "EnableSmartScreen" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "ShellSmartScreenLevel" `
        -Value "Block" `
        -Type String

    Invoke-SafeAction -Description "Disable NetBIOS over TCP/IP where enabled" -ScriptBlock {
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
            Where-Object {
                $_.IPEnabled -eq $true -and
                ($_.TcpipNetbiosOptions -eq 0 -or $_.TcpipNetbiosOptions -eq 1)
            } |
            ForEach-Object {
                Invoke-CimMethod `
                    -InputObject $_ `
                    -MethodName SetTcpipNetbios `
                    -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
            }
    }

    Invoke-SafeAction -Description "Disable PowerShell v2" -ScriptBlock {
        Disable-WindowsOptionalFeature `
            -Online `
            -FeatureName MicrosoftWindowsPowerShellV2 `
            -NoRestart

        Disable-WindowsOptionalFeature `
            -Online `
            -FeatureName MicrosoftWindowsPowerShellV2Root `
            -NoRestart
    } -SuggestReboot

    Invoke-SafeAction -Description "Ensure driver integrity checks are enabled" -ScriptBlock {
        bcdedit.exe /set nointegritychecks off | Out-Null
    } -SuggestReboot
}

function Set-CryptoAndAuthHardening {
    Write-Section "Crypto and authentication hardening"

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "SupportedEncryptionTypes" `
        -Value 2147483640

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -Name "SealSecureChannel" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -Name "SignSecureChannel" `
        -Value 1

    if ($Profile -eq "Strict") {
        Set-RegValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LmCompatibilityLevel" `
            -Value 5

        Set-RegValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" `
            -Name "LDAPClientIntegrity" `
            -Value 1
    }
}

function Set-CredentialProtection {
    Write-Section "Credential protection"

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" `
        -Name "AuditLevel" `
        -Value 8

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RunAsPPL" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
        -Name "AllowProtectedCreds" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LimitBlankPasswordUse" `
        -Value 1

    if ($Profile -eq "Strict") {
        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
            -Name "EnableVirtualizationBasedSecurity" `
            -Value 1

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
            -Name "RequirePlatformSecurityFeatures" `
            -Value 1

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
            -Name "LsaCfgFlags" `
            -Value 1

        $Script:State.RebootSuggested = $true
    }
}

function Set-SmbAndRemoteAccessHardening {
    Write-Section "SMB and remote access hardening"

    Invoke-SafeAction -Description "Disable SMBv1" -ScriptBlock {
        Disable-WindowsOptionalFeature `
            -Online `
            -FeatureName SMB1Protocol `
            -NoRestart
    } -SuggestReboot

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SMB1" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
        -Name "Start" `
        -Value 4

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
        -Name "RestrictNullSessAccess" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymousSAM" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymous" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "EveryoneIncludesAnonymous" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictRemoteSAM" `
        -Value "O:BAG:BAD:(A;;RC;;;BA)" `
        -Type String

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "UseMachineId" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" `
        -Name "AllowNullSessionFallback" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "EnableSecuritySignature" `
        -Value 1

    if ($Profile -eq "Strict") {
        Set-RegValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
            -Name "RequireSecuritySignature" `
            -Value 1

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
            -Name "AllowInsecureGuestAuth" `
            -Value 0

        Set-RegValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
            -Name "EnablePlainTextPassword" `
            -Value 0
    }

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fAllowToGetHelp" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fEncryptRPCTraffic" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fDisableCdm" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        -Name "AllowUnencryptedTraffic" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        -Name "AllowDigest" `
        -Value 0

    if ($Profile -eq "Strict") {
        Invoke-SafeAction -Description "Stop and disable WinRM service" -ScriptBlock {
            Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
            Set-Service -Name WinRM -StartupType Disabled
        }
    }

    Set-RegValue `
        -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" `
        -Name "DisableRpcOverTcp" `
        -Value 1

    if ($Profile -eq "Strict") {
        Set-RegValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control" `
            -Name "DisableRemoteScmEndpoints" `
            -Value 1
    }
}

function Set-BrowserHardening {
    Write-Section "Browser hardening"

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "SmartScreenEnabled" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "SmartScreenPuaEnabled" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "BlockThirdPartyCookies" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "PasswordManagerEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "AutofillCreditCardEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "SSLErrorOverrideAllowed" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "SSLVersionMin" `
        -Value "tls1.2" `
        -Type String

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "DNSInterceptionChecksEnabled" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "AdvancedProtectionAllowed" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "AlwaysOpenPdfExternally" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "BlockExternalExtensions" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "PasswordManagerEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "AutofillCreditCardEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "SSLErrorOverrideAllowed" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "SSLVersionMin" `
        -Value "tls1.2" `
        -Type String

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "SitePerProcess" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
        -Name "AudioSandboxEnabled" `
        -Value 1

    if ($Profile -eq "Strict") {
        foreach ($browserPath in @(
                "HKLM:\SOFTWARE\Policies\Google\Chrome",
                "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            )) {
            Set-RegValue `
                -Path $browserPath `
                -Name "AudioCaptureAllowed" `
                -Value 0

            Set-RegValue `
                -Path $browserPath `
                -Name "VideoCaptureAllowed" `
                -Value 0

            Set-RegValue `
                -Path $browserPath `
                -Name "ScreenCaptureAllowed" `
                -Value 0
        }
    }
}

function Set-OfficeHardening {
    Write-Section "Microsoft Office hardening"

    $officeVersions = @("15.0", "16.0")
    $apps = @("Word", "Excel", "PowerPoint")

    foreach ($version in $officeVersions) {
        foreach ($app in $apps) {
            Set-RegValue `
                -Path "HKCU:\Software\Policies\Microsoft\Office\$version\$app\Security" `
                -Name "blockcontentexecutionfrominternet" `
                -Value 1

            Set-RegValue `
                -Path "HKCU:\Software\Policies\Microsoft\Office\$version\$app\Security" `
                -Name "vbawarnings" `
                -Value 4
        }

        Set-RegValue `
            -Path "HKCU:\Software\Policies\Microsoft\Office\$version\Publisher\Security" `
            -Name "vbawarnings" `
            -Value 4

        Set-RegValue `
            -Path "HKCU:\Software\Policies\Microsoft\Office\$version\Outlook\Security" `
            -Name "markinternalasunsafe" `
            -Value 0

        Set-RegValue `
            -Path "HKCU:\Software\Microsoft\Office\$version\Word\Options" `
            -Name "DontUpdateLinks" `
            -Value 1

        Set-RegValue `
            -Path "HKCU:\Software\Microsoft\Office\$version\Word\Options\WordMail" `
            -Name "DontUpdateLinks" `
            -Value 1
    }
}

function Set-FirewallHardening {
    Write-Section "Windows Firewall hardening"

    if (-not (Test-CommandAvailable -Name "Set-NetFirewallProfile")) {
        Write-SoftWarning "NetSecurity module not available. Skipping firewall."
        return
    }

    Invoke-SafeAction -Description "Enable Windows Firewall profiles" -ScriptBlock {
        Set-NetFirewallProfile `
            -Profile Domain, Public, Private `
            -Enabled True

        Set-NetFirewallProfile `
            -Profile Public `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow

        Set-NetFirewallProfile `
            -Profile Domain, Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow

        Set-NetFirewallProfile `
            -Profile Domain, Public, Private `
            -LogAllowed False `
            -LogBlocked True `
            -LogMaxSizeKilobytes 16384 `
            -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    }

    $blockedPrograms = @(
        "$env:SystemRoot\System32\regsvr32.exe",
        "$env:SystemRoot\System32\mshta.exe",
        "$env:SystemRoot\System32\wscript.exe",
        "$env:SystemRoot\System32\cscript.exe",
        "$env:SystemRoot\System32\rundll32.exe",
        "$env:SystemRoot\System32\hh.exe",
        "$env:SystemRoot\System32\PresentationHost.exe"
    )

    foreach ($program in $blockedPrograms) {
        $fileName = [IO.Path]::GetFileName($program)
        $name = "Block outbound $fileName"

        Invoke-SafeAction -Description $name -ScriptBlock {
            if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule `
                    -DisplayName $name `
                    -Direction Outbound `
                    -Program $program `
                    -Action Block `
                    -Profile Any `
                    -Enabled True
            }
        }
    }
}

function Set-PrivacyBaseline {
    Write-Section "Privacy baseline"

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "AllowTelemetry" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "MaxTelemetryAllowed" `
        -Value 1

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" `
        -Name "Location" `
        -Value "Deny" `
        -Type String

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" `
        -Name "BingSearchEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" `
        -Name "AllowSearchToUseLocation" `
        -Value 0

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" `
        -Name "CortanaConsent" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "PublishUserActivities" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" `
        -Name "DisableSettingSync" `
        -Value 2

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" `
        -Name "DisabledByGroupPolicy" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" `
        -Name "AllowGameDVR" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        -Name "DisableWindowsConsumerFeatures" `
        -Value 1

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
        -Name "SystemPaneSuggestionsEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
        -Name "SilentInstalledAppsEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
        -Name "PreInstalledAppsEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
        -Name "OemPreInstalledAppsEnabled" `
        -Value 0

    Set-RegValue `
        -Path "HKCU:\Control Panel\International\User Profile" `
        -Name "HttpAcceptLanguageOptOut" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" `
        -Name "NoToastApplicationNotificationOnLockScreen" `
        -Value 1
}

function Set-LoggingAndAuditPolicy {
    Write-Section "Logging and audit policy"

    Invoke-SafeAction -Description "Increase Windows event log sizes" -ScriptBlock {
        wevtutil.exe sl Security /ms:104857600
        wevtutil.exe sl Application /ms:67108864
        wevtutil.exe sl System /ms:67108864
        wevtutil.exe sl "Windows PowerShell" /ms:67108864
        wevtutil.exe sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864
    }

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "SCENoApplyLegacyAuditPolicy" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        -Name "EnableModuleLogging" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "EnableTranscripting" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "OutputDirectory" `
        -Value "$env:ProgramData\PowerShellTranscripts" `
        -Type String

    Invoke-SafeAction -Description "Configure detailed audit policy" -ScriptBlock {
        auditpol.exe /set /subcategory:"Security Group Management" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Logoff" /success:enable /failure:disable
        auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Account Lockout" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
        auditpol.exe /set /subcategory:"Removable Storage" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"IPsec Driver" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Security State Change" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"System Integrity" /success:enable /failure:enable
    }
}

function Set-DeviceAndRemovableMediaHardening {
    Write-Section "Device and removable media hardening"

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        -Name "NoAutoplayfornonVolume" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoDriveTypeAutoRun" `
        -Value 255

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoAutorun" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" `
        -Name "EnhancedAntiSpoofing" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        -Name "NoLockScreenCamera" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
        -Name "LetAppsActivateWithVoiceAboveLock" `
        -Value 2

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
        -Name "LetAppsActivateWithVoice" `
        -Value 2
}

function Set-UpdateAndLockScreenBaseline {
    Write-Section "Updates and lock screen"

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" `
        -Name "DODownloadMode" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" `
        -Name "DODownloadMode" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "InactivityTimeoutSecs" `
        -Value 900

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
        -Name "ACSettingIndex" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
        -Name "DCSettingIndex" `
        -Value 1
}

function Set-OptionalAppRemoval {
    Write-Section "Optional app removal"

    if ($Profile -ne "Strict") {
        Write-Info "Skipping built-in app removal in Balanced profile."
        return
    }

    $apps = @(
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Messaging",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.OneConnect",
        "Microsoft.People",
        "Microsoft.Print3D",
        "Microsoft.SkypeApp",
        "Microsoft.Wallet",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.YourPhone",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo"
    )

    foreach ($app in $apps) {
        Invoke-SafeAction -Description "Remove AppX package $app" -ScriptBlock {
            Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue |
                Remove-AppxPackage -ErrorAction SilentlyContinue

            Get-AppxProvisionedPackage -Online |
                Where-Object { $_.DisplayName -eq $app } |
                Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
    }
}

function Show-ValidationCommands {
    Write-Section "Validation commands"

    Write-Host "Useful validation commands:"
    Write-Host ""
    Write-Host "  Get-MpPreference"
    Write-Host "  Get-ProcessMitigation -System"
    Write-Host "  auditpol /get /category:*"
    Write-Host "  Get-NetFirewallProfile"
    Write-Host "  Get-NetFirewallRule | Where-Object DisplayName -like '*Block outbound*'"
    Write-Host "  Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
    Write-Host "  Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2"
    Write-Host "  reg query HKLM\SOFTWARE\Policies\Microsoft\Edge"
    Write-Host "  reg query HKLM\SOFTWARE\Policies\Google\Chrome"
    Write-Host ""
    Write-Host "Event logs to review:"
    Write-Host ""
    Write-Host "  Microsoft-Windows-Windows Defender/Operational"
    Write-Host "  Microsoft-Windows-PowerShell/Operational"
    Write-Host "  Security"
    Write-Host "  System"
}

function Show-RunSummary {
    Write-Section "Summary"

    $endedAt = Get-Date
    $duration = New-TimeSpan -Start $Script:State.StartedAt -End $endedAt

    Write-Host "Started:          $($Script:State.StartedAt)"
    Write-Host "Ended:            $endedAt"
    Write-Host "Duration:         $($duration.ToString())"
    Write-Host "Mode:             $($Script:State.Mode)"
    Write-Host "Profile:          $($Script:State.Profile)"
    Write-Host "Changes:          $($Script:State.Changes)"
    Write-Host "Audit findings:   $($Script:State.AuditFindings)"
    Write-Host "Warnings:         $($Script:State.Warnings)"
    Write-Host "Errors:           $($Script:State.Errors)"
    Write-Host "Reboot suggested: $($Script:State.RebootSuggested)"
    Write-Host ""

    if ($Script:State.RebootSuggested) {
        Write-SoftWarning "A reboot is recommended to complete hardening."
    }

    Write-Host "Recommended next steps:"
    Write-Host "  1. Reboot if suggested."
    Write-Host "  2. Review the transcript log."
    Write-Host "  3. Review Defender ASR events."
    Write-Host "  4. Validate with CIS, STIG, or Microsoft baselines."
    Write-Host "  5. Convert stable settings to Intune or Group Policy."
}

try {
    Initialize-HardeningRun
    Backup-RegistryKeys

    Enable-DefenderBaseline
    Set-DefenderAsrRules
    Set-ExploitProtectionBaseline
    Set-GeneralWindowsHardening
    Set-CryptoAndAuthHardening
    Set-CredentialProtection
    Set-SmbAndRemoteAccessHardening
    Set-BrowserHardening
    Set-OfficeHardening
    Set-FirewallHardening
    Set-PrivacyBaseline
    Set-LoggingAndAuditPolicy
    Set-DeviceAndRemovableMediaHardening
    Set-UpdateAndLockScreenBaseline
    Set-OptionalAppRemoval

    Show-ValidationCommands
    Show-RunSummary
} catch {
    Write-SoftError "Fatal error: $($_.Exception.Message)"
    throw
} finally {
    if (-not $NoTranscript) {
        try {
            Stop-Transcript | Out-Null
        } catch {
            # Transcript may not have started.
        }
    }
}
