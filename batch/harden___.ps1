#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Modern Windows 10/11 client hardening baseline.

.DESCRIPTION
  Applies a compatibility-conscious hardening baseline for Windows 10/11.
  Supports Audit and Enforce modes and Balanced/Strict profiles.

.NOTES
  Test in a lab before production use.
  Prefer Intune, Group Policy, or Security Baselines for fleet deployment.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("Audit", "Enforce")]
    [string]$Mode = "Audit",

    [ValidateSet("Balanced", "Strict")]
    [string]$Profile = "Balanced",

    [string]$LogPath = "$env:ProgramData\WindowsHardening\hardening.log",

    [switch]$SkipBackup
)

$ErrorActionPreference = "Continue"

$State = @{
    Changes = 0
    Errors  = 0
}

function Initialize-Hardening {
    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    Start-Transcript -Path $LogPath -Append | Out-Null

    Write-Host "Windows client hardening"
    Write-Host "Mode: $Mode"
    Write-Host "Profile: $Profile"
    Write-Host "Log: $LogPath"

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host "OS: $($os.Caption) $($os.Version)"
}

function Backup-RegistryKeys {
    if ($SkipBackup) {
        Write-Host "Skipping registry backup."
        return
    }

    $backupRoot = "$env:ProgramData\WindowsHardening\Backups"
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = Join-Path $backupRoot $stamp

    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

    $keys = @(
        "HKLM\SOFTWARE\Policies",
        "HKCU\SOFTWARE\Policies",
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer",
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
    )

    foreach ($key in $keys) {
        $file = Join-Path $backupDir (($key -replace "\\", "_") + ".reg")
        Write-Host "Backing up $key to $file"
        & reg.exe export $key $file /y | Out-Null
    }
}

function Set-RegValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object]$Value,

        [ValidateSet("String", "DWord", "QWord", "MultiString", "ExpandString")]
        [string]$Type = "DWord"
    )

    try {
        if ($Mode -eq "Audit") {
            $current = $null
            if (Test-Path $Path) {
                $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            }

            Write-Host "[AUDIT] $Path\$Name current=[$current] desired=[$Value]"
            return
        }

        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }

            New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value $Value `
                -PropertyType $Type `
                -Force | Out-Null

            Write-Host "[SET] $Path\$Name = $Value"
            $State.Changes++
        }
    } catch {
        Write-Warning "Failed setting $Path\$Name : $($_.Exception.Message)"
        $State.Errors++
    }
}

function Invoke-CommandSafe {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [string]$Description
    )

    try {
        if ($Mode -eq "Audit") {
            Write-Host "[AUDIT] Would run: $Description"
            return
        }

        Write-Host "[RUN] $Description"
        & $ScriptBlock
        $State.Changes++
    } catch {
        Write-Warning "Failed: $Description : $($_.Exception.Message)"
        $State.Errors++
    }
}

function Enable-DefenderBaseline {
    Write-Host "`n== Microsoft Defender baseline =="

    Invoke-CommandSafe -Description "Start Microsoft Defender service" -ScriptBlock {
        Start-Service WinDefend -ErrorAction SilentlyContinue
    }

    Invoke-CommandSafe -Description "Enable Defender sandboxing" -ScriptBlock {
        [Environment]::SetEnvironmentVariable(
            "MP_FORCE_USE_SANDBOX",
            "1",
            "Machine"
        )
    }

    Invoke-CommandSafe -Description "Update Defender signatures" -ScriptBlock {
        Update-MpSignature
    }

    Invoke-CommandSafe -Description "Configure Defender preferences" -ScriptBlock {
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
        Invoke-CommandSafe -Description "Enable Controlled Folder Access" -ScriptBlock {
            Set-MpPreference -EnableControlledFolderAccess Enabled
        }
    }

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" `
        -Name "TamperProtection" `
        -Value 5 `
        -Type DWord

    Write-Host "Note: Tamper Protection is best managed through Intune/MDE."
}

function Set-DefenderAsrRules {
    Write-Host "`n== Attack Surface Reduction rules =="

    $action = if ($Mode -eq "Audit") { "AuditMode" } else { "Enabled" }

    $rules = [ordered]@{
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office child process creation"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office process injection"
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office executable content"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block obfuscated scripts"
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email/webmail"
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS/VBS launching downloaded executables"
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from LSASS"
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted USB processes"
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader child processes"
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block WMI persistence"
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block PSExec/WMI child process creation"
        "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of vulnerable signed drivers"
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced ransomware protection"
    }

    if ($Profile -eq "Strict") {
        $rules["01443614-CD74-433A-B99E-2ECDC07BFC25"] =
            "Block executables unless prevalent, aged, or trusted"
        $rules["26190899-1602-49E8-8B27-EB1D0A1CE869"] =
            "Block Office communication app child processes"
    }

    foreach ($rule in $rules.GetEnumerator()) {
        Invoke-CommandSafe -Description "ASR: $($rule.Value)" -ScriptBlock {
            Add-MpPreference `
                -AttackSurfaceReductionRules_Ids $rule.Key `
                -AttackSurfaceReductionRules_Actions $action
        }
    }
}

function Set-ExploitProtectionBaseline {
    Write-Host "`n== Exploit protection =="

    Invoke-CommandSafe -Description "Set system exploit mitigations" -ScriptBlock {
        Set-ProcessMitigation `
            -System `
            -Enable DEP, EmulateAtlThunks, BottomUp, HighEntropy, SEHOP,
            SEHOPTelemetry, TerminateOnError
    }

    if ($Profile -eq "Strict") {
        Invoke-CommandSafe -Description "Enable stricter exploit mitigations" -ScriptBlock {
            Set-ProcessMitigation `
                -System `
                -Enable CFG, ForceRelocateImages
        }
    }
}

function Set-GeneralWindowsHardening {
    Write-Host "`n== General Windows hardening =="

    # LLMNR and smart multi-homed name resolution
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "DisableSmartNameResolution" `
        -Value 1

    # TCP/IP hardening
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

    # UAC
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

    # DLL search order
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "SafeDllSearchMode" `
        -Value 1

    # Mark-of-the-Web preservation
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
        -Name "SaveZoneInformation" `
        -Value 2

    # SmartScreen
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "EnableSmartScreen" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "ShellSmartScreenLevel" `
        -Value "Block" `
        -Type String

    # Disable PowerShell v2
    Invoke-CommandSafe -Description "Disable PowerShell v2" -ScriptBlock {
        Disable-WindowsOptionalFeature `
            -Online `
            -FeatureName MicrosoftWindowsPowerShellV2 `
            -NoRestart

        Disable-WindowsOptionalFeature `
            -Online `
            -FeatureName MicrosoftWindowsPowerShellV2Root `
            -NoRestart
    }

    # Driver signing
    Invoke-CommandSafe -Description "Ensure driver integrity checks are enabled" -ScriptBlock {
        bcdedit.exe /set nointegritychecks off
    }
}

function Set-CredentialProtection {
    Write-Host "`n== Credential protection =="

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
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LimitBlankPasswordUse" `
        -Value 1

    if ($Profile -eq "Strict") {
        Set-RegValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LmCompatibilityLevel" `
            -Value 5

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
    }
}

function Set-SmbAndRemoteAccessHardening {
    Write-Host "`n== SMB and remote access hardening =="

    Invoke-CommandSafe -Description "Disable SMBv1" -ScriptBlock {
        Disable-WindowsOptionalFeature `
            -Online `
            -FeatureName SMB1Protocol `
            -NoRestart
    }

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

    # Remote Assistance
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fAllowToGetHelp" `
        -Value 0

    # RDP hardening, does not enable RDP
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fEncryptRPCTraffic" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fDisableCdm" `
        -Value 1

    # WinRM
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        -Name "AllowUnencryptedTraffic" `
        -Value 0

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        -Name "AllowDigest" `
        -Value 0

    if ($Profile -eq "Strict") {
        Invoke-CommandSafe -Description "Stop WinRM service" -ScriptBlock {
            Stop-Service WinRM -Force -ErrorAction SilentlyContinue
            Set-Service WinRM -StartupType Disabled
        }
    }
}

function Set-BrowserHardening {
    Write-Host "`n== Browser hardening =="

    # Microsoft Edge Chromium
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

    # Google Chrome
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

    if ($Profile -eq "Strict") {
        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
            -Name "AudioCaptureAllowed" `
            -Value 0

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
            -Name "VideoCaptureAllowed" `
            -Value 0

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" `
            -Name "ScreenCaptureAllowed" `
            -Value 0

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
            -Name "AudioCaptureAllowed" `
            -Value 0

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
            -Name "VideoCaptureAllowed" `
            -Value 0

        Set-RegValue `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
            -Name "ScreenCaptureAllowed" `
            -Value 0
    }
}

function Set-OfficeHardening {
    Write-Host "`n== Microsoft Office hardening =="

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
            -Path "HKCU:\Software\Policies\Microsoft\Office\$version\Word\Options" `
            -Name "DontUpdateLinks" `
            -Value 1
    }

    # Block macros from running in Office files from the Internet
    foreach ($version in $officeVersions) {
        foreach ($app in $apps) {
            Set-RegValue `
                -Path "HKCU:\Software\Policies\Microsoft\Office\$version\$app\Security" `
                -Name "blockcontentexecutionfrominternet" `
                -Value 1
        }
    }

    # Outlook attachment hardening
    foreach ($version in $officeVersions) {
        Set-RegValue `
            -Path "HKCU:\Software\Policies\Microsoft\Office\$version\Outlook\Security" `
            -Name "markinternalasunsafe" `
            -Value 0
    }
}

function Set-FirewallHardening {
    Write-Host "`n== Windows Firewall hardening =="

    Invoke-CommandSafe -Description "Enable Windows Firewall profiles" -ScriptBlock {
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
        $name = "Block outbound $([IO.Path]::GetFileName($program))"

        Invoke-CommandSafe -Description $name -ScriptBlock {
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
    Write-Host "`n== Privacy baseline =="

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "AllowTelemetry" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" `
        -Value 1

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
}

function Set-LoggingAndAuditPolicy {
    Write-Host "`n== Logging and audit policy =="

    Invoke-CommandSafe -Description "Increase event log sizes" -ScriptBlock {
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
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" `
        -Value 1

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        -Name "EnableModuleLogging" `
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

    Invoke-CommandSafe -Description "Set audit policy" -ScriptBlock {
        auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Logoff" /success:enable /failure:disable
        auditpol.exe /set /subcategory:"Account Lockout" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Security Group Management" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Removable Storage" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"System Integrity" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Security State Change" /success:enable /failure:enable
        auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
    }
}

function Set-DeviceAndRemovableMediaHardening {
    Write-Host "`n== Device and removable media hardening =="

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
}

function Set-UpdateAndLockScreenBaseline {
    Write-Host "`n== Updates and lock screen =="

    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" `
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

function Show-PostRunNotes {
    Write-Host "`n== Summary =="
    Write-Host "Changes attempted: $($State.Changes)"
    Write-Host "Errors: $($State.Errors)"
    Write-Host ""
    Write-Host "Recommended next steps:"
    Write-Host "1. Reboot the system."
    Write-Host "2. Review Defender ASR events:"
    Write-Host "   Event Viewer > Applications and Services Logs >"
    Write-Host "   Microsoft > Windows > Windows Defender > Operational"
    Write-Host "3. Validate with CIS-CAT, Microsoft Security Compliance Toolkit,"
    Write-Host "   Intune security baselines, or Defender Vulnerability Management."
    Write-Host "4. For production, manage these settings using Intune/GPO."
}

try {
    Initialize-Hardening
    Backup-RegistryKeys

    Enable-DefenderBaseline
    Set-DefenderAsrRules
    Set-ExploitProtectionBaseline
    Set-GeneralWindowsHardening
    Set-CredentialProtection
    Set-SmbAndRemoteAccessHardening
    Set-BrowserHardening
    Set-OfficeHardening
    Set-FirewallHardening
    Set-PrivacyBaseline
    Set-LoggingAndAuditPolicy
    Set-DeviceAndRemovableMediaHardening
    Set-UpdateAndLockScreenBaseline

    Show-PostRunNotes
} finally {
    Stop-Transcript | Out-Null
}
