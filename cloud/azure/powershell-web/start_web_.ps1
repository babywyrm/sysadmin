<#
.SYNOPSIS
    Lightweight PowerShell webserver using System.Net.HttpListener.
    No IIS required.

.DESCRIPTION
    Supports:
    - PowerShell command execution (POST form)
    - Script upload and execution
    - File upload / download
    - Directory listing
    - Static file serving
    - Server beep (datacenter locate)
    - Request logging
    - Graceful stop

.PARAMETER BindingUrl
    URL to bind to. Default: http://localhost:8080/
    Use http://+:8080/ for all interfaces (requires admin).

.PARAMETER BasePath
    Root directory for static content. Default: current directory.

.EXAMPLE
    .\Start-Webserver.ps1
    .\Start-Webserver.ps1 -BindingUrl "http://+:8080/" -BasePath "C:\www"

.NOTES
    Author:  Markus Scholtes (original), modernized 2026
    Version: 2.0
    WARNING: No authentication. Do not expose publicly.
#>
[CmdletBinding()]
param(
    [string]$BindingUrl = "http://localhost:8080/",
    [string]$BasePath   = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------
# MIME type map
# ---------------------------------------------------------------
$MimeTypes = @{
    '.html' = 'text/html'
    '.htm'  = 'text/html'
    '.css'  = 'text/css'
    '.js'   = 'application/javascript'
    '.json' = 'application/json'
    '.xml'  = 'application/xml'
    '.png'  = 'image/png'
    '.jpg'  = 'image/jpeg'
    '.jpeg' = 'image/jpeg'
    '.gif'  = 'image/gif'
    '.svg'  = 'image/svg+xml'
    '.ico'  = 'image/x-icon'
    '.pdf'  = 'application/pdf'
    '.zip'  = 'application/zip'
    '.txt'  = 'text/plain'
    '.ps1'  = 'text/plain'
    '.log'  = 'text/plain'
}

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
function Get-MimeType([string]$FilePath) {
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    if ($MimeTypes.ContainsKey($ext)) { return $MimeTypes[$ext] }
    return 'application/octet-stream'
}

function Write-Log([string]$Message) {
    $entry = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $script:RequestLog += $entry
    Write-Verbose $entry
}

function Send-Response {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Body        = '',
        [int]$StatusCode     = 200,
        [string]$ContentType = 'text/html; charset=utf-8',
        [byte[]]$RawBytes    = $null
    )
    $Response.StatusCode  = $StatusCode
    $Response.ContentType = $ContentType

    if ($RawBytes) {
        $Response.ContentLength64 = $RawBytes.Length
        $Response.OutputStream.Write($RawBytes, 0, $RawBytes.Length)
    } else {
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $Response.ContentLength64 = $buffer.Length
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    $Response.OutputStream.Close()
}

function Get-HtmlPage([string]$Title, [string]$Body) {
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        body { font-family: Consolas, monospace; background: #1e1e1e; color: #d4d4d4; padding: 2rem; }
        h1, h2 { color: #569cd6; }
        a { color: #4ec9b0; }
        pre { background: #252526; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        input, textarea { background: #3c3c3c; color: #d4d4d4; border: 1px solid #555; padding: 0.4rem; }
        input[type=submit], button { background: #0e639c; color: white; border: none;
            padding: 0.5rem 1rem; cursor: pointer; border-radius: 3px; }
        input[type=submit]:hover { background: #1177bb; }
        table { border-collapse: collapse; width: 100%; }
        td, th { padding: 0.4rem 0.8rem; border: 1px solid #444; text-align: left; }
        th { background: #2d2d2d; }
        nav a { margin-right: 1rem; }
    </style>
</head>
<body>
    <h1>PS Webserver</h1>
    <nav>
        <a href="/">Home</a>
        <a href="/cmd">Execute</a>
        <a href="/upload">Upload</a>
        <a href="/download">Download</a>
        <a href="/log">Log</a>
        <a href="/time">Time</a>
        <a href="/beep">Beep</a>
        <a href="/stop">Stop</a>
    </nav>
    <hr>
    $Body
</body>
</html>
"@
}

function Get-DirectoryListing([string]$DirPath, [string]$UrlPath) {
    $rows = Get-ChildItem -LiteralPath $DirPath |
        Sort-Object -Property @{E={$_.PSIsContainer}; Descending=$true}, Name |
        ForEach-Object {
            $name  = if ($_.PSIsContainer) { "$($_.Name)/" } else { $_.Name }
            $href  = "$UrlPath/$($_.Name)".TrimStart('/')
            $size  = if ($_.PSIsContainer) { '-' } else {
                "{0:N0} KB" -f ($_.Length / 1KB)
            }
            $mtime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
            "<tr><td><a href='/$href'>$name</a></td><td>$size</td><td>$mtime</td></tr>"
        }

    $tableBody = $rows -join "`n"
    return Get-HtmlPage "Index of $UrlPath" @"
<h2>Index of $UrlPath</h2>
<table>
    <tr><th>Name</th><th>Size</th><th>Modified</th></tr>
    $tableBody
</table>
"@
}

# ---------------------------------------------------------------
# Startup
# ---------------------------------------------------------------
$script:RequestLog = @()
$script:StartTime  = Get-Date
$BasePath          = (Resolve-Path $BasePath).Path

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($BindingUrl)

try {
    $listener.Start()
} catch {
    Write-Error "Failed to start listener on $BindingUrl. Try running as Administrator for non-localhost bindings."
    exit 1
}

Write-Host "PS Webserver started on $BindingUrl" -ForegroundColor Green
Write-Host "Base path : $BasePath"               -ForegroundColor Cyan
Write-Host "Press Ctrl+C or browse to /stop to shut down.`n"

# ---------------------------------------------------------------
# Request loop
# ---------------------------------------------------------------
while ($listener.IsListening) {

    $context  = $listener.GetContext()
    $request  = $context.Request
    $response = $context.Response
    $url      = $request.Url
    $method   = $request.HttpMethod
    $rawUrl   = $url.AbsolutePath.TrimEnd('/')

    Write-Log "$method $rawUrl from $($request.RemoteEndPoint)"

    # -----------------------------------------------------------
    switch -Regex ($rawUrl) {

        # ---- Stop ----
        '^/stop$' {
            Send-Response $response -Body (Get-HtmlPage "Stopped" "<h2>Server stopping...</h2>")
            Write-Host "Stop requested. Shutting down." -ForegroundColor Yellow
            $listener.Stop()
            break
        }

        # ---- Beep ----
        '^/beep$' {
            [System.Console]::Beep(1000, 500)
            Send-Response $response -Body (Get-HtmlPage "Beep" "<h2>Beeped.</h2>")
            break
        }

        # ---- Time ----
        '^/time$' {
            $body = @"
<h2>Server Time</h2>
<pre>
Start Time   : $($script:StartTime)
Current Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Uptime       : $((New-TimeSpan -Start $script:StartTime -End (Get-Date)).ToString('hh\:mm\:ss'))
</pre>
"@
            Send-Response $response -Body (Get-HtmlPage "Time" $body)
            break
        }

        # ---- Request Log ----
        '^/log$' {
            $entries = ($script:RequestLog | ForEach-Object {
                [System.Web.HttpUtility]::HtmlEncode($_)
            }) -join "`n"
            Send-Response $response -Body (Get-HtmlPage "Log" "<h2>Request Log</h2><pre>$entries</pre>")
            break
        }

        # ---- Command Execution ----
        '^/cmd$' {
            $output = ''
            if ($method -eq 'POST') {
                $reader  = New-Object System.IO.StreamReader($request.InputStream)
                $rawBody = $reader.ReadToEnd()
                $params  = [System.Web.HttpUtility]::ParseQueryString($rawBody)
                $cmd     = $params['cmd']
                if ($cmd) {
                    try {
                        $output = Invoke-Expression $cmd 2>&1 | Out-String
                        Write-Log "CMD executed: $cmd"
                    } catch {
                        $output = "Error: $_"
                    }
                }
            }
            $encodedOutput = [System.Web.HttpUtility]::HtmlEncode($output)
            $body = @"
<h2>Execute PowerShell</h2>
<form method='POST' action='/cmd'>
    <textarea name='cmd' rows='4' cols='80' placeholder='Enter PowerShell command...'></textarea><br><br>
    <input type='submit' value='Run'>
</form>
$(if ($output) { "<h3>Output:</h3><pre>$encodedOutput</pre>" })
"@
            Send-Response $response -Body (Get-HtmlPage "Execute" $body)
            break
        }

        # ---- Script Upload + Execute ----
        '^/script$' {
            $output = ''
            if ($method -eq 'POST') {
                try {
                    $tempFile = [System.IO.Path]::GetTempFileName() + ".ps1"
                    $buffer   = New-Object byte[] $request.ContentLength64
                    [void]$request.InputStream.Read($buffer, 0, $buffer.Length)
                    [System.IO.File]::WriteAllBytes($tempFile, $buffer)
                    $output = & $tempFile 2>&1 | Out-String
                    Remove-Item $tempFile -Force
                    Write-Log "Script executed, $($buffer.Length) bytes"
                } catch {
                    $output = "Error: $_"
                }
            }
            $encodedOutput = [System.Web.HttpUtility]::HtmlEncode($output)
            $body = @"
<h2>Upload and Execute Script</h2>
<form method='POST' action='/script' enctype='application/octet-stream'>
    <input type='file' name='script' accept='.ps1'><br><br>
    <input type='submit' value='Upload and Run'>
</form>
$(if ($output) { "<h3>Output:</h3><pre>$encodedOutput</pre>" })
"@
            Send-Response $response -Body (Get-HtmlPage "Script" $body)
            break
        }

        # ---- File Upload ----
        '^/upload$' {
            $message = ''
            if ($method -eq 'POST') {
                try {
                    $filename = $request.Headers['X-Filename']
                    if (-not $filename) {
                        $filename = "upload_$(Get-Date -Format 'yyyyMMdd_HHmmss').bin"
                    }
                    $filename = [System.IO.Path]::GetFileName($filename)
                    $destPath = Join-Path $BasePath $filename
                    $buffer   = New-Object byte[] $request.ContentLength64
                    [void]$request.InputStream.Read($buffer, 0, $buffer.Length)
                    [System.IO.File]::WriteAllBytes($destPath, $buffer)
                    $message = "Uploaded: $filename ($($buffer.Length) bytes)"
                    Write-Log "File uploaded: $filename"
                } catch {
                    $message = "Upload failed: $_"
                }
            }
            $body = @"
<h2>Upload File</h2>
<p>Send a POST request with file bytes in body and <code>X-Filename</code> header.<br>
Or use the form below (small files only):</p>
<form method='POST' action='/upload' enctype='application/octet-stream'>
    <input type='file' id='f' name='file'><br><br>
    <input type='submit' value='Upload'>
</form>
$(if ($message) { "<p>$message</p>" })
<h3>PowerShell upload example:</h3>
<pre>
`$bytes = [System.IO.File]::ReadAllBytes('C:\file.txt')
Invoke-RestMethod -Uri '${BindingUrl}upload' ``
    -Method POST ``
    -Body `$bytes ``
    -Headers @{ 'X-Filename' = 'file.txt' }
</pre>
"@
            Send-Response $response -Body (Get-HtmlPage "Upload" $body)
            break
        }

        # ---- File Download ----
        '^/download$' {
            if ($method -eq 'POST') {
                $reader   = New-Object System.IO.StreamReader($request.InputStream)
                $rawBody  = $reader.ReadToEnd()
                $params   = [System.Web.HttpUtility]::ParseQueryString($rawBody)
                $filename = $params['filename']
                if ($filename) {
                    $filePath = Join-Path $BasePath ([System.IO.Path]::GetFileName($filename))
                    if (Test-Path $filePath -PathType Leaf) {
                        $bytes = [System.IO.File]::ReadAllBytes($filePath)
                        $response.Headers.Add(
                            "Content-Disposition",
                            "attachment; filename=`"$([System.IO.Path]::GetFileName($filePath))`""
                        )
                        Send-Response $response -RawBytes $bytes -ContentType (Get-MimeType $filePath)
                        Write-Log "File downloaded: $filename"
                        break
                    } else {
                        Send-Response $response -StatusCode 404 -Body (
                            Get-HtmlPage "Not Found" "<h2>File not found: $filename</h2>"
                        )
                        break
                    }
                }
            }
            $body = @"
<h2>Download File</h2>
<form method='POST' action='/download'>
    <input type='text' name='filename' placeholder='filename.txt' size='40'>
    <input type='submit' value='Download'>
</form>
<h3>PowerShell download example:</h3>
<pre>
Invoke-RestMethod -Uri '${BindingUrl}download' ``
    -Method POST ``
    -Body 'filename=file.txt' ``
    -OutFile 'C:\downloaded.txt'
</pre>
"@
            Send-Response $response -Body (Get-HtmlPage "Download" $body)
            break
        }

        # ---- Home ----
        '^/?$' {
            $body = @"
<h2>Available Endpoints</h2>
<table>
    <tr><th>Path</th><th>Method</th><th>Description</th></tr>
    <tr><td><a href='/cmd'>/cmd</a></td><td>GET/POST</td><td>Execute PowerShell commands</td></tr>
    <tr><td><a href='/script'>/script</a></td><td>GET/POST</td><td>Upload and execute a .ps1 script</td></tr>
    <tr><td><a href='/upload'>/upload</a></td><td>GET/POST</td><td>Upload a file to the server</td></tr>
    <tr><td><a href='/download'>/download</a></td><td>GET/POST</td><td>Download a file from the server</td></tr>
    <tr><td><a href='/log'>/log</a></td><td>GET</td><td>View request log</td></tr>
    <tr><td><a href='/time'>/time</a></td><td>GET</td><td>Server start time and uptime</td></tr>
    <tr><td><a href='/beep'>/beep</a></td><td>GET</td><td>Beep the server speaker</td></tr>
    <tr><td><a href='/stop'>/stop</a></td><td>GET</td><td>Stop the webserver</td></tr>
    <tr><td>/&lt;path&gt;</td><td>GET</td><td>Static file serving and directory listing</td></tr>
</table>
"@
            Send-Response $response -Body (Get-HtmlPage "PS Webserver" $body)
            break
        }

        # ---- Static Files + Directory Listing ----
        default {
            $relPath  = $rawUrl.TrimStart('/')
            $fullPath = Join-Path $BasePath $relPath

            # Block path traversal
            if (-not $fullPath.StartsWith($BasePath)) {
                Send-Response $response -StatusCode 403 -Body (
                    Get-HtmlPage "Forbidden" "<h2>403 Forbidden</h2>"
                )
                break
            }

            if (Test-Path $fullPath -PathType Container) {
                $index = @('index.html','index.htm','default.html','default.htm') |
                    ForEach-Object { Join-Path $fullPath $_ } |
                    Where-Object { Test-Path $_ -PathType Leaf } |
                    Select-Object -First 1

                if ($index) {
                    $bytes = [System.IO.File]::ReadAllBytes($index)
                    Send-Response $response -RawBytes $bytes -ContentType 'text/html; charset=utf-8'
                } else {
                    Send-Response $response -Body (Get-DirectoryListing $fullPath "/$relPath")
                }
            } elseif (Test-Path $fullPath -PathType Leaf) {
                $bytes = [System.IO.File]::ReadAllBytes($fullPath)
                $response.Headers.Add("Cache-Control", "max-age=3600")
                Send-Response $response -RawBytes $bytes -ContentType (Get-MimeType $fullPath)
            } else {
                Send-Response $response -StatusCode 404 -Body (
                    Get-HtmlPage "Not Found" "<h2>404 - Not Found</h2><p>$rawUrl</p>"
                )
            }
            break
        }
    }
}

$listener.Close()
Write-Host "Webserver stopped." -ForegroundColor Red
