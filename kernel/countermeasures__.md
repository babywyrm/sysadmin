# Detecting and Countering Malicious Kernel Modules

## Technical Detection & Countermeasures Guide

# What is it?

This guide provides specific technical approaches to detect and counter the malicious kernel modules described in the previous document.

## Core Detection Techniques

### 1. Syscall Table Integrity Verification

```bash
# Create a baseline of the syscall table
sudo cat /proc/kallsyms | grep sys_call_table > syscall_baseline.txt

# Compare current state with baseline
diff <(sudo cat /proc/kallsyms | grep sys_call_table) syscall_baseline.txt

# Alternatively, use kprobe to detect syscall hooks
echo 'probe kernel.function("sys_*") {printf("%s was called\n", probefunc)}' > detect_hooks.stp
stap detect_hooks.stp
```

### 2. Hidden Module Detection

```bash
# Compare modules visible to lsmod vs. those in /proc/modules
comm -13 <(lsmod | awk '{print $1}' | grep -v Module | sort) <(cat /proc/modules | awk '{print $1}' | sort)

# Check for modules that hide from /proc/modules using memory scanning
sudo grep -a -A 10 -B 10 "module_layout" /dev/mem 2>/dev/null | strings

# Search for unexpected .ko files
find /lib/modules/$(uname -r) -name "*.ko" | xargs modinfo | grep -i "description\|filename" | sort
```

### 3. Process/File Hiding Detection

```bash
# Compare process counts from different sources
diff <(ps aux | wc -l) <(ls /proc | grep -E '^[0-9]+$' | wc -l)

# Find hidden files with directory entry inconsistencies
sudo find / -type d -exec ls -lA {} \; | wc -l
sudo find / -type d -exec find {} -maxdepth 1 \; | wc -l

# Look for DKOM (Direct Kernel Object Manipulation) signs
sudo insmod unhide-linux26.ko  # Tool to detect process hiding
```

### 4. Network Activity Monitoring

```bash
# Compare netstat outputs with socket findings
diff <(netstat -tuln | awk '{print $4}') <(cat /proc/net/tcp | awk '{print $2}' | sed 's/:/ /g' | awk '{printf("0.0.0.0:%d\n", "0x" $2)}')

# Detect hidden connections with ss vs netstat
diff <(ss -anp | grep LISTEN) <(netstat -tlnp)

# Monitor for unexpected outbound connections
sudo tcpdump -i any -n 'not port 80 and not port 443 and not port 53'
```

## Module-Specific Detection & Countermeasures

### Diamorphine

**Detection:**
```bash
# Check for hidden processes by sending signal 31
for pid in $(ps -ef | awk '{print $2}'); do
    kill -31 $pid 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "PID $pid responded to signal 31 (possible diamorphine indicator)"
    fi
done

# Check for the diamorphine-specific /proc handling
strace -e open ls /proc 2>&1 | grep ENOENT
```

**Countermeasures:**
```bash
# Block module loading capability after system initialization
echo "kernel.modules_disabled=1" > /etc/sysctl.d/90-disable-modules.conf
sysctl -p /etc/sysctl.d/90-disable-modules.conf

# Monitor module unloading calls as diamorphine hides after loading
auditctl -a always,exit -F arch=b64 -S delete_module -k module_removal
```

### Suterusu

**Detection:**
```bash
# Look for its characteristic /dev entries
find /dev -type c -not -exec ls -la {} \; 2>/dev/null

# Check for its common procfs hiding technique
python3 -c "
import os
visible_procs = set([int(p) for p in os.listdir('/proc') if p.isdigit()])
running_procs = set([int(p.split()[0]) for p in os.popen('ps -e -o pid').read().splitlines()[1:]])
print(f'Hidden PIDs: {running_procs - visible_procs}')
"
```

**Countermeasures:**
```bash
# Detect and prevent typical suterusu syscall hooks
cat > /etc/modprobe.d/blacklist-suterusu.conf << EOF
blacklist suterusu
install suterusu /bin/false
EOF

# Use kernel ftrace to monitor suspicious function calls
echo function_graph > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/function_graph/recursion
```

### Reptile

**Detection:**
```bash
# Monitor for its specific backdoor network signatures
tcpdump -i any port 4455

# Look for its camouflaged files in the kernel modules directory
find /lib/modules/$(uname -r) -type f -exec strings {} \; | grep -i "reptile\|reverse shell"
```

**Countermeasures:**
```bash
# Block Reptile's default port
iptables -A INPUT -p tcp --dport 4455 -j DROP
iptables -A OUTPUT -p tcp --dport 4455 -j DROP

# Monitor suspicious proc file operations
auditctl -w /proc/kallsyms -p rw -k kallsyms_access
```

### KBeast

**Detection:**
```bash
# Look for KBeast's characteristic hooks
cat /sys/kernel/debug/tracing/available_filter_functions | grep -E 'tcp_|udp_|icmp_'
echo 'tcp_* udp_* icmp_*' > /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer
cat /sys/kernel/debug/tracing/trace_pipe

# Check for KBeast's configuration files
find / -type f -name ".addr" -o -name ".vers" -o -name ".pid" 2>/dev/null
```

**Countermeasures:**
```bash
# Implement kernel control flow integrity monitoring
sudo grub-mkconfig -o /boot/grub/grub.cfg

# Implement port knocking detection
iptables -A INPUT -m recent --name portscan --update --seconds 300 --hitcount 4 -j LOG --log-prefix "POSSIBLE PORT KNOCK: "
```

### Azazel

**Detection:**
```bash
# Look for library preloading indicators
grep -l "azazel" /etc/ld.so.preload 2>/dev/null
find /lib* /usr/lib* -type f -name "*.so*" -exec strings {} \; | grep -i "azazel"

# Check for processes with unusual library injections
for pid in $(ps -ef | awk '{print $2}'); do
    grep -l "azazel" /proc/$pid/maps 2>/dev/null && echo "Found in PID $pid"
done
```

**Countermeasures:**
```bash
# Implement library load monitoring
auditctl -a always,exit -F arch=b64 -S mmap -S mprotect -F key=memory_map

# Use LD_AUDIT to detect library injections
export LD_AUDIT=/path/to/libaudit.so
```

## Advanced Detection Methods

### 1. Kernel Memory Analysis with Volatility

```bash
# Create memory dump
sudo dd if=/dev/mem of=memory_dump.bin bs=1M count=1024

# Analyze with Volatility
volatility -f memory_dump.bin --profile=LinuxUbuntu1804x64 linux_check_syscall
volatility -f memory_dump.bin --profile=LinuxUbuntu1804x64 linux_check_modules
volatility -f memory_dump.bin --profile=LinuxUbuntu1804x64 linux_hidden_modules
```

### 2. LKRG (Linux Kernel Runtime Guard) Implementation

```bash
# Install LKRG for runtime integrity monitoring
git clone https://github.com/lkrg-org/lkrg.git
cd lkrg
make
sudo insmod output/lkrg.ko

# Configure LKRG
echo "options lkrg log_level=3" > /etc/modprobe.d/lkrg.conf
```

### 3. eBPF-Based Detection Programs

```c
// Example eBPF program to detect syscall table hooks
#include <linux/bpf.h>
#include <linux/ptrace.h>

BPF_ARRAY(sys_call_table_baseline, u64, 300);
BPF_PERF_OUTPUT(events);

int kprobe__vfs_read(struct pt_regs *ctx) {
    int index = 0;
    u64 addr = PT_REGS_PARM1(ctx);
    u64 *baseline = sys_call_table_baseline.lookup(&index);
    
    if (baseline && *baseline != addr) {
        events.perf_submit(ctx, &addr, sizeof(addr));
    }
    
    return 0;
}
```

Compile and run with BCC tools.

### 4. Continuous File Integrity Monitoring

```bash
# Setup AIDE for kernel module directory monitoring
sudo apt install aide
echo "/lib/modules NORMAL" >> /etc/aide/aide.conf
echo "/boot NORMAL" >> /etc/aide/aide.conf
sudo aideinit

# Regular integrity checks
sudo aide --check
```

## Module-Specific Monitoring Scripts

### Detect Diamorphine

```python
#!/usr/bin/env python3
"""
Diamorphine Detector - Looks for hidden processes and rootkit characteristics
"""
import os
import subprocess
import signal

def check_signal_31_response():
    """Check for processes that respond to signal 31"""
    suspicious_pids = []
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            os.kill(int(pid), 31)
            suspicious_pids.append(pid)
            print(f"PID {pid} responded to signal 31 (Diamorphine indicator)")
        except (ProcessLookupError, PermissionError):
            pass
    return suspicious_pids

def check_hidden_modules():
    """Look for modules visible in /proc/modules but not in lsmod"""
    lsmod_output = subprocess.check_output(['lsmod'], universal_newlines=True)
    lsmod_modules = set()
    for line in lsmod_output.splitlines()[1:]:  # Skip header
        lsmod_modules.add(line.split()[0])
    
    proc_modules_output = subprocess.check_output(['cat', '/proc/modules'], 
                                                  universal_newlines=True)
    proc_modules = set()
    for line in proc_modules_output.splitlines():
        proc_modules.add(line.split()[0])
    
    hidden = proc_modules - lsmod_modules
    if hidden:
        print(f"Found hidden modules: {hidden}")
    return hidden

if __name__ == "__main__":
    print("Checking for Diamorphine rootkit indicators...")
    pids = check_signal_31_response()
    modules = check_hidden_modules()
    
    if not pids and not modules:
        print("No Diamorphine indicators found.")
```

### Detect Suterusu

```bash
#!/bin/bash
# Suterusu detector

echo "Scanning for Suterusu indicators..."

# Check for hidden processes
ps_count=$(ps aux | wc -l)
proc_count=$(ls /proc | grep -E '^[0-9]+$' | wc -l)

echo "Process count from ps: $ps_count"
echo "Process count from /proc: $proc_count"

if [ $((ps_count - 1)) -ne $proc_count ]; then  # ps header line
    echo "[WARNING] Process count mismatch - possible process hiding"
fi

# Check for suterusu's /dev hidden entries
echo "Checking for hidden /dev entries..."
dev_count=$(ls -la /dev | wc -l)
dev_find_count=$(find /dev -maxdepth 1 | wc -l)

if [ $dev_count -ne $dev_find_count ]; then
    echo "[WARNING] /dev entry count mismatch - possible hidden files"
    # Try to find the hidden entries
    find /dev -type c -not -exec ls -la {} \; 2>/dev/null
fi

# Check for common syscall hooks
echo "Checking for syscall hooks..."
grep -v '\[k\]' /proc/kallsyms | grep ' T ' | grep sys_

echo "Scan complete."
```

### Detect Crypto-Mining Modules

```bash
#!/bin/bash
# Crypto-mining module detector

echo "Scanning for crypto-mining kernel modules..."

# Check for disguised kworker processes
echo "Checking for suspicious kworker processes..."
ps aux | grep kworker | grep -v grep
ps aux | awk '{if ($3 > 80.0) print $0}'

# Check for hidden directories in /dev
echo "Checking for hidden directories in /dev..."
find /dev -type d -name ".*" 2>/dev/null

# Check for network connections to mining pools
echo "Checking for connections to known mining pools..."
netstat -tnap | grep -E ':(3333|3334|3335|3336|4444|5555|7777|8888|9999)'

# Check for high CPU usage by kernel threads
echo "Checking kernel threads CPU usage..."
ps -eo pcpu,pid,user,args | grep -E '^[[:space:]]*[0-9]+\.[0-9]+ +[0-9]+ +root +\[' | sort -nr | head -10

# Monitoring disk I/O for unexpected patterns
echo "Checking unusual I/O patterns..."
iostat -x 1 5

# Check for hidden modules
echo "Checking for hidden modules..."
comm -13 <(lsmod | awk '{print $1}' | grep -v Module | sort) <(cat /proc/modules | awk '{print $1}' | sort)

echo "Scan complete."
```

## System Hardening Against Kernel Module Attacks

### 1. Secure Boot and Module Signing

```bash
# Generate keys for module signing
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=My Module Signing Key/"

# Import the key
sudo mokutil --import MOK.der

# Sign a module
sudo /usr/src/kernels/$(uname -r)/scripts/sign-file sha256 ./MOK.priv ./MOK.der module.ko
```

### 2. Kernel Module Blacklisting

```bash
# Create comprehensive blacklist for suspicious modules
cat > /etc/modprobe.d/blacklist-malicious.conf << EOF
# Known malicious modules
blacklist diamorphine
blacklist suterusu
blacklist reptile
blacklist adore-ng
blacklist kbeast
blacklist azazel
blacklist keysniffer
blacklist modhide
blacklist sk_hide
blacklist khugepaged
blacklist kworker_mine

# Prevent loading via install command
install diamorphine /bin/false
install suterusu /bin/false
install reptile /bin/false
install adore-ng /bin/false
install kbeast /bin/false
install azazel /bin/false
EOF
```

### 3. Linux Security Modules Configuration

```bash
# Enable security modules in the kernel
# Add to GRUB_CMDLINE_LINUX in /etc/default/grub:
GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"

# Update grub
sudo update-grub

# Create AppArmor profile to restrict module loading
cat > /etc/apparmor.d/local/restrict-modules << EOF
/sbin/insmod {
  capability sys_module,
  /lib/modules/** r,
  /lib/modules/*/kernel/** r,
  /lib/modules/*/kernel/fs/** rm,
  /lib/modules/*/kernel/drivers/** rm,
  /lib/modules/*/kernel/net/** rm,
  deny /lib/modules/*/extra/** rwxm,
  deny /lib/modules/*/updates/** rwxm,
  deny /tmp/** rwxm,
  deny /var/tmp/** rwxm,
  deny /dev/shm/** rwxm,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/local/restrict-modules
```

### 4. Immutable Infrastructure Approach

```bash
# Make critical directories immutable
sudo chattr +i /sbin/insmod
sudo chattr +i /sbin/modprobe
sudo chattr +i /lib/modules/$(uname -r)/kernel/

# Use read-only root filesystem when possible (in /etc/fstab)
# Add "ro" to mount options for the root filesystem
UUID=xxx / ext4 ro,errors=remount-ro 0 1
```

## Continuous Monitoring Script

```bash
#!/bin/bash
# Continuous kernel module monitoring

LOG_FILE="/var/log/kernel_module_monitor.log"
BASELINE_FILE="/var/lib/kernel_module_baseline.txt"

echo "Starting kernel module monitor at $(date)" | tee -a $LOG_FILE

# Create initial baseline if doesn't exist
if [ ! -f "$BASELINE_FILE" ]; then
    echo "Creating initial baseline of loaded modules" | tee -a $LOG_FILE
    lsmod > $BASELINE_FILE
fi

# Function to check for new modules
check_modules() {
    TEMP_FILE=$(mktemp)
    lsmod > $TEMP_FILE
    
    echo "=== Module check at $(date) ===" >> $LOG_FILE
    
    # Check for newly loaded modules
    DIFF=$(comm -13 $BASELINE_FILE $TEMP_FILE)
    if [ ! -z "$DIFF" ]; then
        echo "WARNING: New modules detected:" | tee -a $LOG_FILE
        echo "$DIFF" | tee -a $LOG_FILE
        
        # Check each new module
        while read -r module; do
            module_name=$(echo $module | awk '{print $1}')
            
            # Check module info
            echo "Module info for $module_name:" >> $LOG_FILE
            modinfo $module_name >> $LOG_FILE 2>&1
            
            # Check if module file still exists
            module_file=$(modinfo -n $module_name 2>/dev/null)
            if [ -z "$module_file" ] || [ ! -f "$module_file" ]; then
                echo "CRITICAL: Module $module_name has no associated file - possible rootkit!" | tee -a $LOG_FILE
                
                # Alert via email/Slack/etc
                # mail -s "CRITICAL: Hidden kernel module detected" admin@example.com < $LOG_FILE
            fi
        done <<< "$DIFF"
    fi
    
    # Check for modules removed since baseline
    REMOVED=$(comm -23 $BASELINE_FILE $TEMP_FILE)
    if [ ! -z "$REMOVED" ]; then
        echo "INFO: Modules removed since baseline:" >> $LOG_FILE
        echo "$REMOVED" >> $LOG_FILE
    fi
    
    # Check for inconsistencies between lsmod and /proc/modules
    HIDDEN=$(comm -13 <(awk '{print $1}' $TEMP_FILE | grep -v "Module" | sort) <(awk '{print $1}' /proc/modules | sort))
    if [ ! -z "$HIDDEN" ]; then
        echo "CRITICAL: Modules hidden from lsmod but present in /proc/modules:" | tee -a $LOG_FILE
        echo "$HIDDEN" | tee -a $LOG_FILE
        
        # Alert via email/Slack/etc
        # mail -s "CRITICAL: Hidden kernel module detected" admin@example.com < $LOG_FILE
    fi
    
    # Check for suspicious syscall hooks
    if [ -d "/sys/kernel/debug/tracing" ]; then
        echo "Checking syscall table integrity..." >> $LOG_FILE
        cat /sys/kernel/debug/tracing/available_filter_functions | grep sys_call_table >> $LOG_FILE
    fi
    
    # Update baseline with current state (optional, uncomment if desired)
    # cp $TEMP_FILE $BASELINE_FILE
    
    rm $TEMP_FILE
}

# Setup monitoring hooks
if [ -d "/sys/kernel/debug/tracing" ]; then
    echo "Setting up kernel function tracing..." | tee -a $LOG_FILE
    echo 0 > /sys/kernel/debug/tracing/tracing_on
    echo "init_module delete_module" > /sys/kernel/debug/tracing/set_ftrace_filter
    echo function > /sys/kernel/debug/tracing/current_tracer
    echo 1 > /sys/kernel/debug/tracing/tracing_on
    
    # Monitor trace in background
    (tail -f /sys/kernel/debug/tracing/trace_pipe | grep -E 'init_module|delete_module' >> $LOG_FILE) &
    TRACE_PID=$!
    echo "Tracing started with PID $TRACE_PID" >> $LOG_FILE
fi

# Initial check
check_modules

# Set up audit rules
if command -v auditctl &> /dev/null; then
    echo "Setting up audit rules for module operations" | tee -a $LOG_FILE
    auditctl -a always,exit -F arch=b64 -S init_module -S delete_module -S create_module -S finit_module -k MODULE_OPERATIONS
    auditctl -w /proc/kallsyms -p r -k KALLSYMS_ACCESS
    auditctl -w /boot -p wa -k KERNEL_MODIFICATION
    auditctl -w /lib/modules -p wa -k MODULE_MODIFICATION
fi

# Run checks every 5 minutes
while true; do
    sleep 300
    check_modules
done
```

## Comprehensive Defense Strategy

### 1. Prevention Layer

- Use Secure Boot with module signing
- Implement module loading restrictions
- Blacklist known malicious modules
- Use immutable infrastructure approaches
- Apply kernel hardening parameters

### 2. Detection Layer

- Implement continuous file integrity monitoring
- Deploy kernel-aware EDR solutions
- Set up syscall monitoring
- Implement advanced auditing
- Use the monitoring scripts provided above

### 3. Response Layer

- Create automated alerts for suspicious activities
- Develop incident response playbooks specific to kernel module threats
- Maintain forensic readiness for kernel-level incidents
- Practice recovery procedures

