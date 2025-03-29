# Malicious Kernel Modules: A Security Primer '24-'25 Edition

## Introduction

Kernel modules can be used by attackers to gain persistent, privileged access to Linux systems. These loadable modules run with kernel privileges, making them particularly dangerous and difficult to detect. This document catalogs known malicious modules and their characteristics as an educational resource.

## Rootkits and Malicious Kernel Modules

| Module Name | Description | Indicators | Notable Campaigns |
|-------------|-------------|------------|-------------------|
| `diamorphine` | Modern rootkit that hides processes, files, network connections and itself. Allows privilege escalation. | Responds to special signals, hidden from `lsmod` | Commonly found in cryptocurrency mining attacks |
| `suterusu` | Sophisticated rootkit with process hiding and privilege escalation capabilities | Hidden files in `/dev`, syscall hooking | Various APT campaigns |
| `Reptile` | LKM rootkit that provides backdoor capabilities | Hidden processes, unexpected network connections | Botnet operations |
| `Adore-ng` | Advanced rootkit for hiding processes and files | Unusual syscall table modifications | Various targeted attacks |
| `KBeast` | Powerful rootkit with file/process hiding and port knocking | Hidden network connections, syscall hooks | Targeted server compromises |
| `Azazel` | Modern rootkit with process/file hiding and backdoor capabilities | Unexpected library injections, hidden processes | Data exfiltration campaigns |
| `knark` | One of the first LKM rootkits, still found in modified forms | Process hiding, unexpected system calls | Older but still encountered in some environments |
| `intoxonia` | Keylogger rootkit with advanced hiding capabilities | System call table modifications, high CPU usage | Targeted espionage |
| `Phalanx` | Rootkit focused on packet sniffing and backdoors | Hidden network connections, unexpected modules | Financial sector targeting |
| `Xingxao` | Stealthy rootkit that provides remote access | System call hooks, hidden processes | APT campaigns |

## Crypto-Mining Malware

| Module Name | Description | Indicators | Notable Campaigns |
|-------------|-------------|------------|-------------------|
| `kinsing.ko` | Kernel module component of Kinsing crypto-mining malware | High CPU usage, hidden mining processes | Widespread cloud infrastructure attacks |
| `khugepaged` | Malicious module disguised as legitimate memory management module | Unexpected network connections, high CPU usage | Cloud server compromises |
| `kworker_mine` | Disguises as system kworker to mine cryptocurrency | Hidden directory in `/dev`, high CPU usage | Attacks on misconfigured Kubernetes clusters |
| `cpumon` | Monitors CPU usage to hide mining operations when users are active | Fluctuating CPU patterns, unexpected behavior | Cloud-hosted server campaigns |

## Data Theft and Espionage

| Module Name | Description | Indicators | Notable Campaigns |
|-------------|-------------|------------|-------------------|
| `keysniffer` | Kernel-based keylogger that captures keystrokes | Unusual file writes, unexplained memory usage | Targeted corporate espionage |
| `interceptor` | Intercepts network traffic before encryption | Unusual syscall modifications, redirected traffic | Financial institution targeting |
| `ss_module` | Used to capture encrypted communications | Unexpected network behavior, modified SSL libraries | Various APT campaigns |
| `pkgrab` | Captures authentication data | Hidden processes, unexpected disk writes | Credential harvesting operations |

## Network Attack Modules

| Module Name | Description | Indicators | Notable Campaigns |
|-------------|-------------|------------|-------------------|
| `netfilterx` | Covert packet manipulation and traffic analysis | Unknown rules in iptables, hidden connections | DDoS infrastructure, C2 networks |
| `rshell_mod` | Provides persistent reverse shell capabilities | Unexpected outbound connections, hidden from netstat | Various remote access campaigns |
| `nf_conntrack_backdoor` | Disguises as legitimate netfilter component | Unusual firewall behavior, unexpected rules | State-sponsored attacks |
| `sk_filter` | Socket filtering to intercept or modify network traffic | Modified network behavior, hidden connections | Banking trojan infrastructure |

## Anti-Detection Modules

| Module Name | Description | Indicators | Notable Campaigns |
|-------------|-------------|------------|-------------------|
| `antivfake` | Creates false positive signals to confuse security tools | Security tools reporting inconsistent results | Advanced persistent threats |
| `cleaner_mod` | Cleans logs and evidence of compromise | Missing log entries, truncated logs | Post-exploitation phase of targeted attacks |
| `guardian` | Prevents loading of security modules | Security tools failing to start, mysterious crashes | Targeted infrastructure attacks |
| `wipe_IDT` | Interferes with debugging and tracing mechanisms | Debugging tools failing, system instability | Advanced targeted attacks |

## Defense Evasion Modules

| Module Name | Description | Indicators | Notable Campaigns |
|-------------|-------------|------------|-------------------|
| `stealth_mod` | Hides system modifications and files | Files invisible to ls but accessible via other means | Various persistent threats |
| `av_bypass` | Specific targeting of antivirus mechanisms | AV services crashing or reporting inconsistently | Targeted ransomware deployments |
| `unrandomize` | Makes ASLR and other security features predictable | Security mechanisms behaving unexpectedly | Exploit development and deployment |
| `audit_killer` | Disables or manipulates Linux audit subsystem | Missing audit logs, failed auditing | Post-breach activity hiding |

## Detection Methods

1. **File Integrity Monitoring**: Monitor critical kernel and system files for unexpected changes
2. **Runtime Detection**: 
   - Check for unexpected syscall table modifications
   - Look for hidden modules not appearing in `lsmod` but present in `/proc/modules`
3. **Behavior Analysis**:
   - Unexplained network connections
   - System calls behaving differently than expected
4. **Memory Analysis**:
   - Scanning kernel memory for unauthorized hooks or modifications
5. **Static Kernel Module Verification**:
   - Checking module signatures
   - Validating against known-good baselines

## Mitigation Strategies

1. **Kernel Security Features**:
   - Enable Secure Boot with module signing
   - Use kernel lockdown mode where available
   - Implement module loading restrictions (`/etc/modprobe.d/`)

2. **System Hardening**:
   - Restrict module loading capabilities:
     ```bash
     echo "kernel.modules_disabled=1" >> /etc/sysctl.conf
     sysctl -p
     ```
   - Maintain minimal attack surface
   - Remove module loading tools from production systems when not needed

3. **Monitoring and Response**:
   - Implement continuous monitoring for module loading
   - Create baselines of legitimate modules
   - Deploy EDR solutions with kernel monitoring capabilities

4. **Regular Security Updates**:
   - Keep kernels and systems fully patched
   - Monitor security announcements for your distribution

## Forensic Analysis Commands

```bash
# List all loaded kernel modules
lsmod

# Show detailed information about a module
modinfo <module_name>

# Check for hidden modules by comparing lsmod output with /proc/modules
cat /proc/modules | grep -v "$(lsmod | awk '{print $1}' | grep -v 'Module')"

# Check system call table modifications
sudo cat /proc/kallsyms | grep sys_call_table

# Look for unknown persisted modules
find /lib/modules/$(uname -r) -name "*.ko" | grep -v "$(lsmod | awk '{print $1}' | grep -v 'Module')"
```

## Example Incident Response Workflow

1. **Identification**:
   - Detect suspicious module behavior
   - Preserve evidence using memory dumps and disk images

2. **Containment**:
   - Isolate affected systems
   - Prevent further module loading

3. **Eradication**:
   - Boot from trusted media
   - Remove persistent module entries
   - Validate clean state

4. **Recovery**:
   - Restore from known good backups if possible
   - Implement improved controls

5. **Lessons Learned**:
   - Update detection strategies
   - Enhance preventative controls

## Conclusion

Malicious kernel modules represent some of the most sophisticated threats to Linux systems. 
Understanding their capabilities and characteristics is essential for effective defense. By implementing proper controls, monitoring, and response procedures, organizations can reduce the risk posed by these advanced threats.

---

# Lmao

**Note**: This document is for educational purposes only. Knowledge of these techniques should be used responsibly to improve security posture and defensive capabilities.
