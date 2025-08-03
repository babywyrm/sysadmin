
# 🍏 macOS Hack Sheet For Making Life (Marginally) Less Absolutely Toxic

##
##


### 💤 **Prevent Sleep (Lid Closed or Idle)**

```bash
sudo pmset -a disablesleep 1         # Disable sleep entirely (even with lid closed)
sudo pmset -a sleep 0                # Disable idle sleep
caffeinate -dimsu                    # Prevent sleep while terminal session is active
```

---

### 🧠 **System Info & Recon**

```bash
system_profiler SPHardwareDataType            # Hardware overview
system_profiler SPNetworkDataType             # Network interfaces and IPs
ifconfig | grep inet                          # IP addresses
whoami && id                                  # Current user & UID
log show --predicate 'eventMessage contains "wake"' --last 1h
```

---

### 🛠️ **Quick File Access & Hidden Paths**

```bash
defaults write com.apple.finder AppleShowAllFiles TRUE && killall Finder
open /System/Library/CoreServices              # Hidden system apps
```

---

### 🔐 **User & Auth Secrets**

```bash
dscl . list /Users                             # List local users
security find-generic-password -ga wifi-name  # Get saved Wi-Fi passwords (prompted)
sudo opendirectoryd -force                     # Reset auth subsystem
```

---

### 🧳 **Persistence Tricks**

```bash
launchctl list                                 # List all launch agents/daemons
launchctl load ~/Library/LaunchAgents/com.my.agent.plist
```

Sample LaunchAgent:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key> <string>com.my.agent</string>
  <key>ProgramArguments</key> <array>
    <string>/bin/bash</string> <string>-c</string> <string>touch /tmp/persisted</string>
  </array>
  <key>RunAtLoad</key> <true/>
</dict>
</plist>
```

---

### 🧭 **Network/Port Recon**

```bash
netstat -anv | grep LISTEN                    # Listening ports
lsof -i -nP                                   # Open sockets
dns-sd -B _services._dns-sd._udp              # Bonjour service discovery
```

---

### 🧼 **Bypass Gatekeeper / Quarantine**

```bash
xattr -d com.apple.quarantine ./payload.sh
spctl --add --label "trusted" ./payload.sh
```

---

### 🕵️ **Sneaky Binary Tricks**

```bash
sudo nvram boot-args="nvram -p"              # View NVRAM boot args (can be used for rootkit-like behavior)
codesign --remove-signature payload.app      # Strip code signature
csrutil status                                # Check SIP status (reboot into recovery to change)
```

---

### 📦 **Package & Binary Utilities**

```bash
pkgutil --pkgs                               # List all installed packages
pkgutil --files com.apple.pkg.Core
otool -L /bin/bash                           # Show linked libraries
codesign -dv --verbose=4 /Applications/Safari.app
```

---

### 📜 **Script Persistence / Hidden Startup**

```bash
crontab -e
echo "@reboot /Users/you/.hidden/start.sh" >> ~/.crontab
```

---

### 🛡️ **Security & Privacy Bypasses**

```bash
tccutil reset All                            # Reset app permissions (e.g., Full Disk Access)
sudo launchctl bootout system /System/Library/LaunchDaemons/com.apple.TCC.db
```

---

### 📁 **Interesting Paths**

```
~/Library/Logs/
~/Library/LaunchAgents/
~/Library/Application Support/
~/Library/Preferences/
```
