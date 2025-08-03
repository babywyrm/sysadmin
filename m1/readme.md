

# 🍏 macOS Hack Sheet (Extended Edition) -- for less day to day toxicity, tbh 

##
##

## 🗂️ SYSTEM | Hardware, Identity, and Users

```bash
system_profiler SPHardwareDataType          # Hardware info
uname -a                                    # Kernel info
sw_vers                                     # macOS version
whoami && id                                # Current user
dscl . list /Users                          # Local users
last                                        # User login history
```

---

## 🌙 POWER | Sleep, Display, Battery Control

```bash
sudo pmset -a disablesleep 1               # Never sleep, even when lid is closed
sudo pmset -a sleep 0                       # Disable idle sleep
caffeinate -dimsu                           # Keep awake until command exits
sudo pmset -g                              # Show power settings
```

---

## 🛠️ SYSTEM TWEAKS & TOOLS

```bash
defaults write com.apple.finder AppleShowAllFiles TRUE && killall Finder  # Show hidden files
open /System/Library/CoreServices        # Hidden system apps
nvram boot-args="keepsyms=1 debug=0x100" # Enable verbose boot for debugging
csrutil status                           # Check System Integrity Protection
```

---

## 🔐 SECURITY & PRIVACY

```bash
tccutil reset All                        # Reset app privacy permissions
sudo fdesetup status                     # FileVault status
security dump-keychain                   # Dump keychain entries
sudo log show --predicate 'eventMessage contains "auth"' --info --last 1d
```

---

## 🧪 NETWORK / DISCOVERY

```bash
ipconfig getifaddr en0                   # Get IP
netstat -anv | grep LISTEN               # Listening ports
lsof -i -nP                              # Open sockets
scutil --dns                             # Show DNS settings
dns-sd -B _services._dns-sd._udp         # Bonjour scan
```

---

## 📦 APPS, LAUNCH AGENTS & PERSISTENCE

```bash
launchctl list                           # User launch agents
sudo launchctl list                      # System launch daemons
ls ~/Library/LaunchAgents
crontab -l                               # Scheduled jobs
at -l                                    # Pending jobs
```

Launch Agent Sample:

```bash
~/Library/LaunchAgents/com.fake.agent.plist
```

---

## 🕵️ EVASION / HIDING TRICKS

```bash
xattr -d com.apple.quarantine ./evil.sh
spctl --add --label "trusted" ./evil.sh
chflags hidden filename
chflags uchg filename                    # Make immutable
```

---

## 🧠 DEV TOOLS / MONITORING

```bash
ps aux | grep suspicious
fs_usage | grep write                    # Monitor file writes
sudo dtruss -n curl                      # Trace system calls
sudo opensnoop -n Finder                 # See files opened by process
sudo execsnoop                           # Commands executed
```

---

## 🧼 CLEANUP / COVER TRACKS

```bash
rm -rf ~/Library/Caches/*
history -c && rm ~/.bash_history
sudo log erase --all                     # Wipe unified logs
```

---

## 🛑 INTERESTING DIRECTORIES

```bash
/Users/<user>/Library/Logs/
/Users/<user>/Library/LaunchAgents/
/Library/LaunchDaemons/
/private/var/tmp/
/System/Library/Extensions/
```

---

## 🐚 SHELL GOODIES (Default MacShell is `zsh`)

```bash
autoload -Uz colors && colors
alias l='ls -lah'
alias network="netstat -anv | grep LISTEN"
alias lockdown="sudo pmset -a disablesleep 1 && sudo killall -STOP -c Dock"
```

---

## 📁 App Store + Brew Utilities

```bash
system_profiler SPApplicationsDataType | grep -B3 -A3 "Location"
brew list
brew install nmap jq htop git python3
```

---

## 🚀 `mac_hax` Terminal Tool

**Structure proposal:**

```
mac_hax/
├── mac_hax.sh            # Main interactive CLI
├── modules/
│   ├── recon.sh
│   ├── evasion.sh
│   ├── system_tweaks.sh
│   └── persistence.sh
└── README.md
```

**Basic example usage:**

```bash
./mac_hax.sh --recon
./mac_hax.sh --evasion
./mac_hax.sh --all > report.txt
```


