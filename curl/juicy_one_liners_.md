

## 🧭 **Proposed Structure for the Updated Cheat Sheet**

### 1. System and Process Basics
- Disk, memory, CPU usage with `df`, `du`, `free`, `top`, and `ps`.
- Modern replacements: `lsblk`, `btop`, `btm`, and `htop`.

### 2. Network Checks
- Keep all the `ss`, `lsof`, and `netstat` entries.
- Add `sudo ss -tuna | grep <port>` shortcut.
- Add `nmap -p- --min-rate 1000 <target>` for fast scanning.
- Add `nc -zv host port` simple port check.

### 3. Disk Usage and Cleanup
- Keep existing `du` one-liners.
- Add:
  ```bash
  sudo du -h -d1 /var | sort -h  # quickly find big dirs
  sudo journalctl --disk-usage    # check systemd log space
  sudo journalctl --vacuum-time=7d  # clean logs older than 7 days
  ```
- Add basic container cleanup:
  ```bash
  sudo k3s crictl image prune
  sudo docker system prune -af
  ```

### 4. Containers (Docker / K3s / Podman)
- Keep Docker section.
- Add `crictl`, `nerdctl`, and `podman` equivalents.
- Add modern "cleanup" one-liners:
  ```bash
  sudo docker container prune -f
  sudo docker image prune -af
  sudo docker volume prune -f
  ```
- Add a quick container inspection:
  ```bash
  docker inspect <container> | jq
  ```

### 5. Security & CTF Additions
- `strings`, `file`, `exiftool`, `binwalk`, `xxd`, `nc`, `curl`, `jq`
- Common scanning and enumeration one-liners:
  ```bash
  for port in {1..1024}; do (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1 && echo "Port $port open"; done
  ```
- Add payload helpers like:
  ```bash
  echo -n "command" | base64 -w0
  python3 -m http.server 8000  # quick file share
  nc -lvnp 4444                # start a reverse listener
  ```

### 6. Git / DevOps
- Keep your git section but add:
  ```bash
  git restore . && git clean -fd
  git log --oneline --graph --decorate
  ```
- Add CI/CD debugging (curl + token workflow already there).

### 7. Networking / Curl Rework
- Keep your Bearer/Basic Auth + JSON workflows.
- Add:
  ```bash
  curl -w "@curl-format.txt" -o /dev/null -s https://example.com
  ```
  (for measuring latency, speed, etc.)
- Add curl with colors / pretty JSON:
  ```bash
  curl -s https://api.github.com | jq
  ```

### 8. Quality of Life Tools
- Add:
  ```bash
  batcat file.txt    # better cat
  fd pattern         # faster find
  rg string          # faster grep
  tldr command       # quick manpages
  ```
- Add:
  ```bash
  sudo apt autoremove --purge -y
  ```

---


