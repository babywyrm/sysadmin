


## ✅ Modernized Fail2Ban Setup for Web Route Abuse 


### ⚠️ Security Advisory Recap (RCE in `mail-whois`)

* **Vulnerability**: Exploitable command execution via `mailutils` (`~!` escape sequences in input piped to `mail`)
* **Fixed in**:

  * Fail2Ban: ≥ `0.10.7`, `0.11.3`
  * Commit: `410a6ce`
* **Recommended Action**:

  * **Avoid** `mail-whois` with `mailutils` unless `-E` escape is set
  * **Use** `bsd-mailx`, `heirloom-mailx`, or `sendmail`-based alternatives
  * Or patch the `mail` call like so:

    ```bash
    mail -E 'set escape' -s ...
    ```

---

### ✅ Installation

```bash
sudo apt update
sudo apt install fail2ban -y
```

---

### 🔍 Confirm Running and Version

```bash
fail2ban-client version
sudo systemctl status fail2ban
```

Ensure you’re running a version ≥ `0.11.3` or manually patch/remove `mail-whois`.

---

### 📂 Directory Overview

```plaintext
/etc/fail2ban/
├── action.d/
├── filter.d/
├── jail.conf        # DO NOT MODIFY
├── jail.local       # CUSTOMIZE THIS
```

---

### 🔧 Step 1: Create a Custom Filter

**Path**: `/etc/fail2ban/filter.d/weblogin.conf`

```ini
[Definition]
failregex = ^<HOST> -.*"(POST|GET) /login HTTP.*"
ignoreregex =
```

---

### 🔧 Step 2: Configure Jail

**Path**: `/etc/fail2ban/jail.local`

```ini
[weblogin]
enabled  = true
filter   = weblogin
port     = http,https
logpath  = /var/log/apache2/access.log
action   = iptables-multiport[name=weblogin, port="http,https"]
findtime = 60
bantime  = 3600
maxretry = 10
```

> ✅ Increase `maxretry` if you expect legit traffic or password managers.

---

### ✅ Step 3: Restart Fail2Ban

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status weblogin
```

---

### 🔒 Optional: Disable `mail-whois` or Patch

To prevent any future mail-based RCEs, either:

* Replace `mail-whois` with `mailx-whois` (uses `mailx`, not `mailutils`)
* Or edit `/etc/fail2ban/action.d/mail-whois.conf`:

**Original**:

```ini
actionban = printf %%b "Hi...\n...`%(_whois_command)s`\n" | mail ...
```

**Secure Replacement** (if stuck with `mailutils`):

```ini
actionban = printf %%b "Hi...\n...`%(_whois_command)s`\n" | mail -E 'set escape' ...
```

---

### 🛡️ Harden WHOIS Use

If you must use WHOIS in actions:

* Use `whois -h whois.arin.net <ip>` with `timeout` and output filtering
* Avoid relying on `rwhois` unless from trusted IPs

Example safe usage:

```bash
timeout 5s whois -h whois.arin.net <ip> | grep -v '^~'
```

---

### ✅ Example Output

```bash
sudo fail2ban-client status weblogin
# Status
# |- Number of jail:      3
# `- Jail list:           sshd, postfix, weblogin

sudo tail -f /var/log/fail2ban.log
# [weblogin] Ban 192.168.1.100
# [weblogin] Unban 192.168.1.100
```

---

### 🧪 Testing the Jail

To test locally:

```bash
curl -X POST http://localhost/login
curl -X POST http://localhost/login
# ...repeat until banned (based on maxretry)
```

Or monitor log:

```bash
sudo tail -f /var/log/fail2ban.log
```

---

### 🔐 Best Practices Summary

| Area          | Best Practice                             |
| ------------- | ----------------------------------------- |
| Email actions | Avoid `mail-whois` or patch               |
| WHOIS usage   | Sanitize output, avoid `~!`, use timeouts |
| Logging       | Monitor logs for ban/unban actions        |
| Filtering     | Keep regex simple and target attack paths |
| Upgrades      | Stay on Fail2Ban ≥ `0.11.3` for fixes     |

---

