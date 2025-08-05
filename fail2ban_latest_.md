

## 🔐 Hardened Fail2Ban Setup   ..updated..

---

### 📦 Step 1: Install Fail2Ban (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install fail2ban -y
```

**Confirm Version** (must be ≥ `0.11.3` for `mail-whois` patch):

```bash
fail2ban-client -V
# Fail2Ban v0.11.3 or higher recommended
```

---

### 🗂️ Step 2: Filesystem Layout

```plaintext
/etc/fail2ban/
├── jail.conf         # Default config – DO NOT EDIT
├── jail.local        # Your custom jails live here
├── filter.d/         # Custom match filters
├── action.d/         # Actions like iptables, email, etc.
└── logrotate.d/fail2ban  # Log rotation
```

> 💡 Tip: If `jail.local` doesn’t exist, create it:

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

Then wipe all jails from `jail.local` and insert your own.

---

### 🔧 Step 3: Create a Custom Filter for Web Logins

**Path**: `/etc/fail2ban/filter.d/weblogin.conf`

```ini
[Definition]
failregex = ^<HOST> -.*"(POST|GET) /login HTTP.*"
ignoreregex =
```

> ✅ Adjust `/login` if your app uses `/api/login`, `/admin`, etc.

---

### 🧱 Step 4: Add Jail to `jail.local`

**Path**: `/etc/fail2ban/jail.local`

```ini
[DEFAULT]
bantime = 3600
findtime = 300
maxretry = 10
backend = auto
loglevel = INFO
usedns = warn
destemail = you@example.com
sender = fail2ban@yourhost.local
action = %(action_)s  # Use mailx, not mailutils!

[weblogin]
enabled = true
port    = http,https
filter  = weblogin
logpath = /var/log/apache2/access.log
```

> Replace with `/var/log/nginx/access.log` if using NGINX.

---

### 🧨 RCE Warning: `mail-whois` is vulnerable

Avoid this block in any jail:

```ini
action = mail-whois[name=ssh, dest=root@localhost, sender=fail2ban@localhost]
```

Instead, use:

```ini
action = %(action_mwl)s
```

Or safer:

```ini
action = mail[name="Fail2Ban", dest=you@example.com, sender=fail2ban@host]
```

**Alternative**: use `bsd-mailx` instead of `mailutils` to avoid `~!` tilde RCE sequences.

---

### 📫 Optional: Send Slack or Discord Webhooks

**Path**: `/etc/fail2ban/action.d/slack.conf`

```ini
[Definition]
actionstart = curl -X POST -H 'Content-type: application/json' \
  --data '{"text": "[Fail2Ban] Started jail <name>."}' <slack_webhook_url>

actionban = curl -X POST -H 'Content-type: application/json' \
  --data '{"text": "[Fail2Ban] Banned IP <ip> for <name>."}' <slack_webhook_url>

actionunban = curl -X POST -H 'Content-type: application/json' \
  --data '{"text": "[Fail2Ban] Unbanned IP <ip> for <name>."}' <slack_webhook_url>
```

Add to your jail:

```ini
action = slack
```

---

### 💣 Optional: Protect `/xmlrpc.php`, `/wp-login.php`, APIs

**Filter**: `/etc/fail2ban/filter.d/wordpress-login.conf`

```ini
[Definition]
failregex = <HOST> -.*"(POST|GET) /wp-login.php HTTP.*"
            <HOST> -.*"(POST|GET) /xmlrpc.php HTTP.*"
```

**Jail**:

```ini
[wordpress-login]
enabled  = true
filter   = wordpress-login
port     = http,https
logpath  = /var/log/apache2/access.log
maxretry = 5
findtime = 120
bantime  = 7200
```

---

### 🔍 Step 5: Restart & Check Status

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status
sudo fail2ban-client status weblogin
```

---

### 🧪 Step 6: Test It

From a test client or local terminal:

```bash
curl -X POST http://yourhost/login
# Repeat until maxretry triggers
```

Watch logs:

```bash
sudo tail -f /var/log/fail2ban.log
```

Example:

```text
[weblogin] Ban 1.2.3.4
[weblogin] Unban 1.2.3.4
```

---

### 🔐 Optional: Harden SSH with Extra Filters

```ini
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 7200
```

---

### 🚨 Troubleshooting Tips

| Symptom                | Fix                                                                 |
| ---------------------- | ------------------------------------------------------------------- |
| Jail doesn't work      | Check log path, filter name, test regex with `fail2ban-regex`       |
| Not banning IPs        | Confirm log entries match `failregex`                               |
| Email not sent         | Use `mailx`, check `ssmtp` or `msmtp` mail logs                     |
| Wrong IP shown in logs | Use `usedns = warn` or `usedns = no`                                |
| Need IPv6 support      | Add `banaction = iptables-multiport` or `ip6tables-multiport` combo |

---

### 🔁 Rotate Logs (Optional)

Check `/etc/logrotate.d/fail2ban` and ensure logs are rotated weekly:

```bash
cat /etc/logrotate.d/fail2ban
```

---

### 💾 Backup Your Configs

```bash
sudo tar czvf fail2ban-configs-backup.tar.gz /etc/fail2ban
```

---

### ✅ Final Recommendations

* Upgrade to Fail2Ban `0.11.3+`
* Avoid `mail-whois` unless patched
* Use `mailx`, `sendmail`, or webhooks instead of `mailutils`
* Always test with `fail2ban-regex`:

  ```bash
  fail2ban-regex /var/log/apache2/access.log /etc/fail2ban/filter.d/weblogin.conf
  ```


##
##
