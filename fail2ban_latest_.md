

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




## 🐳 Dockerized Fail2Ban (2025 Edition)

### 📁 Project Layout

```bash
fail2ban-docker/
├── Dockerfile
├── jail.local
├── filter.d/
│   └── weblogin.conf
├── action.d/
│   └── slack.conf
├── entrypoint.sh
├── fail2ban.log
└── docker-compose.yml
```

##
##


### 🐳 `Dockerize this piece lol`

```Dockerfile
FROM alpine:latest

LABEL maintainer="you@example.com"
LABEL version="2025.08.1"

ENV F2B_VERSION=1.0.2

RUN apk add --no-cache \
    fail2ban \
    iptables \
    bash \
    mailx \
    curl \
    iproute2 \
    shadow \
    tzdata \
    && rm -rf /var/cache/apk/*

# Copy configurations
COPY jail.local /etc/fail2ban/jail.local
COPY filter.d/ /etc/fail2ban/filter.d/
COPY action.d/ /etc/fail2ban/action.d/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

# Logs
VOLUME ["/var/log", "/etc/fail2ban"]

ENTRYPOINT ["/entrypoint.sh"]
```

---

### ⚙️ `entrypoint.sh`

```bash
#!/bin/bash
set -e

echo "[+] Starting Fail2Ban..."
touch /var/log/fail2ban.log

# Optional: tail the log in background
tail -F /var/log/fail2ban.log &

exec fail2ban-server -f
```

---

### 📄 `jail.local`

```ini
[DEFAULT]
bantime  = 3600
findtime = 300
maxretry = 5
usedns   = warn
backend  = auto
destemail = you@example.com
sender = fail2ban@yourhost.local
action = %(action_mwl)s

[weblogin]
enabled  = true
port     = http,https
filter   = weblogin
logpath  = /var/log/apache2/access.log
```

---

### 📜 `filter.d/weblogin.conf`

```ini
[Definition]
failregex = ^<HOST> -.*"(POST|GET) /login HTTP.*"
ignoreregex =
```

---

### 📣 `action.d/slack.conf` (Webhook example)

```ini
[Definition]
actionstart = curl -X POST -H 'Content-type: application/json' \
  --data '{"text": "[Fail2Ban] Started jail <name>."}' <webhook_url>

actionban = curl -X POST -H 'Content-type: application/json' \
  --data '{"text": "[Fail2Ban] Banned IP <ip> in jail <name>."}' <webhook_url>

actionunban = curl -X POST -H 'Content-type: application/json' \
  --data '{"text": "[Fail2Ban] Unbanned IP <ip> in jail <name>."}' <webhook_url>
```

---

### 🐙 `docker-compose.yml`

```yaml
version: '3.8'

services:
  fail2ban:
    build: .
    container_name: fail2ban
    network_mode: "host"  # Required to see host logs + ban IPs
    volumes:
      - ./fail2ban.log:/var/log/fail2ban.log
      - ./filter.d:/etc/fail2ban/filter.d
      - ./action.d:/etc/fail2ban/action.d
      - ./jail.local:/etc/fail2ban/jail.local
      - /var/log/apache2:/var/log/apache2:ro  # Adjust to nginx if needed
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped
```

---

### ✅ Build and Run

```bash
docker-compose build
docker-compose up -d
```

---

### 🔎 Validate Fail2Ban Status

```bash
docker exec -it fail2ban fail2ban-client status
docker exec -it fail2ban fail2ban-client status weblogin
```

---

### 🔬 Testing

Trigger log entries:

```bash
for i in {1..10}; do curl -X POST http://localhost/login; done
```

Check logs:

```bash
docker logs -f fail2ban
```

---

### 🔐 Extra Hardening (Optional)

* Use `--read-only` container flag
* Mount only `/var/log/apache2` as needed
* Drop all unnecessary capabilities
* Replace `iptables` with `nftables` if preferred (requires adaptation)

---

### 📦 Future Enhancements

* Add **support for `crowdsec` or `cscli`** integration
* Stream events to **ElasticSearch, Loki, or Promtail**
* Add **cron task** to auto-prune old bans
* Mirror logs to external syslog or SIEM

---

### ✍️ Markdown Summary Footer (for your file)

```markdown
### 🐳 Dockerized Fail2Ban Summary

- Hardened Alpine container
- Preloaded with custom filters for web route abuse
- Mailx & webhook alerting supported
- Host networking + `iptables` support
- Logs + filters mounted persistently
- Slack/Discord/webhook ready
```


##
##



# Makefile (beta)

```
# Project variables
IMAGE_NAME=fail2ban-secure
CONTAINER_NAME=fail2ban
COMPOSE_FILE=docker-compose.yml

.PHONY: help build up down restart logs status shell test clean

help:
	@echo "Usage:"
	@echo "  make build     - Build the Docker image"
	@echo "  make up        - Start Fail2Ban container"
	@echo "  make down      - Stop container"
	@echo "  make restart   - Restart container"
	@echo "  make logs      - Tail Fail2Ban logs"
	@echo "  make status    - Show Fail2Ban jail status"
	@echo "  make shell     - Shell into the container"
	@echo "  make test      - Run simulated attack test"
	@echo "  make clean     - Remove image and container"

build:
	docker-compose -f $(COMPOSE_FILE) build

up:
	docker-compose -f $(COMPOSE_FILE) up -d

down:
	docker-compose -f $(COMPOSE_FILE) down

restart:
	docker-compose -f $(COMPOSE_FILE) restart

logs:
	docker logs -f $(CONTAINER_NAME)

status:
	docker exec -it $(CONTAINER_NAME) fail2ban-client status

shell:
	docker exec -it $(CONTAINER_NAME) /bin/bash

test:
	@echo "[*] Simulating web brute force..."
	@for i in $$(seq 1 15); do \
		curl -s -o /dev/null -X POST http://localhost/login; \
	done
	@echo "[✓] Done — check logs via 'make logs'"

clean:
	-docker rm -f $(CONTAINER_NAME)
	-docker rmi $(IMAGE_NAME)
```
