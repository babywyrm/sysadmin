
# 🚀 Modern Kubernetes Tools & CLI Utilities (2025 Edition)

A curated collection of essential tools to enhance your Kubernetes workflow, debugging, and development experience.

## 📋 Table of Contents

- [Core Productivity Tools](#core-productivity-tools)
- [Development & Debugging](#development--debugging)  
- [Monitoring & Observability](#monitoring--observability)
- [Security & Policy](#security--policy)
- [Networking & Connectivity](#networking--connectivity)
- [Resource Management](#resource-management)
- [GitOps & CD](#gitops--cd)
- [IDE & Editor Extensions](#ide--editor-extensions)
- [Installation Scripts](#installation-scripts)

---

## 🔧 Core Productivity Tools

### kubectx & kubens
Switch between clusters and namespaces effortlessly.

```bash
# Installation
brew install kubectx

# Switch contexts with fuzzy finder
kubectx

# Switch namespaces  
kubens

# Quick context switching
kubectx my-cluster
kubens my-namespace

# Previous context
kubectx -

# Interactive mode with fzf
kubectx --help
```

### k9s 🐕
Full-screen CLI dashboard for Kubernetes clusters.

```bash
# Installation
brew install k9s

# Launch dashboard
k9s

# Connect to specific context
k9s --context my-cluster

# Key shortcuts in k9s:
# :pods - view pods
# :svc - view services  
# :deploy - view deployments
# / - search/filter
# ? - help
```

### kubectl aliases & plugins
Enhance kubectl with shortcuts and powerful plugins.

```bash
# Install kubectl aliases
curl -Lo ~/.kubectl_aliases https://raw.githubusercontent.com/ahmetb/kubectl-aliases/master/.kubectl_aliases
echo 'source ~/.kubectl_aliases' >> ~/.zshrc

# Popular aliases:
# k = kubectl
# kgp = kubectl get pods
# kgs = kubectl get svc
# kgd = kubectl get deploy
# kdp = kubectl describe pod
# kaf = kubectl apply -f

# Install krew (plugin manager)
(
  set -x; cd "$(mktemp -d)" &&
  OS="$(uname | tr '[:upper:]' '[:lower:]')" &&
  ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" &&
  KREW="krew-${OS}_${ARCH}" &&
  curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" &&
  tar zxvf "${KREW}.tar.gz" &&
  ./"${KREW}" install krew
)
```

---

## 🔍 Development & Debugging

### stern
Enhanced multi-pod log streaming with powerful filtering.

```bash
# Installation  
brew install stern

# Tail all pods in namespace
stern . -n my-namespace

# Filter by app label
stern -l app=my-app

# Multiple containers
stern my-pod --all-namespaces

# Follow specific containers
stern my-pod -c container1,container2

# Output to file
stern my-pod > logs.txt

# JSON output
stern my-pod -o json

# Since timestamp
stern my-pod --since 1h
```

### kubefwd
Port forward multiple services simultaneously.

```bash
# Installation
brew install txn2/tap/kubefwd

# Forward all services in namespace (requires sudo)
sudo kubefwd services -n my-namespace

# Forward specific services
sudo kubefwd services -n my-namespace -l app=frontend

# With custom domain suffix
sudo kubefwd services -n my-namespace -d local.dev

# Docker alternative (no sudo required)
docker run -it --rm --privileged \
  -v "${HOME}/.kube/":/root/.kube/ \
  txn2/kubefwd services -n my-namespace
```

### telepresence
Local development against remote Kubernetes clusters.

```bash
# Installation  
curl -fL https://app.getambassador.io/download/tel2oss/releases/download/v2.18.0/telepresence-linux-amd64 -o telepresence
sudo install -o root -g root -m 0755 telepresence /usr/local/bin/telepresence

# Connect to cluster
telepresence connect

# Intercept a service
telepresence intercept my-service --port 8080

# Run local service that handles intercepted traffic  
./my-local-service

# List active intercepts
telepresence list

# Leave intercept
telepresence leave my-service
```

### skaffold
Continuous development workflow for Kubernetes applications.

```bash
# Installation
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64
sudo install skaffold /usr/local/bin/

# Initialize in project directory
skaffold init

# Continuous development
skaffold dev

# Build and deploy  
skaffold run

# Debug mode
skaffold debug

# Example skaffold.yaml
cat > skaffold.yaml << EOF
apiVersion: skaffold/v4beta9
kind: Config
build:
  artifacts:
  - image: my-app
    docker:
      dockerfile: Dockerfile
deploy:
  kubectl:
    manifests:
    - k8s-*.yaml
EOF
```

---

## 📊 Monitoring & Observability

### kubespy  
Real-time Kubernetes resource observation.

```bash
# Installation
brew install kubespy

# Watch deployment rollout
kubespy trace deployment my-app

# Monitor status changes
kubespy status deployment my-app -n my-namespace

# Watch changes as JSON diffs
kubespy changes service my-service

# Trace complex resources
kubespy trace ingress my-ingress
```

### kubectl-tree
Show hierarchical view of Kubernetes resources.

```bash
# Install via krew
kubectl krew install tree

# View resource hierarchy
kubectl tree deployment my-app

# Include all namespaces
kubectl tree deployment my-app --all-namespaces

# Show specific resource types
kubectl tree deploy,rs,po my-app
```

### popeye  
Kubernetes cluster sanitizer and linter.

```bash
# Installation
brew install popeye

# Scan entire cluster
popeye

# Scan specific namespace
popeye -n my-namespace

# Output formats
popeye -o yaml
popeye -o json
popeye -o html > report.html

# Custom configuration
cat > popeye.yaml << EOF
popeye:
  excludes:
    apps/v1/deployments:
      - name: "rx:my-deploy.*"
        codes: [400, 500]
EOF
popeye -f popeye.yaml
```

---

## 🔒 Security & Policy

### trivy
Vulnerability scanner for containers and Kubernetes.

```bash
# Installation
brew install trivy

# Scan container image  
trivy image nginx:latest

# Scan Kubernetes manifests
trivy config .

# Scan running cluster
trivy k8s cluster

# Scan specific namespace
trivy k8s --namespace kube-system all

# Export results
trivy k8s cluster --format json -o results.json
```

### hadolint
Dockerfile linter for best practices.

```bash
# Installation
brew install hadolint

# Lint Dockerfile
hadolint Dockerfile  

# Ignore specific rules
hadolint --ignore DL3008 Dockerfile

# JSON output
hadolint --format json Dockerfile

# Integration with CI
hadolint Dockerfile || exit 1
```

### falco
Runtime security monitoring for Kubernetes.

```bash
# Install via Helm
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco

# Custom rules example
cat > custom-rules.yaml << EOF
- rule: Suspicious Network Activity
  desc: Detect suspicious network connections
  condition: >
    k8s_audit and ka.verb=create and
    ka.uri.resource=pods
  output: >
    Suspicious pod creation (user=%ka.user.name pod=%ka.target.pod)
  priority: WARNING
EOF
```

---

## 🌐 Networking & Connectivity

### kubectl-neat
Clean up kubectl output by removing noise.

```bash
# Install via krew  
kubectl krew install neat

# Clean YAML output
kubectl get pod my-pod -o yaml | kubectl neat

# Clean and save
kubectl get deployment my-app -o yaml | kubectl neat > clean-deployment.yaml
```

### kubectl-port-forward-manager
Manage multiple port forwards easily.

```bash
# Install
go install github.com/knight42/kubectl-port-forward-manager@latest

# Create port forward configuration
cat > pf-config.yaml << EOF
forwards:
- name: api-server
  namespace: default
  resource: service/my-api
  ports:
  - 8080:80
- name: database  
  namespace: default
  resource: pod/postgres-0
  ports:
  - 5432:5432
EOF

# Start all forwards
kubectl port-forward-manager start -f pf-config.yaml
```

---

## 📈 Resource Management

### kube-capacity
Show resource usage and capacity across clusters.

```bash
# Install via krew
kubectl krew install resource-capacity

# View cluster capacity
kubectl resource-capacity

# Sort by usage
kubectl resource-capacity --sort cpu.util

# Specific namespace
kubectl resource-capacity --namespace kube-system

# Output formats
kubectl resource-capacity -o yaml
```

### kubectl-cost  
Kubernetes cost monitoring and optimization.

```bash
# Install via krew
kubectl krew install cost

# Get cost breakdown
kubectl cost namespace

# Cost by deployment
kubectl cost deployment

# Cost prediction
kubectl cost predict --replicas 5 deployment/my-app
```

### goldilocks
Resource recommendation tool.

```bash
# Install via Helm
helm repo add fairwinds-stable https://charts.fairwinds.com/stable
helm install goldilocks fairwinds-stable/goldilocks

# Enable namespace for monitoring  
kubectl label namespace my-namespace goldilocks.fairwinds.com/enabled=true

# Port forward dashboard
kubectl port-forward -n goldilocks service/goldilocks-dashboard 8080:80
```

---

## 🚀 GitOps & CD

### argocd CLI
Manage ArgoCD applications from command line.

```bash
# Installation
brew install argocd

# Login
argocd login argocd.example.com --username admin

# List applications
argocd app list

# Sync application  
argocd app sync my-app

# Get application details
argocd app get my-app

# Create application
argocd app create my-app \
  --repo https://github.com/my-org/my-app \
  --path k8s \
  --dest-server https://kubernetes.default.svc \
  --dest-namespace default
```

### flux CLI  
Manage Flux GitOps deployments.

```bash
# Installation
curl -s https://fluxcd.io/install.sh | sudo bash

# Bootstrap Flux on cluster
flux bootstrap github \
  --owner=my-org \
  --repository=my-fleet \
  --branch=main \
  --path=./clusters/my-cluster

# Check Flux components
flux check

# Create source
flux create source git my-app \
  --url=https://github.com/my-org/my-app \
  --branch=main

# Create kustomization
flux create kustomization my-app \
  --source=my-app \
  --path="./kustomize" \
  --prune=true
```

---

## 💻 IDE & Editor Extensions

### VS Code Extensions
Essential extensions for Kubernetes development:

```json
{
  "recommendations": [
    "ms-kubernetes-tools.vscode-kubernetes-tools",
    "redhat.vscode-yaml", 
    "ms-vscode.remote-containers",
    "GitLens.gitlens",
    "ms-azuretools.vscode-docker",
    "hashicorp.terraform",
    "ms-python.python",
    "golang.go",
    "bradlc.vscode-tailwindcss"
  ]
}
```

### Shell Configuration
Enhanced shell setup for Kubernetes:

```bash
# ~/.zshrc additions
# Kubectl completion
source <(kubectl completion zsh)

# Aliases
alias k='kubectl'
alias kgp='kubectl get pods'  
alias kgs='kubectl get svc'
alias kgd='kubectl get deployment'
alias kaf='kubectl apply -f'
alias kdf='kubectl delete -f'

# Functions
function kexec() {
  kubectl exec -it $1 -- ${2:-/bin/bash}
}

function klogs() {
  kubectl logs -f $1 ${2:+-c $2}
}

function kport() {
  kubectl port-forward $1 ${2:-8080}:${3:-80}
}

# Prompt enhancement with kube context
autoload -U colors && colors
PROMPT='%{$fg[cyan]%}($(kubectx -c))%{$reset_color%} '$PROMPT
```

---

## 🛠️ Installation Scripts

### One-Click Setup Script

```bash
#!/bin/bash
# install-k8s-tools.sh - Install essential Kubernetes tools

set -e

echo "🚀 Installing Kubernetes Tools..."

# Update package manager
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt update
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew update
fi

# Core tools
echo "📦 Installing core tools..."
brew_install() {
    if command -v brew &> /dev/null; then
        brew install $1
    else
        echo "❌ Homebrew not found. Please install manually: $1"
    fi
}

# Install tools
tools=(
    "kubectl"
    "kubectx" 
    "stern"
    "k9s"
    "helm"
    "skaffold"
    "popeye"
    "trivy"
    "hadolint" 
    "argocd"
    "fluxcd/tap/flux"
)

for tool in "${tools[@]}"; do
    echo "Installing $tool..."
    brew_install $tool
done

# Install kubectl plugins via krew
echo "🔌 Installing kubectl plugins..."
kubectl krew install tree
kubectl krew install neat  
kubectl krew install resource-capacity
kubectl krew install cost

# Setup aliases
echo "⚙️  Setting up aliases..."
curl -Lo ~/.kubectl_aliases https://raw.githubusercontent.com/ahmetb/kubectl-aliases/master/.kubectl_aliases

# Add to shell configuration
if [[ -f ~/.zshrc ]]; then
    echo 'source ~/.kubectl_aliases' >> ~/.zshrc
    echo 'source <(kubectl completion zsh)' >> ~/.zshrc
elif [[ -f ~/.bashrc ]]; then
    echo 'source ~/.kubectl_aliases' >> ~/.bashrc  
    echo 'source <(kubectl completion bash)' >> ~/.bashrc
fi

echo "✅ Installation complete!"
echo "🔄 Restart your shell or run: source ~/.zshrc"
```

### Tool Health Check Script

```bash
#!/bin/bash
# check-k8s-tools.sh - Verify tool installations

echo "🔍 Checking Kubernetes Tools..."

tools=(
    "kubectl:Kubernetes CLI"
    "kubectx:Context switcher"  
    "stern:Log streaming"
    "k9s:Cluster dashboard"
    "helm:Package manager"
    "skaffold:Development workflow"
    "popeye:Cluster sanitizer"
    "trivy:Security scanner"
    "argocd:GitOps CLI"
    "flux:GitOps toolkit"
)

for tool_info in "${tools[@]}"; do
    IFS=':' read -r tool desc <<< "$tool_info"
    if command -v $tool &> /dev/null; then
        version=$(eval "$tool version" 2>/dev/null | head -n1 || echo "unknown")
        echo "✅ $tool ($desc): $version"
    else
        echo "❌ $tool ($desc): Not installed"
    fi
done

echo ""
echo "📊 Kubernetes cluster info:"
if kubectl cluster-info &> /dev/null; then
    echo "✅ Connected to: $(kubectl config current-context)"
    echo "🏷️  Current namespace: $(kubectl config view --minify -o jsonpath='{..namespace}' 2>/dev/null || echo 'default')"
else
    echo "❌ No Kubernetes cluster connection"
fi
```

---

## 🎯 Usage Examples

### Daily Workflow Example

```bash
# Morning routine
kubectx production
kubens my-app
k9s  # Check cluster health

# Development workflow  
kubectx development
skaffold dev  # Start continuous development

# Debugging session
stern my-app -f  # Stream logs
kubectl tree deployment my-app  # Check resource hierarchy
popeye -n my-namespace  # Check for issues

# Security check
trivy k8s cluster --format table

# Cleanup
kubefwd services -n my-namespace  # Test connectivity
```

##
##



##
https://gist.github.com/yokawasa/26306126fe893285770c1c94c1571be8
##

# Kubernetes Tools

<!-- TOC -->

- [Kubernetes Tools](#kubernetes-tools)
    - [Links](#links)
    - [kubectx](#kubectx)
    - [stern](#stern)
    - [kubefwd](#kubefwd)
    - [kubespy](#kubespy)
    - [hadolint](#hadolint)

<!-- /TOC -->

## Links
- iterm2 / oh-my-zsh (theme: tangodark | [palenight](https://github.com/JonathanSpeek/palenight-iterm2))
- kubectl tab completion (`source <(kubectl completion zsh)`)
- VSCode + [GitLens](https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens) | [moonlight](https://marketplace.visualstudio.com/items?itemName=atomiks.moonlight) | [YAML](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml) |  
- skaffold
- kubectl plugins
  - [kube-capacity](https://github.com/robscott/kube-capacity)
  - [kubectl-plugin-ssh-jump](https://github.com/yokawasa/kubectl-plugin-ssh-jump)
  - [kubectl-fzf](https://github.com/bonnefoa/kubectl-fzf)

## kubectx
[kubectx](https://github.com/ahmetb/kubectx) is a commandline tool that allow you to switch between clusters and namespaces in kubectl easily & smoothly

```sh
# installation (Mac)
$ brew install kubectx

# how to switch contexts
$ kubectx [tab]
 <cluster1> <cluster2> <cluster3> ...
```

## stern
[stern](https://github.com/wercker/stern) is a commandline for multi pod and container log tailing for Kubernetes

```
# installation on MacOS
$ brew install stern

# Usage
## tail <podname> in namespace
## stern <podname> -n <namespace>
$ stern samplepod

+ samplepod-684ccd679f-nl252 › sample-pod-demo
samplepod-684ccd679f-nl252 sample-pod-demo o36e6ivtni@8ae3fca5-9b5c-471b-99d8-0eeb567c6acb
samplepod-684ccd679f-nl252 sample-pod-demo ===== table list =====
samplepod-684ccd679f-nl252 sample-pod-demo ('test',)
samplepod-684ccd679f-nl252 sample-pod-demo ===== Records =====
samplepod-684ccd679f-nl252 sample-pod-demo Id: 1 Content: hoge
samplepod-684ccd679f-nl252 sample-pod-demo Id: 2 Content: foo
samplepod-684ccd679f-nl252 sample-pod-demo Id: 3 Content: bar
```

## kubefwd
[kubefwd](https://github.com/txn2/kubefwd) is a command line utility built to port forward some or all pods within a Kubernetes namespace.

Installation on Mac
```sh
$ brew install txn2/tap/kubefwd
```

For other platform, use docker like this:
```sh
$ docker run -it --rm --privileged --name the-project \
    -v "$(echo $HOME)/.kube/":/root/.kube/ \
    txn2/kubefwd services -n the-project

$ docker exec the-project curl -s <target>
```

Here is how to use:
```sh
# For all services for default namespace
sudo kubefwd services
# For all services for a specific namespace
sudo kubefwd services -n <namespace>


 _          _           __             _
| | ___   _| |__   ___ / _|_      ____| |
| |/ / | | | '_ \ / _ \ |_\ \ /\ / / _  |
|   <| |_| | |_) |  __/  _|\ V  V / (_| |
|_|\_\\__,_|_.__/ \___|_|   \_/\_/ \__,_|

Press [Ctrl-C] to stop forwarding.
Loading hosts file /etc/hosts
Original hosts backup already exists at /etc/hosts.original
Forwarding local 127.1.27.1:443 as kubernetes:443 to pod mytimeds-m7sn9:443
Forwarding local 127.1.27.2:80 as party-clippy:80 to pod party-clippy-dc7448885-fbzj4:8080
```

Then, access party-clippy

```sh
curl party-clippy:80
```


## kubespy
kubespy is a commandline tool for observing Kubernetes resources in real time
- https://github.com/pulumi/kubespy

Here is a way to install kubespy
```sh
# install binary (`go install` didn't work on my env for some reason)

$ wget https://github.com/pulumi/kubespy/releases/download/v0.4.0/kubespy-darwin-368.tar.gz
$ tar zxvf kubespy-darwin-368.tar.gz
$ cp -p releases/kubespy-darwin-386/kubespy $PATH/
$ kubespy

Spy on your Kubernetes resources

Usage:
  kubespy [command]

Available Commands:
  changes     Displays changes made to a Kubernetes resource in real time. Emitted as JSON diffs
  help        Help about any command
  status      Displays changes to a Kubernetes resources's status in real time. Emitted as JSON diffs
  trace       Traces status of complex API objects
  version     Displays version information for this tool

Flags:
  -h, --help   help for kubespy

Use "kubespy [command] --help" for more information about a command.
```

## hadolint
[hadolint](https://github.com/hadolint/hadolint) is a smarter Dockerfile linter that helps you build best practice Docker images.

How to install
```sh
# Directly download binary
$ curl -L -O https://github.com/hadolint/hadolint/releases/download/v1.15.0/hadolint-Darwin-x86_64
$ ln -s hadolint-Darwin-x86_64 hadolint

# Install with brew on Mac
$ brew install hadolint

# Use docker container
$ docker pull hadolint/hadolint
```

How to Use 
```sh
$ cd azure-container-labs/apps/vote/azure-vote
# hadolint <Dockerfile>
$ hadolint Dockerfile

Dockerfile:3 DL3008 Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
Dockerfile:3 DL3009 Delete the apt-get lists after installing something
Dockerfile:3 DL3013 Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>`
Dockerfile:3 DL3015 Avoid additional packages by specifying `--no-install-recommends`
Dockerfile:7 DL3020 Use COPY instead of ADD for files and folders
```
For more detail, see [hadolint/hadolint](https://github.com/hadolint/hadolint)  
