```
k3s-pt-cluster/
│── build/               # Docker container builds using runc & nerdctl
│   ├── base/            # Base images for services
│   ├── app1/            # Specific app container (e.g., vulnerable web app)
│   ├── app2/            # Another service (e.g., logging, DB, etc.)
│── cluster/             # Cluster setup scripts
│   ├── 01-init-k3s.sh   # Install & bootstrap K3s
│   ├── 02-deploy-apps.sh # Deploy apps & services in phases
│   ├── 03-set-users.sh  # Randomize user passwords
│   ├── k3s-config.yaml  # Base K3s configuration
│── manifests/           # Kubernetes manifests
│   ├── namespaces.yaml  # Namespaces for different environments
│   ├── app1-deploy.yaml # Deployment for a vulnerable app
│   ├── app2-deploy.yaml # Deployment for another service
│── users/               # User & password management
│   ├── generate-users.py # Script to randomize passwords
│   ├── user-list.yaml   # Static user config (optional)
│── networking/          # Networking configuration (CNI, firewall, etc.)
│   ├── cni-config.yaml  # Custom CNI setup
│   ├── firewall-rules.sh # Additional firewall rules
│── tools/               # Additional helper tools/scripts
│── README.md            # Documentation
│── Makefile             # Automate deployment tasks

```

.PHONY: setup build-cluster deploy-apps set-users clean

# High-level setup command
setup: build-cluster deploy-apps set-users

# Step 1: Initialize the K3s cluster
build-cluster:
	@echo "Initializing K3s cluster..."
	./cluster/01-init-k3s.sh

# Step 2: Deploy services in phases
deploy-apps:
	@echo "Deploying applications and services..."
	./cluster/02-deploy-apps.sh

# Step 3: Set up users & rotate passwords
set-users:
	@echo "Setting up users and generating passwords..."
	./cluster/03-set-users.sh

# Optional: Cleanup target (deletes cluster & resets)
clean:
	@echo "Tearing down cluster..."
	k3s-uninstall.sh || true
	rm -rf /var/lib/rancher/k3s


