
# How to Use the Docker Socket Protector Script (Beta Edition) 

## What is this script and why do I need it?

The Docker Socket Protector script helps secure your Docker environment by protecting the Docker socket, which is a common target for attackers. 
When containers have access to the Docker socket, they potentially can escape their isolation and gain control over your host system. 
This script creates multiple layers of protection without breaking your existing workflows.

## Prerequisites

Before using this script, you need:

- A Linux system with Docker installed and running
- Root/sudo access to your system
- Basic knowledge of Docker and Linux commands

## Simple Installation Guide

### Step 1: Download the script

```bash
curl -o docker-socket-protector.sh https://your-domain.com/docker-socket-protector.sh
chmod +x docker-socket-protector.sh
```

### Step 2: Run the installation command

```bash
sudo ./docker-socket-protector.sh install
```

This command will:
- Create a special user group for Docker socket access
- Set up a secure proxy for the Docker socket
- Configure security protections (AppArmor if available)
- Set up logging to track access attempts
- Create a maintenance service to keep protections active

### Step 3: Test your installation

```bash
sudo ./docker-socket-protector.sh test
```

This runs a series of tests to verify that the protections are working correctly.

### Step 4: Check the status

```bash
sudo ./docker-socket-protector.sh status
```

This shows you the current state of all protection mechanisms.

## Understanding What This Script Does

This script implements multiple security layers to protect your Docker environment:

1. **Restricted Access Control**: Creates a special group (`docker-socket-users`) that controls who can access Docker.

2. **Socket Proxy**: Creates a secure proxy socket (`/var/run/secure-docker.sock`) that provides a controlled access point to Docker.

3. **Security Policies**: When available, installs AppArmor profiles to add additional restrictions.

4. **Audit Logging**: Sets up logging so you can see who is accessing the Docker socket.

5. **Self-Healing**: Installs a maintenance service that automatically keeps the protections active, even after system reboots.

## How to Use the Protected Docker Environment

### Basic Docker Commands

After installation, use the secure socket by setting the `DOCKER_HOST` environment variable:

```bash
# Run a normal Docker command through the secure socket
DOCKER_HOST=unix:///var/run/secure-docker.sock docker ps

# Make this change permanent for your user
echo 'export DOCKER_HOST=unix:///var/run/secure-docker.sock' >> ~/.bashrc
source ~/.bashrc
```

### Giving Access to Other Users

To allow another user to access Docker:

```bash
# Add user to the docker-socket-users group
sudo usermod -aG docker-socket-users username

# The user will need to log out and back in for changes to take effect
```

### Running Containers That Need Docker Access

Instead of mounting the original Docker socket, mount the secure socket:

```bash
# UNSAFE way (don't do this anymore):
# docker run -v /var/run/docker.sock:/var/run/docker.sock my-image

# SECURE way:
docker run -v /var/run/secure-docker.sock:/var/run/docker.sock my-image
```

## Common Use Cases

### CI/CD Pipelines

Update your CI/CD configuration to use the secure socket:

```bash
# Jenkins pipeline example
pipeline {
    agent any
    environment {
        DOCKER_HOST = 'unix:///var/run/secure-docker.sock'
    }
    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp .'
            }
        }
    }
}
```

### Docker Compose

Update your docker-compose.yml files:

```yaml
version: '3'
services:
  app:
    image: my-app
    # If the service needs Docker access:
    volumes:
      - /var/run/secure-docker.sock:/var/run/docker.sock
```

### Kubernetes

If you're running Kubernetes components that need Docker access:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: docker-access-pod
spec:
  containers:
  - name: docker-container
    image: my-image
    volumeMounts:
    - name: docker-socket
      mountPath: /var/run/docker.sock
  volumes:
  - name: docker-socket
    hostPath:
      path: /var/run/secure-docker.sock
```

## Troubleshooting

### "Permission denied" when using Docker

This usually means the user isn't in the `docker-socket-users` group:

```bash
# Add the user to the group
sudo usermod -aG docker-socket-users $USER

# Log out and log back in, or run this command:
newgrp docker-socket-users
```

### Socket proxy stopped working

You can check the status and restart the protection:

```bash
# Check status
sudo ./docker-socket-protector.sh status

# Reinstall if needed
sudo ./docker-socket-protector.sh install
```

### Removing the protections

If you need to uninstall the protections:

```bash
sudo ./docker-socket-protector.sh uninstall
```

## Frequently Asked Questions

### Will this break my existing Docker setup?

No. The script creates a parallel secure access path without removing the original functionality. You just need to use the secure socket instead of the default one.

### How secure is this solution?

The script implements multiple security layers:
- Access control through Unix permissions
- Socket proxying with controlled access
- Mandatory access control with AppArmor (when available)
- Audit logging for security monitoring

This provides significant protection against common Docker socket attacks.

### Does this work with Docker Compose, Kubernetes, etc.?

Yes. Any tool that uses the Docker socket can work with this protection - you just need to configure it to use the secure socket path (`/var/run/secure-docker.sock`).

### Will this protect against ALL container escape techniques?

No security measure is 100% effective. This script focuses specifically on protecting the Docker socket, which is a common attack vector. You should still follow other container security best practices.

### Does this work in cloud environments?

Yes, the script works in any Linux environment with Docker installed, including cloud VMs. Just make sure you have root access to install it.

## Security Monitoring

To check who's accessing your Docker socket:

```bash
# View recent Docker socket access attempts
sudo ausearch -k docker_socket_access -ts recent

# Monitor access in real-time
sudo ausearch -k docker_socket_access -ts recent -f
```

