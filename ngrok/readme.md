```
# Basic webhook.site test
python webhook_commander.py --webhook-site --requests 20 --concurrency 3

# Test custom endpoint with auth and export
python webhook_commander.py --url https://api.example.com/webhook --auth "user:pass" --requests 100 --export json

# Compare webhook.site vs custom endpoint
python webhook_commander.py --webhook-site --url https://your-ngrok-url.ngrok.app --requests 50 --concurrency 10

# Load test with large payloads
python webhook_commander.py --url https://api.example.com/webhook --payload-type large --payload-size 5 --requests 200 --rate-limit 10

# Complex payload with retries
python webhook_commander.py --webhook-site --payload-type complex --retry 2 --timeout 10 --export csv --output results.csv
```

# Ngrok Setup Guide for 2025 ..beta..

## Overview
Ngrok is a secure tunneling service that exposes local servers to the public internet. This guide covers modern setup and usage patterns for 2025.

## Quick Start

### Installation

| Platform | Installation Method |
|----------|-------------------|
| **macOS** | `brew install ngrok/ngrok/ngrok` |
| **Windows** | `choco install ngrok` or `winget install ngrok.ngrok` |
| **Linux (Ubuntu/Debian)** | `curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc \| sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \| sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok` |
| **Linux (RHEL/CentOS)** | `curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc \| sudo tee /etc/yum.repos.d/ngrok.repo >/dev/null && sudo yum install ngrok` |
| **Manual Install** | Download from https://ngrok.com/download |
| **Docker** | `docker run --net=host -it ngrok/ngrok:latest http 80` |

### Authentication Setup

1. **Sign up** at https://dashboard.ngrok.com/signup
2. **Get your authtoken** from https://dashboard.ngrok.com/get-started/your-authtoken
3. **Configure locally**:
   ```bash
   ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
   ```

## Basic Usage Examples

| Use Case | Command | Description |
|----------|---------|-------------|
| **HTTP Server** | `ngrok http 3000` | Expose local HTTP server on port 3000 |
| **HTTPS Server** | `ngrok http https://localhost:8443` | Expose local HTTPS server |
| **Custom Subdomain** | `ngrok http --domain=myapp.ngrok-free.app 3000` | Use reserved domain (paid plans) |
| **Basic Auth** | `ngrok http --basic-auth="user:password" 3000` | Add HTTP basic authentication |
| **Static Files** | `ngrok http file:///path/to/files` | Serve static files |
| **TCP Tunnel** | `ngrok tcp 22` | Expose SSH or other TCP services |
| **TLS Tunnel** | `ngrok tls 443` | Expose TLS/HTTPS services |

## Modern Configuration File Setup

Create `~/.ngrok2/ngrok.yml`:

```yaml
version: "2"
authtoken: YOUR_AUTHTOKEN_HERE

# Define reusable tunnel configurations
tunnels:
  # Development web server
  webapp:
    proto: http
    addr: 3000
    subdomain: myapp-dev
    auth: "admin:secret123"
    
  # API server with custom domain (paid plans)
  api:
    proto: http
    addr: 8080
    domain: api.mycompany.ngrok-free.app
    
  # Database tunnel
  database:
    proto: tcp
    addr: 5432
    
  # SSH access
  ssh:
    proto: tcp
    addr: 22

# Global settings
web_addr: localhost:4040
log_level: info
log_format: json
log: /var/log/ngrok.log
```

### Using Configuration File

```bash
# Start specific tunnel
ngrok start webapp

# Start multiple tunnels
ngrok start webapp api

# Start all tunnels
ngrok start --all
```

## Advanced Use Cases

### Docker Integration

**Dockerfile approach:**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

**Docker Compose with ngrok:**
```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    
  ngrok:
    image: ngrok/ngrok:latest
    restart: unless-stopped
    command:
      - "start"
      - "--all"
      - "--config"
      - "/etc/ngrok.yml"
    volumes:
      - ./ngrok.yml:/etc/ngrok.yml
    ports:
      - 4040:4040
    depends_on:
      - app
```

### Development Workflow Scripts

**Modern shell functions (add to `~/.bashrc` or `~/.zshrc`):**

```bash
# Quick HTTP tunnel with optional auth
expose() {
    local port=${1:-3000}
    local auth=${2:-}
    local domain=${3:-}
    
    local cmd="ngrok http $port"
    
    if [[ -n "$auth" ]]; then
        cmd="$cmd --basic-auth=$auth"
    fi
    
    if [[ -n "$domain" ]]; then
        cmd="$cmd --domain=$domain"
    fi
    
    echo "🚀 Exposing localhost:$port via ngrok..."
    eval $cmd
}

# Quick SSH tunnel
expose-ssh() {
    echo "🔒 Exposing SSH (port 22) via ngrok..."
    ngrok tcp 22
}

# Quick database tunnel
expose-db() {
    local port=${1:-5432}
    echo "🗄️ Exposing database on port $port via ngrok..."
    ngrok tcp $port
}

# Start predefined development environment
dev-tunnel() {
    echo "🛠️ Starting development tunnels..."
    ngrok start webapp api
}
```

### Usage examples:
```bash
# Basic HTTP tunnel
expose 3000

# HTTP tunnel with auth
expose 3000 "admin:password"

# HTTP tunnel with custom domain (paid)
expose 3000 "" "myapp.ngrok-free.app"

# SSH tunnel
expose-ssh

# Database tunnel
expose-db 5432
```

## Security Best Practices

| Practice | Implementation |
|----------|---------------|
| **Use Authentication** | Always add `--basic-auth` for sensitive applications |
| **Restrict Access** | Use `--cidr-allow` to limit IP ranges |
| **Monitor Usage** | Check ngrok web interface at http://localhost:4040 |
| **Environment Isolation** | Use different authtoken for production/staging |
| **Secure Credentials** | Store authtoken in environment variables |

**Example with security:**
```bash
# Secure tunnel with IP restriction and auth
ngrok http 3000 \
  --basic-auth="admin:$(openssl rand -base64 12)" \
  --cidr-allow="192.168.1.0/24"
```

## Modern Features (2025)

| Feature | Usage | Benefit |
|---------|-------|---------|
| **Edge Labels** | `ngrok http --label edge=my-edge 3000` | Traffic routing and management |
| **OAuth Integration** | `ngrok http --oauth=google 3000` | Use Google/GitHub for authentication |
| **Request Inspection** | Visit http://localhost:4040 | Debug webhooks and API calls |
| **Traffic Replay** | Web interface replay button | Test webhook handlers |
| **Custom Response Headers** | `ngrok http --response-header="X-Custom: value" 3000` | Add custom headers |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **"authtoken not found"** | Run `ngrok config add-authtoken YOUR_TOKEN` |
| **Port already in use** | Use different local port: `ngrok http 3001` |
| **Tunnel not accessible** | Check firewall settings and local server status |
| **Rate limits** | Upgrade to paid plan or reduce request frequency |
| **Config file errors** | Validate YAML syntax at https://yamlchecker.com |

## Free vs Paid Plans (2025)

| Feature | Free | Paid |
|---------|------|------|
| **Concurrent Tunnels** | 1 | Unlimited |
| **Custom Domains** | ❌ | ✅ |
| **Reserved Domains** | ❌ | ✅ |
| **IP Allowlist** | ❌ | ✅ |
| **Auth Providers** | Basic Auth | OAuth, SAML, etc. |
| **Bandwidth** | Limited | Unlimited |

## Quick Reference Commands

```bash
# Essential commands
ngrok http 3000                    # Basic HTTP tunnel
ngrok http --domain=custom.ngrok-free.app 3000  # Custom domain
ngrok tcp 22                       # TCP tunnel for SSH
ngrok start --all                  # All configured tunnels
ngrok config check                 # Validate configuration
ngrok diagnose                     # Network diagnostics
ngrok update                       # Update to latest version

# Inspection
curl http://localhost:4040/api/tunnels  # API to get tunnel info
```


### Additional Information
<http://nikhgupta.com/workflow/making-ngrok-work-with-pow-and-apache-exposing-localhost-domains-to-the-internet/><br>
<http://adrianartiles.com/webhook-testing-and-exposing-localhost-to-the-internet-with-ngrok><br>
<https://ngrok.com/><br>
<https://ngrok.com/dashboard><br>
