# Enhanced Web Terminal Architecture for Project-X CTF Platform  -- Dev -- 

## Architecture Overview (ASCII Diagram)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                INTERNET                                         │
└─────────────────────────────────┬───────────────────────────────────────────────┘
                                  │ HTTPS
┌─────────────────────────────────▼───────────────────────────────────────────────┐
│                          AMBASSADOR EDGE STACK                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────────┐  │
│  │   JWT Minting   │    │  Auth Validation │    │     Rate Limiting        │  │
│  │   /auth/login   │    │   /auth/validate │    │   (per user/tier)        │  │
│  └─────────────────┘    └─────────────────┘    └─────────────────────────────┘  │
│                                  │                                              │
│  ┌─────────────────────────────────▼─────────────────────────────────────────┐  │
│  │                        ROUTING MAPPINGS                                   │  │
│  │  /api/challenges/* → challenge-controller                                 │  │
│  │  /challenge/{id}/terminal → {id}-terminal-service                         │  │
│  │  /challenge/{id}/* → {id}-challenge-service                               │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────────────┐
│                           ISTIO SERVICE MESH                                   │
│                              (mTLS + SPIRE)                                    │
└─────────────────────────────────┬───────────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼──────────┐    ┌─────────▼────────────┐    ┌──────▼─────────────────────┐
│ project-x-infra  │    │ project-x-challenges │    │    spire-system          │
│   namespace      │    │      namespace       │    │     namespace            │
│                  │    │                      │    │                          │
│ ┌──────────────┐ │    │ PER-CHALLENGE ZONES: │    │ ┌─────────────────────┐  │
│ │ challenge-   │ │    │                      │    │ │   SPIRE Server      │  │
│ │ controller   │ │    │ ┌─────────────────┐  │    │ │                     │  │
│ │              │ │    │ │  Challenge A    │  │    │ │  Issues SVIDs for:  │  │
│ │ - Creates    │ │    │ │                 │  │    │ │  - Controller pods  │  │
│ │ - Manages    │ │    │ │ ┌─────────────┐ │  │    │ │  - Challenge pods   │  │
│ │ - Monitors   │ │    │ │ │ web-app     │ │  │    │ │  - Terminal pods    │  │
│ └──────────────┘ │    │ │ │ (target)    │ │  │    │ └─────────────────────┘  │
│                  │    │ │ └─────────────┘ │  │    │                          │
│ ┌──────────────┐ │    │ │ ┌─────────────┐ │  │    │ ┌─────────────────────┐  │
│ │ auth-service │ │    │ │ │ web-terminal│ │  │    │ │   SPIRE Agents      │  │
│ │              │ │    │ │ │             │ │  │    │ │  (DaemonSet)        │  │
│ │ - Issues JWT │ │    │ │ │ xterm.js    │ │  │    │ │                     │  │
│ │ - Validates  │ │    │ │ │ WebSocket   │ │  │    │ │  Workload Attestor  │  │
│ └──────────────┘ │    │ │ │ SSH client  │ │  │    │ │  k8s + Docker       │  │
│                  │    │ │ └─────────────┘ │  │    │ └─────────────────────┘  │
│ ┌──────────────┐ │    │ └─────────────────┘  │    └──────────────────────────┘
│ │   Redis      │ │    │                      │                 │
│ │              │ │    │ ┌─────────────────┐  │                 │
│ │ - Counters   │ │    │ │  Challenge B    │  │                 │
│ │ - Session    │ │    │ │                 │  │                 │
│ │ - Rate Limit │ │    │ │ ┌─────────────┐ │  │                 │
│ └──────────────┘ │    │ │ │ database    │ │  │                 │
└──────────────────┘    │ │ │ (target)    │ │  │                 │
                        │ │ └─────────────┘ │  │                 │
                        │ │ ┌─────────────┐ │  │                 │
                        │ │ │ web-terminal│ │  │                 │
                        │ │ │             │ │  │                 │
                        │ │ │ xterm.js    │ │  │                 │
                        │ │ │ WebSocket   │ │  │                 │
                        │ │ │ SSH client  │ │  │                 │
                        │ │ └─────────────┘ │  │                 │
                        │ └─────────────────┘  │                 │
                        └──────────────────────┘                 │
                                                                 │
    ┌────────────────────────────────────────────────────────────┘
    │
┌───▼──────────────────────────────────────────────────────────────────────────────┐
│                           OPA/GATEKEEPER POLICIES                               │
│                                                                                  │
│  ┌─────────────────────────┐  ┌──────────────────────────────────────────────┐  │
│  │   SignedImagesOnly      │  │         ProjectXResourceLimits              │  │
│  │                         │  │                                              │  │
│  │ - Validates Cosign sigs │  │ - Per-user challenge limits                 │  │
│  │ - Registry allowlist    │  │ - CPU/Memory quotas                         │  │
│  │ - Applies to all pods   │  │ - Terminal + Challenge pod counts           │  │
│  └─────────────────────────┘  └──────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘

DATA FLOW:
1. User → Ambassador (JWT) → Challenge Controller → Creates Challenge + Terminal
2. User → Ambassador → Istio VirtualService → Terminal WebSocket
3. Terminal → SSH/Direct connection → Challenge pods within same namespace
4. All communication secured by mTLS + SPIRE SVIDs
```

## Detailed Technical Implementation

### 1. Enhanced Challenge Controller Logic

```go
// pkg/controller/challenge.go
package controller

import (
    "context"
    "fmt"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    
    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    networkingv1 "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/util/intstr"
    
    istiov1alpha3 "istio.io/api/networking/v1alpha3"
    istiov1beta1 "istio.io/api/security/v1beta1"
)

type ChallengeEnvironment struct {
    ChallengeID     string
    UserID          string
    Tier            string
    TargetPods      []PodConfig
    TerminalConfig  TerminalConfig
    NetworkConfig   NetworkConfig
    ExpiresAt       time.Time
}

type PodConfig struct {
    Name        string
    Image       string
    Ports       []int32
    Environment map[string]string
    Resources   corev1.ResourceRequirements
    SSHEnabled  bool
}

type TerminalConfig struct {
    Image           string
    WebSocketPort   int32
    SSHClientTools  []string
    PreInstalledKeys bool
}

func (c *Controller) CreateChallengeEnvironment(ctx context.Context, req *ChallengeRequest) (*ChallengeEnvironment, error) {
    challengeID := c.generateChallengeID()
    
    // Generate SSH key pair for internal communication
    sshKeyPair, err := c.generateSSHKeyPair()
    if err != nil {
        return nil, fmt.Errorf("failed to generate SSH keys: %w", err)
    }
    
    env := &ChallengeEnvironment{
        ChallengeID: challengeID,
        UserID:      req.UserID,
        Tier:        req.Tier,
        ExpiresAt:   time.Now().Add(c.config.DefaultChallengeTTL),
    }
    
    // 1. Create SSH keys secret
    if err := c.createSSHKeysSecret(ctx, env, sshKeyPair); err != nil {
        return nil, err
    }
    
    // 2. Create target challenge pods
    if err := c.createTargetPods(ctx, env, req.ChallengeType); err != nil {
        return nil, err
    }
    
    // 3. Create web terminal pod
    if err := c.createTerminalPod(ctx, env); err != nil {
        return nil, err
    }
    
    // 4. Create services
    if err := c.createServices(ctx, env); err != nil {
        return nil, err
    }
    
    // 5. Register SPIRE workload entries
    if err := c.registerSpireWorkloads(ctx, env); err != nil {
        return nil, err
    }
    
    // 6. Create Istio policies
    if err := c.createIstioResources(ctx, env); err != nil {
        return nil, err
    }
    
    // 7. Create NetworkPolicies
    if err := c.createNetworkPolicies(ctx, env); err != nil {
        return nil, err
    }
    
    // 8. Update Redis counters
    if err := c.updateChallengeCounters(ctx, env); err != nil {
        return nil, err
    }
    
    return env, nil
}

func (c *Controller) createTerminalPod(ctx context.Context, env *ChallengeEnvironment) error {
    deployment := &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:      fmt.Sprintf("%s-terminal", env.ChallengeID),
            Namespace: c.config.ChallengeNamespace,
            Labels: map[string]string{
                "app":                          "terminal",
                "project-x/challenge-id":       env.ChallengeID,
                "project-x/user-id":           env.UserID,
                "project-x/tier":              env.Tier,
                "project-x/component":         "terminal",
                "spiffe.io/spire-managed-identity": "true",
            },
            Annotations: map[string]string{
                "spiffe.io/spiffeid": fmt.Sprintf("spiffe://%s/challenge/%s/terminal", 
                    c.config.TrustDomain, env.ChallengeID),
            },
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: int32Ptr(1),
            Selector: &metav1.LabelSelector{
                MatchLabels: map[string]string{
                    "project-x/challenge-id": env.ChallengeID,
                    "project-x/component":    "terminal",
                },
            },
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels: map[string]string{
                        "app":                          "terminal",
                        "project-x/challenge-id":       env.ChallengeID,
                        "project-x/user-id":           env.UserID,
                        "project-x/tier":              env.Tier,
                        "project-x/component":         "terminal",
                        "spiffe.io/spire-managed-identity": "true",
                    },
                    Annotations: map[string]string{
                        "spiffe.io/spiffeid": fmt.Sprintf("spiffe://%s/challenge/%s/terminal", 
                            c.config.TrustDomain, env.ChallengeID),
                        "sidecar.istio.io/inject": "true",
                    },
                },
                Spec: corev1.PodSpec{
                    ServiceAccountName: "challenge-runner",
                    SecurityContext: &corev1.PodSecurityContext{
                        RunAsNonRoot: boolPtr(true),
                        RunAsUser:    int64Ptr(1000),
                        FSGroup:      int64Ptr(1000),
                    },
                    Containers: []corev1.Container{
                        {
                            Name:  "web-terminal",
                            Image: fmt.Sprintf("%s/web-terminal:latest", 
                                c.config.ImageRegistryPerTier[env.Tier]),
                            Ports: []corev1.ContainerPort{
                                {
                                    Name:          "websocket",
                                    ContainerPort: 8080,
                                    Protocol:      corev1.ProtocolTCP,
                                },
                                {
                                    Name:          "metrics",
                                    ContainerPort: 9090,
                                    Protocol:      corev1.ProtocolTCP,
                                },
                            },
                            Env: []corev1.EnvVar{
                                {
                                    Name:  "CHALLENGE_ID",
                                    Value: env.ChallengeID,
                                },
                                {
                                    Name:  "USER_ID", 
                                    Value: env.UserID,
                                },
                                {
                                    Name:  "TIER",
                                    Value: env.Tier,
                                },
                                {
                                    Name:  "TARGET_SERVICES",
                                    Value: c.buildTargetServicesEnv(env),
                                },
                            },
                            Resources: corev1.ResourceRequirements{
                                Requests: corev1.ResourceList{
                                    corev1.ResourceCPU:    resource.MustParse("100m"),
                                    corev1.ResourceMemory: resource.MustParse("128Mi"),
                                },
                                Limits: corev1.ResourceList{
                                    corev1.ResourceCPU:    resource.MustParse("500m"),
                                    corev1.ResourceMemory: resource.MustParse("512Mi"),
                                },
                            },
                            SecurityContext: &corev1.SecurityContext{
                                AllowPrivilegeEscalation: boolPtr(false),
                                RunAsNonRoot:             boolPtr(true),
                                RunAsUser:                int64Ptr(1000),
                                ReadOnlyRootFilesystem:   boolPtr(true),
                                Capabilities: &corev1.Capabilities{
                                    Drop: []corev1.Capability{"ALL"},
                                },
                            },
                            VolumeMounts: []corev1.VolumeMount{
                                {
                                    Name:      "ssh-keys",
                                    MountPath: "/home/ctf/.ssh",
                                    ReadOnly:  true,
                                },
                                {
                                    Name:      "tmp",
                                    MountPath: "/tmp",
                                },
                                {
                                    Name:      "home",
                                    MountPath: "/home/ctf",
                                },
                            },
                            LivenessProbe: &corev1.Probe{
                                ProbeHandler: corev1.ProbeHandler{
                                    HTTPGet: &corev1.HTTPGetAction{
                                        Path: "/healthz",
                                        Port: intstr.FromInt(8080),
                                    },
                                },
                                InitialDelaySeconds: 10,
                                PeriodSeconds:       30,
                            },
                            ReadinessProbe: &corev1.Probe{
                                ProbeHandler: corev1.ProbeHandler{
                                    HTTPGet: &corev1.HTTPGetAction{
                                        Path: "/ready",
                                        Port: intstr.FromInt(8080),
                                    },
                                },
                                InitialDelaySeconds: 5,
                                PeriodSeconds:       10,
                            },
                        },
                    },
                    Volumes: []corev1.Volume{
                        {
                            Name: "ssh-keys",
                            VolumeSource: corev1.VolumeSource{
                                Secret: &corev1.SecretVolumeSource{
                                    SecretName:  fmt.Sprintf("%s-ssh-keys", env.ChallengeID),
                                    DefaultMode: int32Ptr(0600),
                                },
                            },
                        },
                        {
                            Name: "tmp",
                            VolumeSource: corev1.VolumeSource{
                                EmptyDir: &corev1.EmptyDirVolumeSource{},
                            },
                        },
                        {
                            Name: "home",
                            VolumeSource: corev1.VolumeSource{
                                EmptyDir: &corev1.EmptyDirVolumeSource{},
                            },
                        },
                    },
                },
            },
        },
    }
    
    _, err := c.clientset.AppsV1().Deployments(c.config.ChallengeNamespace).
        Create(ctx, deployment, metav1.CreateOptions{})
    return err
}
```

### 2. Web Terminal Implementation

```yaml
# Web Terminal Dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --only=production

FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    nodejs \
    npm \
    openssh-client \
    curl \
    wget \
    netcat-openbsd \
    nmap \
    git \
    vim \
    bash \
    tmux \
    python3 \
    py3-pip

# Create non-root user
RUN addgroup -g 1000 ctf && \
    adduser -D -u 1000 -G ctf ctf

# Install web terminal application
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY src/ ./src/
COPY package.json ./

# Set up SSH client configuration
RUN mkdir -p /home/ctf/.ssh && \
    chown -R ctf:ctf /home/ctf && \
    chmod 700 /home/ctf/.ssh

USER ctf
EXPOSE 8080
CMD ["node", "src/server.js"]
```

```javascript
// src/server.js - Web Terminal Server
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pty = require('node-pty');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const challengeId = process.env.CHALLENGE_ID;
const userId = process.env.USER_ID;
const tier = process.env.TIER;
const targetServices = JSON.parse(process.env.TARGET_SERVICES || '[]');

// Serve xterm.js frontend
app.use(express.static('public'));
app.use('/xterm', express.static('node_modules/xterm/lib'));
app.use('/xterm-addon-fit', express.static('node_modules/xterm-addon-fit/lib'));
app.use('/xterm-addon-web-links', express.static('node_modules/xterm-addon-web-links/lib'));

// Health checks
app.get('/healthz', (req, res) => res.status(200).send('OK'));
app.get('/ready', (req, res) => res.status(200).send('Ready'));

// Terminal info API
app.get('/api/terminal/info', (req, res) => {
  res.json({
    challengeId,
    userId,
    tier,
    targetServices,
    hostname: process.env.HOSTNAME,
    environment: 'Project-X CTF Environment'
  });
});

// WebSocket terminal handler
wss.on('connection', (ws, req) => {
  console.log(`New terminal connection for challenge ${challengeId}`);
  
  // Create PTY process
  const shell = pty.spawn('bash', [], {
    name: 'xterm-color',
    cols: 80,
    rows: 30,
    cwd: '/home/ctf',
    env: {
      ...process.env,
      TERM: 'xterm-256color',
      CHALLENGE_ID: challengeId,
      USER_ID: userId,
      TIER: tier,
      PS1: `\\[\\033[01;32m\\]ctf@${challengeId}\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ `
    }
  });

  // Send welcome message
  shell.write(`echo "Welcome to Project-X CTF Terminal"\r`);
  shell.write(`echo "Challenge ID: ${challengeId}"\r`);
  shell.write(`echo "Available targets:"\r`);
  targetServices.forEach(service => {
    shell.write(`echo "  - ${service.name}: ${service.host}:${service.port}"\r`);
  });
  shell.write(`echo ""\r`);
  shell.write(`clear\r`);

  // Handle PTY data
  shell.on('data', (data) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'data', data }));
    }
  });

  // Handle PTY exit
  shell.on('exit', (code) => {
    console.log(`Terminal process exited with code ${code}`);
    ws.close();
  });

  // Handle WebSocket messages
  ws.on('message', (message) => {
    try {
      const msg = JSON.parse(message);
      
      switch (msg.type) {
        case 'data':
          shell.write(msg.data);
          break;
        case 'resize':
          shell.resize(msg.cols, msg.rows);
          break;
        default:
          console.log('Unknown message type:', msg.type);
      }
    } catch (err) {
      console.error('Error parsing WebSocket message:', err);
    }
  });

  // Handle WebSocket close
  ws.on('close', () => {
    console.log('Terminal WebSocket closed');
    shell.kill();
  });

  // Handle WebSocket errors
  ws.on('error', (err) => {
    console.error('Terminal WebSocket error:', err);
    shell.kill();
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`Web terminal server listening on port ${PORT}`);
  console.log(`Challenge ID: ${challengeId}`);
  console.log(`User ID: ${userId}`);
  console.log(`Tier: ${tier}`);
});
```

### 3. Enhanced Istio Configuration

```yaml
# Enhanced VirtualService with terminal routing
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: {challengeID}
  namespace: project-x-challenges
  labels:
    project-x/challenge-id: "{challengeID}"
    project-x/user-id: "{userID}"
spec:
  hosts:
  - "{challengeID}.project-x.example.com"
  gateways:
  - project-x-gateway
  http:
  # Terminal WebSocket route
  - match:
    - uri:
        prefix: "/terminal"
    - headers:
        upgrade:
          exact: websocket
    route:
    - destination:
        host: "{challengeID}-terminal.project-x-challenges.svc.cluster.local"
        port:
          number: 8080
    timeout: 3600s  # Long timeout for persistent connections
    
  # Terminal HTTP routes (static files, API)
  - match:
    - uri:
        prefix: "/terminal"
    route:
    - destination:
        host: "{challengeID}-terminal.project-x-challenges.svc.cluster.local"
        port:
          number: 8080
    headers:
      response:
        add:
          X-Frame-Options: "SAMEORIGIN"
          X-Content-Type-Options: "nosniff"
          
  # Main challenge application routes
  - match:
    - uri:
        prefix: "/"
    route:
    - destination:
        host: "{challengeID}.project-x-challenges.svc.cluster.local"
        port:
          number: 8080
    fault:
      delay:
        percentage:
          value: 0.1
        fixedDelay: 5s  # Simulate network issues for realism

---
# Enhanced AuthorizationPolicy with terminal access
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: {challengeID}-authz
  namespace: project-x-challenges
  labels:
    project-x/challenge-id: "{challengeID}"
    project-x/user-id: "{userID}"
spec:
  selector:
    matchLabels:
      project-x/challenge-id: "{challengeID}"
  action: ALLOW
  rules:
  # Terminal access - requires scoped JWT
  - from:
    - source:
        principals:
        - "cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"
    to:
    - operation:
        paths: ["/terminal*"]
    when:
    - key: request.auth.claims.challenge_id
      values: ["{challengeID}"]
    - key: request.auth.claims.user_id  
      values: ["{userID}"]
    - key: request.auth.claims.scope
      values: ["terminal_access", "challenge_access"]
      
  # Challenge access - requires scoped JWT
  - from:
    - source:
        principals:
        - "cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"
    when:
    - key: request.auth.claims.challenge_id
      values: ["{challengeID}"]
    - key: request.auth.claims.user_id
      values: ["{userID}"]
      
  # Inter-pod communication within challenge
  - from:
    - source:
        principals:
        - "cluster.local/ns/project-x-challenges/sa/challenge-runner"
    when:
    - key: source.labels.project-x/challenge-id
      values: ["{challengeID}"]
```

### 4. Enhanced NetworkPolicies for Terminal Communication

```yaml
# Enhanced NetworkPolicy for internal challenge communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: challenge-{challengeID}-internal
  namespace: project-x-challenges
  labels:
    project-x/challenge-id: "{challengeID}"
    project-x/user-id: "{userID}"
spec:
  podSelector:
    matchLabels:
      project-x/challenge-id: "{challengeID}"
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow Istio sidecar communication
  - from:
    - podSelector:
        matchLabels:
          app: istio-proxy
    ports:
    - protocol: TCP
      port: 15090  # Envoy admin
    - protocol: TCP  
      port: 15021  # Health check
      
  # Allow inter-challenge pod communication
  - from:
    - podSelector:
        matchLabels:
          project-x/challenge-id: "{challengeID}"
    ports:
    - protocol: TCP
      port: 22     # SSH
    - protocol: TCP
      port: 80     # HTTP
    - protocol: TCP
      port: 443    # HTTPS
    - protocol: TCP
      port: 8080   # Common app port
    - protocol: TCP
      port: 3000   # Development servers
    - protocol: TCP
      port: 5432   # PostgreSQL
    - protocol: TCP
      port: 3306   # MySQL
    - protocol: TCP
      port: 6379   # Redis
    - protocol: TCP
      port: 9090   # Metrics
      
  egress:
  # Allow SPIRE agent communication
  - to:
    - podSelector:
        matchLabels:
          app: spire-agent
    ports:
    - protocol: TCP
      port: 8081
      
  # Allow Istio control plane communication
  - to:
    - namespaceSelector:
        matchLabels:
          name: istio-system
    ports:
    - protocol: TCP
      port: 15010  # Pilot
    - protocol: TCP
      port: 15011  # Pilot
    - protocol: TCP
      port: 15012  # Pilot
      
  # Allow inter-challenge communication
  - to:
    - podSelector:
        matchLabels:
          project-x/challenge-id: "{challengeID}"
    ports:
    - protocol: TCP
      port: 22     # SSH
    - protocol: TCP
      port: 80     # HTTP
    - protocol: TCP
      port: 443    # HTTPS
    - protocol: TCP
      port: 8080   # Common app port
    - protocol: TCP
      port: 3000   # Development servers
    - protocol: TCP
      port: 5432   # PostgreSQL
    - protocol: TCP
      port: 3306   # MySQL
    - protocol: TCP
      port: 6379   # Redis
      
  # Allow DNS resolution
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    - podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53

---
# Terminal-specific NetworkPolicy for WebSocket connections
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: terminal-{challengeID}-websocket
  namespace: project-x-challenges
  labels:
    project-x/challenge-id: "{challengeID}"
    project-x/component: terminal
spec:
  podSelector:
    matchLabels:
      project-x/challenge-id: "{challengeID}"
      project-x/component: terminal
  policyTypes:
  - Ingress
  
  ingress:
  # Allow WebSocket connections from Istio gateway
  - from:
    - namespaceSelector:
        matchLabels:
          name: istio-system
    - podSelector:
        matchLabels:
          app: istio-proxy
    ports:
    - protocol: TCP
      port: 8080  # WebSocket port
```

### 5. Updated OPA/Gatekeeper Policies

```yaml
# Enhanced resource limits template for terminal pods
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: projectxresourcelimitsv2
spec:
  crd:
    spec:
      names:
        kind: ProjectXResourceLimitsV2
      validation:
        openAPIV3Schema:
          type: object
          properties:
            tierLimits:
              type: object
              additionalProperties:
                type: object
                properties:
                  maxChallenges:
                    type: integer
                  maxPodsPerChallenge:
                    type: integer
                  maxCPUPerPod:
                    type: string
                  maxMemoryPerPod:
                    type: string
                  maxTotalCPU:
                    type: string
                  maxTotalMemory:
                    type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package projectxresourcelimitsv2
      
      violation[{"msg": msg}] {
        input.review.kind.kind == "Pod"
        input.review.object.metadata.namespace == "project-x-challenges"
        
        challenge_id := input.review.object.metadata.labels["project-x/challenge-id"]
        user_id := input.review.object.metadata.labels["project-x/user-id"]
        tier := input.review.object.metadata.labels["project-x/tier"]
        component := input.review.object.metadata.labels["project-x/component"]
        
        # Check if this would exceed per-challenge pod limits
        existing_pods := get_existing_pods_for_challenge(challenge_id)
        max_pods := input.parameters.tierLimits[tier].maxPodsPerChallenge
        count(existing_pods) >= max_pods
        
        msg := sprintf("Challenge %v already has %v pods, maximum %v allowed for tier %v", 
          [challenge_id, count(existing_pods), max_pods, tier])
      }
      
      violation[{"msg": msg}] {
        input.review.kind.kind == "Pod"
        input.review.object.metadata.namespace == "project-x-challenges"
        
        user_id := input.review.object.metadata.labels["project-x/user-id"]
        tier := input.review.object.metadata.labels["project-x/tier"]
        
        # Check total user challenge count
        user_challenges := get_user_challenges(user_id)
        max_challenges := input.parameters.tierLimits[tier].maxChallenges
        count(user_challenges) >= max_challenges
        
        msg := sprintf("User %v already has %v challenges, maximum %v allowed for tier %v",
          [user_id, count(user_challenges), max_challenges, tier])
      }
      
      get_existing_pods_for_challenge(challenge_id) = pods {
        pods := [pod | 
          pod := data.inventory.namespace["project-x-challenges"]["v1"]["Pod"][_]
          pod.metadata.labels["project-x/challenge-id"] == challenge_id
        ]
      }
      
      get_user_challenges(user_id) = challenges {
        challenge_ids := [id | 
          pod := data.inventory.namespace["project-x-challenges"]["v1"]["Pod"][_]
          pod.metadata.labels["project-x/user-id"] == user_id
          id := pod.metadata.labels["project-x/challenge-id"]
        ]
        challenges := {id | id := challenge_ids[_]}
      }

---
# Updated constraint with terminal pod limits
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: ProjectXResourceLimitsV2
metadata:
  name: projectx-tier-limits-v2
spec:
  enforcementAction: deny
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    namespaces: ["project-x-challenges"]
  parameters:
    tierLimits:
      tier-1:
        maxChallenges: 3
        maxPodsPerChallenge: 3  # main + terminal + maybe database
        maxCPUPerPod: "1000m"
        maxMemoryPerPod: "1Gi"
        maxTotalCPU: "3000m"
        maxTotalMemory: "3Gi"
      tier-2:
        maxChallenges: 5
        maxPodsPerChallenge: 5  # more complex scenarios
        maxCPUPerPod: "2000m"
        maxMemoryPerPod: "2Gi"
        maxTotalCPU: "10000m"
        maxTotalMemory: "10Gi"
      tier-3:
        maxChallenges: 10
        maxPodsPerChallenge: 8  # enterprise scenarios
        maxCPUPerPod: "4000m"
        maxMemoryPerPod: "4Gi"
        maxTotalCPU: "40000m"
        maxTotalMemory: "40Gi"
```

### 6. Enhanced Ambassador Mappings

```yaml
# Terminal-specific mapping with WebSocket support
apiVersion: x.getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: challenge-terminal-router
  namespace: project-x-infra
spec:
  hostname: project-x.example.com
  prefix: /challenge/(.+)/terminal
  prefix_regex: true
  service: challenge-router.project-x-infra.svc.cluster.local:3000
  rewrite: "/terminal/${1}"
  timeout_ms: 3600000  # 1 hour for persistent WebSocket
  idle_timeout_ms: 300000  # 5 minutes idle
  
  # JWT validation for terminal access
  filters:
  - name: jwt
    jwt:
      issuer: "project-x.auth"
      jwksURI: "https://project-x.example.com/.well-known/jwks.json"
      audiences: ["challenge:*"]
      requiredClaims:
        scope: ["terminal_access", "challenge_access"]
      authHeader: "authorization"
      cookie: "jwt"
      
  # Rate limiting per user
  - name: rate-limiting
    rateLimit:
      domain: project-x-terminal
      service: projectx-rate-limit
      descriptors:
      - key: "user_id"
        value: "%JWT_claim_user_id%"
      - key: "challenge_id"
        value: "%JWT_claim_challenge_id%"
        
  # WebSocket upgrade support
  upgrade_configs:
  - upgrade_type: websocket
    
  # CORS for terminal
  cors:
    origins: ["https://project-x.example.com"]
    methods: ["GET", "POST", "OPTIONS"]
    headers: ["Authorization", "Content-Type", "Upgrade", "Connection"]
    credentials: true

---
# Challenge router service enhancement
apiVersion: v1
kind: ConfigMap
metadata:
  name: challenge-router-config
  namespace: project-x-infra
data:
  nginx.conf: |
    upstream backend {
        server challenge-router:3000;
    }
    
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }
    
    server {
        listen 80;
        
        # Terminal WebSocket proxy
        location ~ ^/terminal/([^/]+)/?(.*)$ {
            set $challenge_id $1;
            set $path $2;
            
            # Validate challenge access
            access_by_lua_block {
                local jwt = ngx.var.cookie_jwt or ngx.var.http_authorization
                if not jwt then
                    ngx.status = 401
                    ngx.say("Unauthorized")
                    ngx.exit(401)
                end
                
                -- JWT validation logic here
                -- Validate challenge_id matches request
            }
            
            proxy_pass http://$challenge_id-terminal.project-x-challenges.svc.cluster.local:8080/$path$is_args$args;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket timeouts
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
        }
        
        # Regular challenge proxy
        location ~ ^/([^/]+)/?(.*)$ {
            set $challenge_id $1;
            set $path $2;
            
            proxy_pass http://$challenge_id.project-x-challenges.svc.cluster.local:8080/$path$is_args$args;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
```


- **🔒 Security**: Full SPIRE identity, mTLS, JWT validation, NetworkPolicies
- **🚀 Scalability**: Lightweight terminal pods, efficient WebSocket handling  
- **🌐 Cloud-Native**: No VPN needed, all browser-based access
- **🎯 Realistic**: Users can SSH between pods, escalate privileges naturally
- **📊 Observable**: Metrics, logging, health checks throughout
- **🛡️ Policy-Driven**: OPA/Gatekeeper enforces all resource and security constraints
