# Centralized User Workstation Architecture

## Enhanced Architecture Diagram (Proposed) 

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               INTERNET                                         │
└─────────────────────────────────┬───────────────────────────────────────────────┘
                                  │ HTTPS
┌─────────────────────────────────▼───────────────────────────────────────────────┐
│                         AMBASSADOR EDGE STACK                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────────┐  │
│  │   JWT Minting   │    │  Auth Validation │    │     Rate Limiting        │  │
│  │   /auth/login   │    │   /auth/validate │    │   (per user/tier)        │  │
│  └─────────────────┘    └─────────────────┘    └─────────────────────────────┘  │
│                                  │                                              │
│  ┌─────────────────────────────────▼─────────────────────────────────────────┐  │
│  │                        ROUTING MAPPINGS                                   │  │
│  │  /api/challenges/* → challenge-controller                                 │  │
│  │  /workstation/{userID} → {userID}-workstation-service                     │  │
│  │  /challenge/{id}/* → {id}-challenge-service                               │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────────────┐
│                           ISTIO SERVICE MESH                                   │
│                              (mTLS + SPIRE)                                    │
└─────────────────────────────────┬───────────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┬─────────────────────┐
        │                         │                         │                     │
┌───────▼──────────┐    ┌─────────▼────────────┐    ┌──────▼──────────┐  ┌──────▼────────┐
│ project-x-infra  │    │ project-x-challenges │    │ project-x-users │  │ spire-system  │
│   namespace      │    │      namespace       │    │   namespace     │  │   namespace   │
│                  │    │                      │    │                 │  │               │
│ ┌──────────────┐ │    │ USER CHALLENGE ZONES:│    │ USER STATIONS:  │  │ ┌───────────┐ │
│ │ challenge-   │ │    │                      │    │                 │  │ │SPIRE Srvr │ │
│ │ controller   │ │    │ ┌─────────────────┐  │    │ ┌─────────────┐ │  │ │           │ │
│ │              │ │    │ │  Challenge A    │  │    │ │ Workstation │ │  │ │ Issues    │ │
│ │ - Creates    │ │    │ │  (user: alice)  │  │    │ │   alice     │ │  │ │ SVIDs for │ │
│ │ - Manages    │ │    │ │                 │  │    │ │             │ │  │ │ all pods  │ │
│ │ - Monitors   │ │    │ │ ┌─────────────┐ │  │    │ │ ┌─────────┐ │ │  │ └───────────┘ │
│ └──────────────┘ │    │ │ │ web-app     │ │  │    │ │ │Guacamole│ │ │  │               │
│                  │    │ │ │ (target)    │ │  │    │ │ │ Desktop │ │ │  │ ┌───────────┐ │
│ ┌──────────────┐ │    │ │ └─────────────┘ │  │    │ │ │         │ │ │  │ │SPIRE Agent│ │
│ │ auth-service │ │    │ └─────────────────┘  │    │ │ │- xterm  │ │ │  │ │(DaemonSet)│ │
│ │              │ │    │                      │    │ │ │- Firefox│ │ │  │ │           │ │
│ │ - Issues JWT │ │    │ ┌─────────────────┐  │    │ │ │- Tools  │ │ │  │ │ Workload  │ │
│ │ - Validates  │ │    │ │  Challenge B    │  │    │ │ └─────────┘ │ │  │ │ Attestor  │ │
│ └──────────────┘ │    │ │  (user: bob)    │  │    │ └─────────────┘ │  │ │ k8s+Docker│ │
│                  │    │ │                 │  │    │                 │  │ └───────────┘ │
│ ┌──────────────┐ │    │ │ ┌─────────────┐ │  │    │ ┌─────────────┐ │  └───────────────┘
│ │   Redis      │ │    │ │ │ database    │ │  │    │ │ Workstation │ │           │
│ │              │ │    │ │ │ (target)    │ │  │    │ │    bob      │ │           │
│ │ - Counters   │ │    │ │ └─────────────┘ │  │    │ │             │ │           │
│ │ - Session    │ │    │ └─────────────────┘  │    │ │ ┌─────────┐ │ │           │
│ │ - Rate Limit │ │    │                      │    │ │ │Guacamole│ │ │           │
│ └──────────────┘ │    │ ┌─────────────────┐  │    │ │ │ Desktop │ │ │           │
└──────────────────┘    │ │  Challenge C    │  │    │ │ │         │ │ │           │
                        │ │  (user: alice)  │  │    │ │ │- xterm  │ │ │           │
                        │ │                 │  │    │ │ │- Firefox│ │ │           │
                        │ │ ┌─────────────┐ │  │    │ │ │- Tools  │ │ │           │
                        │ │ │ admin-host  │ │  │    │ │ └─────────┘ │ │           │
                        │ │ │ (target)    │ │  │    │ └─────────────┘ │           │
                        │ │ └─────────────┘ │  │    └─────────────────┘           │
                        │ └─────────────────┘  │                                  │
                        └──────────────────────┘                                  │
                                  │                                               │
    ┌─────────────────────────────────────────────────────────────────────────────┘
    │
┌───▼──────────────────────────────────────────────────────────────────────────────┐
│                     ENHANCED NETWORK POLICIES                                   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │ User Workstation → User's Challenges (SSH, HTTP, all protocols)            │ │
│  │ Challenge Pods ← → Other Challenge Pods (same user only)                   │ │
│  │ Challenges isolated between different users                                 │ │
│  │ Workstations isolated between different users                               │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘

USER WORKFLOW:
1. User logs in → Gets JWT
2. Accesses /workstation/{userID} → Guacamole desktop loads
3. Inside desktop: uses terminal, browser, tools to access challenges
4. Creates challenges via API → Controller creates target pods
5. Workstation can SSH/HTTP to all user's active challenges
6. NetworkPolicies ensure isolation between users
```

## Implementation Details

### 1. Enhanced Challenge Controller with Workstation Management

```go
// pkg/controller/workstation.go
package controller

import (
    "context"
    "fmt"
    "time"
    
    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/api/resource"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/util/intstr"
)

type UserWorkstation struct {
    UserID          string
    Tier            string
    WorkstationID   string
    ActiveSince     time.Time
    LastActivity    time.Time
    ActiveChallenges []string
    Resources       WorkstationResources
}

type WorkstationResources struct {
    CPU       string
    Memory    string
    Storage   string
    GPUCount  int    // For advanced tiers
}

func (c *Controller) EnsureUserWorkstation(ctx context.Context, userID, tier string) (*UserWorkstation, error) {
    workstationID := fmt.Sprintf("ws-%s", userID)
    
    // Check if workstation already exists
    existing, err := c.getExistingWorkstation(ctx, userID)
    if err != nil {
        return nil, err
    }
    
    if existing != nil {
        // Update last activity and return existing
        existing.LastActivity = time.Now()
        return existing, c.updateWorkstationActivity(ctx, existing)
    }
    
    // Create new workstation
    workstation := &UserWorkstation{
        UserID:        userID,
        Tier:          tier,
        WorkstationID: workstationID,
        ActiveSince:   time.Now(),
        LastActivity:  time.Now(),
        Resources:     c.getWorkstationResourcesForTier(tier),
    }
    
    if err := c.createWorkstationPod(ctx, workstation); err != nil {
        return nil, err
    }
    
    if err := c.createWorkstationService(ctx, workstation); err != nil {
        return nil, err
    }
    
    if err := c.createWorkstationNetworkPolicies(ctx, workstation); err != nil {
        return nil, err
    }
    
    if err := c.registerWorkstationWithSpire(ctx, workstation); err != nil {
        return nil, err
    }
    
    if err := c.createIstioResourcesForWorkstation(ctx, workstation); err != nil {
        return nil, err
    }
    
    return workstation, nil
}

func (c *Controller) createWorkstationPod(ctx context.Context, ws *UserWorkstation) error {
    deployment := &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:      ws.WorkstationID,
            Namespace: "project-x-users",
            Labels: map[string]string{
                "app":                          "workstation",
                "project-x/user-id":           ws.UserID,
                "project-x/tier":              ws.Tier,
                "project-x/component":         "workstation",
                "spiffe.io/spire-managed-identity": "true",
            },
            Annotations: map[string]string{
                "spiffe.io/spiffeid": fmt.Sprintf("spiffe://%s/user/%s/workstation", 
                    c.config.TrustDomain, ws.UserID),
            },
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: int32Ptr(1),
            Selector: &metav1.LabelSelector{
                MatchLabels: map[string]string{
                    "project-x/user-id":    ws.UserID,
                    "project-x/component":  "workstation",
                },
            },
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels: map[string]string{
                        "app":                          "workstation",
                        "project-x/user-id":           ws.UserID,
                        "project-x/tier":              ws.Tier,
                        "project-x/component":         "workstation",
                        "spiffe.io/spire-managed-identity": "true",
                    },
                    Annotations: map[string]string{
                        "spiffe.io/spiffeid": fmt.Sprintf("spiffe://%s/user/%s/workstation", 
                            c.config.TrustDomain, ws.UserID),
                        "sidecar.istio.io/inject": "true",
                    },
                },
                Spec: corev1.PodSpec{
                    ServiceAccountName: "workstation-runner",
                    SecurityContext: &corev1.PodSecurityContext{
                        RunAsNonRoot: boolPtr(true),
                        RunAsUser:    int64Ptr(1001),
                        FSGroup:      int64Ptr(1001),
                    },
                    Containers: []corev1.Container{
                        {
                            Name:  "guacamole-desktop",
                            Image: fmt.Sprintf("%s/workstation-desktop:latest", 
                                c.config.ImageRegistryPerTier[ws.Tier]),
                            Ports: []corev1.ContainerPort{
                                {
                                    Name:          "guacamole",
                                    ContainerPort: 8080,
                                    Protocol:      corev1.ProtocolTCP,
                                },
                                {
                                    Name:          "vnc",
                                    ContainerPort: 5901,
                                    Protocol:      corev1.ProtocolTCP,
                                },
                                {
                                    Name:          "ssh",
                                    ContainerPort: 22,
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
                                    Name:  "USER_ID",
                                    Value: ws.UserID,
                                },
                                {
                                    Name:  "TIER", 
                                    Value: ws.Tier,
                                },
                                {
                                    Name:  "WORKSTATION_ID",
                                    Value: ws.WorkstationID,
                                },
                                {
                                    Name:  "VNC_PASSWORD",
                                    ValueFrom: &corev1.EnvVarSource{
                                        SecretKeyRef: &corev1.SecretKeySelector{
                                            LocalObjectReference: corev1.LocalObjectReference{
                                                Name: fmt.Sprintf("%s-workstation-secrets", ws.UserID),
                                            },
                                            Key: "vnc-password",
                                        },
                                    },
                                },
                                {
                                    Name:  "CHALLENGE_NAMESPACE",
                                    Value: "project-x-challenges",
                                },
                            },
                            Resources: corev1.ResourceRequirements{
                                Requests: corev1.ResourceList{
                                    corev1.ResourceCPU:    resource.MustParse(ws.Resources.CPU),
                                    corev1.ResourceMemory: resource.MustParse(ws.Resources.Memory),
                                },
                                Limits: corev1.ResourceList{
                                    corev1.ResourceCPU:    resource.MustParse(ws.Resources.CPU),
                                    corev1.ResourceMemory: resource.MustParse(ws.Resources.Memory),
                                },
                            },
                            SecurityContext: &corev1.SecurityContext{
                                AllowPrivilegeEscalation: boolPtr(false),
                                RunAsNonRoot:             boolPtr(true),
                                RunAsUser:                int64Ptr(1001),
                                ReadOnlyRootFilesystem:   boolPtr(false), // Desktop needs write access
                                Capabilities: &corev1.Capabilities{
                                    Drop: []corev1.Capability{"ALL"},
                                    Add:  []corev1.Capability{"SETGID", "SETUID"}, // Needed for VNC
                                },
                            },
                            VolumeMounts: []corev1.VolumeMount{
                                {
                                    Name:      "user-home",
                                    MountPath: "/home/ctf",
                                },
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
                                    Name:      "shared-tools",
                                    MountPath: "/opt/tools",
                                    ReadOnly:  true,
                                },
                            },
                            LivenessProbe: &corev1.Probe{
                                ProbeHandler: corev1.ProbeHandler{
                                    HTTPGet: &corev1.HTTPGetAction{
                                        Path: "/healthz",
                                        Port: intstr.FromInt(8080),
                                    },
                                },
                                InitialDelaySeconds: 30,
                                PeriodSeconds:       30,
                            },
                            ReadinessProbe: &corev1.Probe{
                                ProbeHandler: corev1.ProbeHandler{
                                    HTTPGet: &corev1.HTTPGetAction{
                                        Path: "/ready",
                                        Port: intstr.FromInt(8080),
                                    },
                                },
                                InitialDelaySeconds: 10,
                                PeriodSeconds:       10,
                            },
                        },
                    },
                    Volumes: []corev1.Volume{
                        {
                            Name: "user-home",
                            VolumeSource: corev1.VolumeSource{
                                PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
                                    ClaimName: fmt.Sprintf("%s-home", ws.UserID),
                                },
                            },
                        },
                        {
                            Name: "ssh-keys",
                            VolumeSource: corev1.VolumeSource{
                                Secret: &corev1.SecretVolumeSource{
                                    SecretName:  fmt.Sprintf("%s-ssh-keys", ws.UserID),
                                    DefaultMode: int32Ptr(0600),
                                },
                            },
                        },
                        {
                            Name: "tmp",
                            VolumeSource: corev1.VolumeSource{
                                EmptyDir: &corev1.EmptyDirVolumeSource{
                                    SizeLimit: resource.NewQuantity(1*1024*1024*1024, resource.BinarySI), // 1GB
                                },
                            },
                        },
                        {
                            Name: "shared-tools",
                            VolumeSource: corev1.VolumeSource{
                                ConfigMap: &corev1.ConfigMapVolumeSource{
                                    LocalObjectReference: corev1.LocalObjectReference{
                                        Name: "penetration-testing-tools",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }
    
    _, err := c.clientset.AppsV1().Deployments("project-x-users").
        Create(ctx, deployment, metav1.CreateOptions{})
    return err
}

func (c *Controller) getWorkstationResourcesForTier(tier string) WorkstationResources {
    switch tier {
    case "tier-1":
        return WorkstationResources{
            CPU:     "1000m",
            Memory:  "2Gi", 
            Storage: "10Gi",
        }
    case "tier-2":
        return WorkstationResources{
            CPU:     "2000m",
            Memory:  "4Gi",
            Storage: "20Gi",
        }
    case "tier-3":
        return WorkstationResources{
            CPU:     "4000m",
            Memory:  "8Gi",
            Storage: "50Gi",
            GPUCount: 1, // For ML/AI challenges
        }
    default:
        return WorkstationResources{
            CPU:     "500m",
            Memory:  "1Gi",
            Storage: "5Gi",
        }
    }
}
```

### 2. Workstation Desktop Container (Dockerfile)

```dockerfile
# Dockerfile for workstation-desktop
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install base packages
RUN apt-get update && apt-get install -y \
    # Desktop environment
    xfce4 xfce4-goodies \
    # VNC server
    tightvncserver \
    # Guacamole client tools
    guacd libguac-client-rdp0 libguac-client-ssh0 libguac-client-vnc0 \
    # Web server for Guacamole
    tomcat9 \
    # Penetration testing tools
    nmap \
    wireshark-gtk \
    burpsuite \
    sqlmap \
    metasploit-framework \
    john \
    hashcat \
    aircrack-ng \
    nikto \
    dirb \
    gobuster \
    hydra \
    # Network tools
    netcat-openbsd \
    socat \
    ssh \
    openssh-client \
    telnet \
    curl \
    wget \
    # Development tools
    git \
    vim \
    nano \
    python3 \
    python3-pip \
    nodejs \
    npm \
    # Browsers
    firefox \
    # Other utilities
    tmux \
    screen \
    htop \
    tree \
    file \
    binutils \
    strace \
    ltrace \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Install Guacamole
WORKDIR /opt
RUN wget https://downloads.apache.org/guacamole/1.5.3/binary/guacamole-1.5.3.war && \
    mv guacamole-1.5.3.war /var/lib/tomcat9/webapps/guacamole.war

# Create CTF user
RUN useradd -m -s /bin/bash -u 1001 ctf && \
    echo "ctf:ctfpassword" | chpasswd && \
    usermod -aG sudo ctf

# Configure VNC
USER ctf
WORKDIR /home/ctf

# VNC startup script
RUN mkdir -p ~/.vnc && \
    echo "#!/bin/bash" > ~/.vnc/xstartup && \
    echo "unset SESSION_MANAGER" >> ~/.vnc/xstartup && \
    echo "unset DBUS_SESSION_BUS_ADDRESS" >> ~/.vnc/xstartup && \
    echo "exec startxfce4" >> ~/.vnc/xstartup && \
    chmod +x ~/.vnc/xstartup

# Install Python penetration testing tools
RUN pip3 install --user \
    requests \
    beautifulsoup4 \
    scapy \
    pwntools \
    impacket \
    volatility3 \
    bloodhound \
    crackmapexec

# Create tools directory structure
RUN mkdir -p ~/tools/{web,network,crypto,forensics,reverse,misc}

# Copy custom configurations
COPY --chown=ctf:ctf configs/ /home/ctf/.config/

# Copy startup script
COPY scripts/start-workstation.sh /usr/local/bin/
RUN sudo chmod +x /usr/local/bin/start-workstation.sh

USER root

# Guacamole configuration
COPY guacamole/ /etc/guacamole/
RUN chown -R tomcat:tomcat /etc/guacamole/

# Health check script
COPY scripts/healthcheck.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/healthcheck.sh

# Expose ports
EXPOSE 8080 5901 22 9090

# Start services
CMD ["/usr/local/bin/start-workstation.sh"]
```

### 3. Startup Script for Workstation

```bash
#!/bin/bash
# scripts/start-workstation.sh

set -e

USER_ID=${USER_ID:-"default"}
TIER=${TIER:-"tier-1"}
VNC_PASSWORD=${VNC_PASSWORD:-"defaultpass"}

echo "Starting Project-X Workstation for user: $USER_ID (tier: $TIER)"

# Configure VNC password
su - ctf -c "echo '$VNC_PASSWORD' | vncpasswd -f > ~/.vnc/passwd"
su - ctf -c "chmod 600 ~/.vnc/passwd"

# Start VNC server
su - ctf -c "vncserver :1 -geometry 1920x1080 -depth 24"

# Configure Guacamole connection
cat > /etc/guacamole/user-mapping.xml << EOF
<user-mapping>
    <authorize username="$USER_ID" password="$VNC_PASSWORD">
        <connection name="Desktop">
            <protocol>vnc</protocol>
            <param name="hostname">localhost</param>
            <param name="port">5901</param>
            <param name="password">$VNC_PASSWORD</param>
        </connection>
    </authorize>
</user-mapping>
EOF

# Start Tomcat (Guacamole)
service tomcat9 start

# Start SSH server (for debugging/alternative access)
service ssh start

# Start Guacamole daemon
guacd -f

echo "Workstation started successfully"
echo "VNC: localhost:5901"
echo "Guacamole: http://localhost:8080/guacamole"
echo "SSH: localhost:22"

# Keep container running and monitor services
while true; do
    # Check if VNC is running
    if ! pgrep -f "Xvnc :1" > /dev/null; then
        echo "VNC server died, restarting..."
        su - ctf -c "vncserver :1 -geometry 1920x1080 -depth 24"
    fi
    
    # Check if Tomcat is running
    if ! pgrep -f "tomcat" > /dev/null; then
        echo "Tomcat died, restarting..."
        service tomcat9 restart
    fi
    
    # Check if Guacamole daemon is running  
    if ! pgrep -f "guacd" > /dev/null; then
        echo "Guacamole daemon died, restarting..."
        guacd -f &
    fi
    
    sleep 30
done
```

### 4. Enhanced NetworkPolicies for User Workstation

```yaml
# NetworkPolicy: User workstation access to their challenges
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: workstation-{userID}-to-challenges
  namespace: project-x-users
  labels:
    project-x/user-id: "{userID}"
    project-x/component: workstation-access
spec:
  podSelector:
    matchLabels:
      project-x/user-id: "{userID}"
      project-x/component: workstation
  policyTypes:
  - Egress
  
  egress:
  # Allow access to user's challenges in project-x-challenges namespace
  - to:
    - namespaceSelector:
        matchLabels:
          name: project-x-challenges
    - podSelector:
        matchLabels:
          project-x/user-id: "{userID}"
    ports:
    - protocol: TCP  # All TCP ports for flexibility
    - protocol: UDP  # All UDP ports for flexibility
    
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
      port: 15010
    - protocol: TCP
      port: 15011
    - protocol: TCP
      port: 15012

---
# NetworkPolicy: Allow workstation access FROM challenges (reverse connections)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: challenges-{userID}-to-workstation
  namespace: project-x-challenges
  labels:
    project-x/user-id: "{userID}"
    project-x/component: challenge-access
spec:
  podSelector:
    matchLabels:
      project-x/user-id: "{userID}"
  policyTypes:
  - Egress
  
  egress:
  # Allow reverse connections to user's workstation
  - to:
    - namespaceSelector:
        matchLabels:
          name: project-x-users  
    - podSelector:
        matchLabels:
          project-x/user-id: "{userID}"
          project-x/component: workstation
    ports:
    - protocol: TCP  # All TCP ports
    - protocol: UDP  # All UDP ports
    
  # Standard egress rules...
  - to:
    - podSelector:
        matchLabels:
          app: spire-agent
    ports:
    - protocol: TCP
      port: 8081

---
# NetworkPolicy: Isolate users from each other
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: user-isolation
  namespace: project-x-users
spec:
  podSelector: {}  # Apply to all pods in namespace
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Only allow ingress from Istio sidecar
  - from:
    - podSelector:
        matchLabels:
          app: istio-proxy
          
  # Only allow ingress from same user's pods
  - from:
    - podSelector:
        matchExpressions:
        - key: project-x/user-id
          operator: In
          values: ["$USER_ID"]  # This gets templated per user
          
  egress:
  # Standard egress rules (DNS, SPIRE, Istio)
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
  - to:
    - podSelector:
        matchLabels:
          app: spire-agent
  - to:
    - namespaceSelector:
        matchLabels:
          name: istio-system
```

### 5. Enhanced Istio Configuration for Workstations

```yaml
# VirtualService for workstation access
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: workstation-{userID}
  namespace: project-x-users
  labels:
    project-x/user-id: "{userID}"
    project-x/component: workstation
spec:
  hosts:
  - "workstation-{userID}.project-x.example.com"
  gateways:
  - project-x-gateway
  http:
  # Guacamole WebSocket connections
  - match:
    - uri:
        prefix: "/guacamole/websocket-tunnel"
    - headers:
        upgrade:
          exact: websocket
    route:
    - destination:
        host: "ws-{userID}.project-x-users.svc.cluster.local"
        port:
          number: 8080
    timeout: 7200s  # 2 hours for long desktop sessions
    
  # Guacamole HTTP routes
  - match:
    - uri:
        prefix: "/guacamole"
    route:
    - destination:
        host: "ws-{userID}.project-x-users.svc.cluster.local"
        port:
          number: 8080
    headers:
      response:
        add:
          X-Frame-Options: "SAMEORIGIN"
          Content-Security-Policy: "frame-ancestors 'self'"
          
  # Default route for workstation
  - match:
    - uri:
        prefix: "/"
    route:
    - destination:
        host: "ws-{userID}.project-x-users.svc.cluster.local"
        port:
          number: 8080

---
# AuthorizationPolicy for workstation access
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: workstation-{userID}-authz
  namespace: project-x-users
  labels:
    project-x/user-id: "{userID}"
    project-x/component: workstation
spec:
  selector:
    matchLabels:
      project-x/user-id: "{userID}"
      project-x/component: workstation
  action: ALLOW
  rules:
  # Allow access with valid user JWT
  - from:
    - source:
        principals:
        - "cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"
    when:
    - key: request.auth.claims.user_id
      values: ["{userID}"]
    - key: request.auth.claims.scope
      values: ["workstation_access", "challenge_access"]
      
  # Allow inter-pod communication from user's challenges
  - from:
    - source:
        principals:
        - "cluster.local/ns/project-x-challenges/sa/challenge-runner"
    when:
    - key: source.labels.project-x/user-id
      values: ["{userID}"]

---
# ServiceMonitor for workstation metrics
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: workstation-{userID}
  namespace: project-x-users
  labels:
    project-x/user-id: "{userID}"
    project-x/component: workstation
spec:
  selector:
    matchLabels:
      project-x/user-id: "{userID}"
      project-x/component: workstation
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
```

### 6. Updated Ambassador Mappings

```yaml
# Workstation access mapping
apiVersion: x.getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: workstation-access
  namespace: project-x-infra
spec:
  hostname: project-x.example.com
  prefix: /workstation/(.+)
  prefix_regex: true
  service: workstation-router.project-x-infra.svc.cluster.local:3000
  rewrite: "/workstation/${1}"
  timeout_ms: 7200000  # 2 hours for desktop sessions
  idle_timeout_ms: 600000  # 10 minutes idle
  
  # JWT validation for workstation access
  filters:
  - name: jwt
    jwt:
      issuer: "project-x.auth"
      jwksURI: "https://project-x.example.com/.well-known/jwks.json"
      audiences: ["project-x"]
      requiredClaims:
        scope: ["workstation_access"]
      authHeader: "authorization"
      cookie: "jwt"
      
  # Rate limiting per user
  - name: rate-limiting
    rateLimit:
      domain: project-x-workstation
      service: projectx-rate-limit
      descriptors:
      - key: "user_id"
        value: "%JWT_claim_user_id%"
        
  # WebSocket upgrade support for VNC/Guacamole
  upgrade_configs:
  - upgrade_type: websocket
    
  # CORS for workstation
  cors:
    origins: ["https://project-x.example.com"]
    methods: ["GET", "POST", "OPTIONS"]
    headers: ["Authorization", "Content-Type", "Upgrade", "Connection"]
    credentials: true
```

## Benefits of Centralized Workstation Approach

**🎯 Realistic Environment:**
- Users get persistent desktop with full browser, terminal, tools
- Can work on multiple challenges simultaneously
- Mimics real penetration testing workstation

**🚀 Better Resource Efficiency:**
- One workstation pod per user vs one terminal per challenge
- Persistent sessions across browser refreshes
- Shared tool installations

**🔒 Enhanced Security:**
- User isolation at namespace level
- NetworkPolicies ensure users can't access each other's environments
- SPIRE identity for all workstation communications

**📊 Improved Scalability:**
- Workstations can hibernate/scale down when inactive
- Challenge pods remain lightweight (no terminal overhead)
- Better resource utilization patterns

**🛠️ Enhanced User Experience:**
- Full desktop environment with GUI tools
- Persistent file system for user data
- Professional CTF workspace

