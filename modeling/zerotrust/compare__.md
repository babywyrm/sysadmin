
# **Security Layer Evolution: mTLS → SPIFFE/SPIRE → Istio → Falco/eBPF**  ..beta..
## Complete Stack Security Analysis in Kubernetes

---

## **Security Stack Overview: Layer-by-Layer Evolution**

```mermaid
graph TB
    subgraph "Application Layer (L7)"
        A1[HTTP/gRPC APIs]
        A2[Business Logic]
        A3[Authentication/Authorization]
    end
    
    subgraph "Service Mesh Layer (L4-L7)"
        SM1[Istio Control Plane]
        SM2[Envoy Sidecars]
        SM3[Traffic Management]
        SM4[Security Policies]
    end
    
    subgraph "Identity Layer"
        I1[SPIFFE/SPIRE]
        I2[Certificate Management]
        I3[Identity Attestation]
        I4[Trust Bundles]
    end
    
    subgraph "Transport Layer (L4)"
        T1[mTLS Connections]
        T2[Certificate Validation]
        T3[Encrypted Channels]
    end
    
    subgraph "Network Layer (L3)"
        N1[Network Policies]
        N2[CNI Plugin Security]
        N3[IP/Port Controls]
    end
    
    subgraph "Container Runtime (L2/L3)"
        C1[Container Isolation]
        C2[Namespace Boundaries]
        C3[cgroups/seccomp]
    end
    
    subgraph "Kernel/System Layer (L1/L2)"
        K1[Falco Runtime Security]
        K2[eBPF Monitoring]
        K3[System Call Filtering]
        K4[Kernel Security Modules]
    end
    
    A1 --> SM2
    SM1 --> I1
    SM2 --> T1
    T1 --> N1
    N1 --> C1
    C1 --> K1
    
    style I1 fill:#4ecdc4
    style K1 fill:#ff6b6b
    style SM1 fill:#45b7d1
    style T1 fill:#96ceb4
```

---

## **Security Evolution Comparison Matrix**

| **Layer** | **Basic K8s** | **+ mTLS** | **+ SPIFFE/SPIRE** | **+ Istio** | **+ Falco/eBPF** |
|-----------|---------------|------------|-------------------|-------------|------------------|
| **L7 - Application** | Basic auth tokens | Certificate-based auth | Workload identity verification | Policy-based access control | Application behavior monitoring |
| **L4 - Transport** | Plain TCP/HTTP | Encrypted TLS tunnels | Automatic cert rotation | Traffic encryption + routing | Connection anomaly detection |
| **L3 - Network** | Network policies | Encrypted packets | Identity-based routing | Service mesh networking | Network intrusion detection |
| **L2 - Container** | Pod isolation | Container-level certs | Workload attestation | Sidecar security | Runtime behavior analysis |
| **L1 - Kernel** | Basic isolation | Process security | Identity propagation | Enhanced isolation | System call monitoring |

---

## **Layer 1: Kernel/System Security with Falco + eBPF**

### **Without Enhanced Security**
```mermaid
graph LR
    subgraph "Basic Kernel Security"
        A[Process 1] --> B[System Calls]
        C[Process 2] --> B
        D[Process 3] --> B
        B --> E[Kernel]
        E --> F[File System]
        E --> G[Network]
        
        style B fill:#ffcccc
        style E fill:#ffcccc
    end
    
    H[Limited Visibility<br/>Basic Isolation<br/>No Runtime Monitoring]
    
    style H fill:#ff6b6b
```

### **With Falco + eBPF Enhanced Security**
```mermaid
graph LR
    subgraph "Enhanced Kernel Security"
        A[Pod Process] --> B[eBPF Probes]
        B --> C[System Call Monitoring]
        C --> D[Falco Rules Engine]
        D --> E[Security Events]
        E --> F[Alert/Block Actions]
        
        G[File Access] --> B
        H[Network Connections] --> B
        I[Process Execution] --> B
        
        style B fill:#51cf66
        style D fill:#51cf66
        style F fill:#4ecdc4
    end
    
    J[Complete Visibility<br/>Behavioral Analysis<br/>Real-time Protection]
    
    style J fill:#51cf66
```

### **Falco Rules for Microservices Security**
```yaml
# Falco rules for detecting suspicious activities in microservices
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules
  namespace: falco
data:
  microservices_rules.yaml: |
    - rule: Suspicious Container Network Activity
      desc: Detect unexpected network connections from containers
      condition: >
        spawned_process and container and
        (proc.name in (nc, ncat, netcat, socat, curl, wget) and
         not proc.args contains "healthcheck" and
         not proc.args contains "metrics")
      output: >
        Suspicious network tool executed in container
        (user=%user.name command=%proc.cmdline container=%container.name
         image=%container.image.repository:%container.image.tag)
      priority: WARNING
      tags: [network, mitre_lateral_movement]

    - rule: Unauthorized Process in Service Container
      desc: Detect unauthorized processes in microservice containers
      condition: >
        spawned_process and container and
        not proc.name in (java, node, python, gunicorn, nginx, envoy) and
        not proc.name startswith "istio-" and
        not proc.pname in (java, node, python, gunicorn)
      output: >
        Unauthorized process started in service container
        (user=%user.name command=%proc.cmdline container=%container.name
         image=%container.image.repository:%container.image.tag)
      priority: ERROR
      tags: [process, mitre_execution]

    - rule: Service Accessing Sensitive Files
      desc: Detect when services access sensitive system files
      condition: >
        open_read and container and
        (fd.name startswith "/etc/shadow" or
         fd.name startswith "/etc/passwd" or
         fd.name startswith "/root/" or
         fd.name startswith "/var/log/auth")
      output: >
        Service accessing sensitive files
        (file=%fd.name command=%proc.cmdline container=%container.name
         image=%container.image.repository:%container.image.tag)
      priority: CRITICAL
      tags: [filesystem, mitre_credential_access]
```

---

## **Layer 2-3: Container & Network Security Evolution**

### **Basic Container Networking**
```mermaid
graph TB
    subgraph "Traditional Container Network"
        subgraph "Pod A"
            A1[Container 1<br/>IP: 10.0.1.10]
            A2[Container 2<br/>IP: 10.0.1.10]
        end
        
        subgraph "Pod B" 
            B1[Container 3<br/>IP: 10.0.1.11]
        end
        
        A1 -.->|HTTP| B1
        A2 -.->|HTTP| B1
    end
    
    C[Network Security Gaps:<br/>• Plain text communication<br/>• IP-based trust<br/>• No identity verification<br/>• Limited visibility]
    
    style C fill:#ff6b6b
```

### **Enhanced with Network Policies + mTLS**
```mermaid
graph TB
    subgraph "Secured Container Network"
        subgraph "Namespace: Frontend"
            subgraph "Pod A"
                A1[API Container<br/>Cert: api-svc.crt<br/>Identity: spiffe://cluster/ns/frontend/sa/api]
                A1S[Envoy Sidecar<br/>mTLS Termination]
                A1 --- A1S
            end
        end
        
        subgraph "Namespace: Backend"
            subgraph "Pod B"
                B1[DB Container<br/>Cert: db-svc.crt<br/>Identity: spiffe://cluster/ns/backend/sa/database]
                B1S[Envoy Sidecar<br/>mTLS Termination]
                B1 --- B1S
            end
        end
        
        A1S -.->|mTLS Encrypted| B1S
        NP[Network Policy:<br/>Only frontend → backend<br/>Port 5432 only]
        
        style A1S fill:#51cf66
        style B1S fill:#51cf66
        style NP fill:#4ecdc4
    end
```

### **Network Policy with Identity-Based Rules**
```yaml
# Network policy enhanced with service identity
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: identity-based-policy
  namespace: backend
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    # Only allow traffic from pods with specific service account
    - namespaceSelector:
        matchLabels:
          name: frontend
      podSelector:
        matchLabels:
          service-identity: "spiffe://cluster.local/ns/frontend/sa/api"
    ports:
    - protocol: TCP
      port: 5432
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow metrics to monitoring namespace
  - to:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090

---
# Cilium-based identity-aware network policy
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: service-identity-policy
  namespace: backend
spec:
  endpointSelector:
    matchLabels:
      app: database
  ingress:
  - fromEndpoints:
    - matchLabels:
        "spiffe.io/spiffe-id": "spiffe://cluster.local/ns/frontend/sa/api"
    toPorts:
    - ports:
      - port: "5432"
        protocol: TCP
      rules:
        http:
        - method: "POST"
          path: "/api/query"
        - method: "GET" 
          path: "/health"
```

---

## **Layer 4: Transport Security Evolution**

### **mTLS Certificate Lifecycle with SPIFFE/SPIRE**
```mermaid
sequenceDiagram
    participant W as Workload
    participant SA as SPIRE Agent
    participant SS as SPIRE Server
    participant CA as Root CA
    
    Note over W,CA: Workload Bootstrap Process
    
    W->>SA: 1. Request SVID (Workload API)
    SA->>SS: 2. Node Attestation + CSR
    SS->>CA: 3. Validate Node Identity
    CA-->>SS: 4. Node Certificate
    SS->>SA: 5. Node SVID Issued
    
    Note over W,CA: Workload Identity Attestation
    
    SA->>W: 6. Request Workload Attestation
    W->>SA: 7. Provide K8s Service Account Token
    SA->>SS: 8. Workload Attestation + CSR
    SS->>SS: 9. Validate Against Registration Policies
    SS->>CA: 10. Sign Workload Certificate
    CA-->>SS: 11. Workload Certificate
    SS->>SA: 12. Workload SVID
    SA->>W: 13. Deliver X.509-SVID + JWT-SVID
    
    Note over W,CA: Automatic Rotation (Every 1 hour)
    
    loop Every Hour
        SA->>SS: Automatic Renewal Request
        SS->>CA: Sign New Certificate
        CA-->>SS: New Certificate
        SS->>SA: New SVID
        SA->>W: Hot Reload Certificate
    end
```

### **SPIRE Architecture in Kubernetes**
```mermaid
graph TB
    subgraph "SPIRE Infrastructure"
        subgraph "Control Plane"
            SS[SPIRE Server<br/>• Identity Registry<br/>• Certificate Authority<br/>• Policy Engine]
            DB[(SPIRE Database<br/>Registration Data)]
            SS --> DB
        end
        
        subgraph "Data Plane"
            SA1[SPIRE Agent<br/>Node 1]
            SA2[SPIRE Agent<br/>Node 2]
            SA3[SPIRE Agent<br/>Node 3]
        end
        
        SS -.->|Secure Bootstrap| SA1
        SS -.->|Secure Bootstrap| SA2
        SS -.->|Secure Bootstrap| SA3
    end
    
    subgraph "Workloads"
        subgraph "Node 1"
            W1[Pod A<br/>Identity: spiffe://cluster/ns/prod/sa/api]
            W2[Pod B<br/>Identity: spiffe://cluster/ns/prod/sa/web]
        end
        
        subgraph "Node 2"
            W3[Pod C<br/>Identity: spiffe://cluster/ns/prod/sa/db]
            W4[Pod D<br/>Identity: spiffe://cluster/ns/prod/sa/cache]
        end
        
        subgraph "Node 3"
            W5[Pod E<br/>Identity: spiffe://cluster/ns/test/sa/api]
        end
    end
    
    SA1 -.->|Issue SVIDs| W1
    SA1 -.->|Issue SVIDs| W2
    SA2 -.->|Issue SVIDs| W3
    SA2 -.->|Issue SVIDs| W4
    SA3 -.->|Issue SVIDs| W5
    
    style SS fill:#4ecdc4
    style SA1 fill:#51cf66
    style SA2 fill:#51cf66
    style SA3 fill:#51cf66
```

### **Certificate Comparison: Manual vs SPIFFE/SPIRE**
```mermaid
graph TB
    subgraph "Manual Certificate Management"
        M1[Generate CSR] --> M2[Manual CA Signing]
        M2 --> M3[Deploy Certificate]
        M3 --> M4[Manual Rotation]
        M4 --> M5{Certificate Expired?}
        M5 -->|Yes| M6[Service Downtime]
        M5 -->|No| M7[Manual Monitoring]
        M7 --> M4
        
        style M6 fill:#ff6b6b
        style M2 fill:#ffeb3b
        style M4 fill:#ffeb3b
    end
    
    subgraph "SPIFFE/SPIRE Automated Management"
        S1[Workload Attestation] --> S2[Automatic SVID Issuance]
        S2 --> S3[Continuous Validation]
        S3 --> S4[Automatic Rotation]
        S4 --> S5{Health Check}
        S5 -->|Healthy| S6[Zero Downtime]
        S5 -->|Issues| S7[Automatic Remediation]
        S7 --> S3
        S6 --> S3
        
        style S6 fill:#51cf66
        style S2 fill:#51cf66
        style S4 fill:#51cf66
        style S7 fill:#51cf66
    end
```

---

## **Layer 5-6: Istio Service Mesh Integration**

### **Complete Service Mesh Security Stack**
```mermaid
graph TB
    subgraph "Istio Service Mesh Architecture"
        subgraph "Control Plane"
            IC[Istiod<br/>• Certificate Authority<br/>• Configuration Management<br/>• Service Discovery]
            SPIRE[SPIRE Server<br/>• Root Identity Provider<br/>• Certificate Authority<br/>• Trust Bundle Distribution]
            
            IC -.->|Federation| SPIRE
        end
        
        subgraph "Data Plane - Pod 1"
            APP1[Application<br/>Port: 8080]
            ENVOY1[Envoy Proxy<br/>• mTLS Termination<br/>• Policy Enforcement<br/>• Observability]
            APP1 --- ENVOY1
        end
        
        subgraph "Data Plane - Pod 2"
            APP2[Application<br/>Port: 8080]
            ENVOY2[Envoy Proxy<br/>• mTLS Termination<br/>• Policy Enforcement<br/>• Observability]
            APP2 --- ENVOY2
        end
        
        IC -.->|Config + Certs| ENVOY1
        IC -.->|Config + Certs| ENVOY2
        ENVOY1 -.->|mTLS| ENVOY2
        
        style SPIRE fill:#4ecdc4
        style IC fill:#45b7d1
        style ENVOY1 fill:#96ceb4
        style ENVOY2 fill:#96ceb4
    end
```

### **Security Policy Evolution**
```yaml
# Basic Istio Security
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT

---
# Enhanced with SPIFFE Integration
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: spiffe-enhanced
  namespace: production
spec:
  mtls:
    mode: STRICT
  selector:
    matchLabels:
      app: payment-service
  # Use SPIFFE-issued certificates
  portLevelMtls:
    8080:
      mode: STRICT

---
# Advanced Authorization with SPIFFE Identities
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: spiffe-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  rules:
  - from:
    - source:
        # SPIFFE-based identity verification
        principals: 
        - "spiffe://cluster.local/ns/production/sa/order-service"
        - "spiffe://cluster.local/ns/production/sa/billing-service"
  - to:
    - operation:
        methods: ["POST", "GET"]
        paths: ["/api/v1/payment/*"]
  - when:
    # Additional context-aware conditions
    - key: source.certificate_fingerprint
      values: ["sha256:a1b2c3d4..."]
    - key: source.certificate_subject
      values: ["CN=order-service.production.cluster.local"]
    - key: request.headers[x-request-id]
      notValues: [""]

---
# Runtime Security Integration with Falco
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: falco-integration
  namespace: production
spec:
  selector:
    matchLabels:
      app: database
  rules:
  - from:
    - source:
        principals: ["spiffe://cluster.local/ns/production/sa/api-service"]
  - when:
    # Block requests from workloads flagged by Falco
    - key: custom.falco_risk_score
      values: ["low", "medium"]
    # Deny access if Falco detected suspicious activity
    - key: custom.falco_alert
      notValues: ["high", "critical"]
```

---

## **Layer 7: Application Security with Complete Observability**

### **Complete Security Telemetry Pipeline**
```mermaid
graph TB
    subgraph "Application Layer"
        APP[Microservice<br/>Business Logic]
        AUTH[Auth Middleware<br/>JWT + RBAC]
        APP --> AUTH
    end
    
    subgraph "Service Mesh Layer"
        ENVOY[Envoy Sidecar<br/>L7 Proxy]
        POL[Security Policies<br/>AuthZ + AuthN]
        ENVOY --> POL
    end
    
    subgraph "Identity Layer"
        SPIRE[SPIRE Agent<br/>Identity Provider]
        CERT[X.509 Certificates<br/>Auto-rotation]
        SPIRE --> CERT
    end
    
    subgraph "Runtime Security"
        FALCO[Falco<br/>Behavior Analysis]
        EBPF[eBPF Probes<br/>Kernel Events]
        FALCO --> EBPF
    end
    
    subgraph "Observability"
        METRICS[Prometheus<br/>Security Metrics]
        LOGS[Fluentd<br/>Centralized Logging]
        TRACES[Jaeger<br/>Distributed Tracing]
        
        METRICS --> DASH[Grafana Dashboard]
        LOGS --> SIEM[SIEM Analysis]
        TRACES --> TOPO[Service Topology]
    end
    
    AUTH -.->|Auth Events| LOGS
    POL -.->|Policy Decisions| METRICS
    CERT -.->|Cert Lifecycle| LOGS
    FALCO -.->|Security Alerts| SIEM
    ENVOY -.->|Access Logs| TRACES
    
    style FALCO fill:#ff6b6b
    style SPIRE fill:#4ecdc4
    style ENVOY fill:#96ceb4
    style SIEM fill:#ffa726
```

### **Complete Security Configuration Example**
```yaml
# Application with complete security stack
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-microservice
  namespace: production
  labels:
    app: payment-service
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-service
  template:
    metadata:
      labels:
        app: payment-service
        version: v1
      annotations:
        # Enable Istio sidecar injection
        sidecar.istio.io/inject: "true"
        # SPIFFE identity
        spiffe.io/spiffe-id: "spiffe://cluster.local/ns/production/sa/payment-service"
        # Falco monitoring annotations
        falco.org/monitor: "true"
        falco.org/rules: "payment-service-rules"
    spec:
      serviceAccountName: payment-service
      securityContext:
        # Pod-level security context
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 2001
        fsGroup: 3001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: payment-service
        image: myapp/payment-service:v1.2.3
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        securityContext:
          # Container-level security
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        # Resource limits for security
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        # Health checks
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        # Environment variables for security
        env:
        - name: ENABLE_MTLS
          value: "true"
        - name: SPIFFE_ENDPOINT_SOCKET
          value: "unix:///run/spire/sockets/agent.sock"
        - name: LOG_LEVEL
          value: "INFO"
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /run/spire/sockets
          readOnly: true
        - name: tmp-volume
          mountPath: /tmp
        - name: cache-volume
          mountPath: /app/cache
      volumes:
      - name: spire-agent-socket
        hostPath:
          path: /run/spire/sockets
          type: Directory
      - name: tmp-volume
        emptyDir: {}
      - name: cache-volume
        emptyDir: {}

---
# Service for the deployment
apiVersion: v1
kind: Service
metadata:
  name: payment-service
  namespace: production
  labels:
    app: payment-service
spec:
  selector:
    app: payment-service
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090

---
# ServiceMonitor for Prometheus scraping
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: payment-service-metrics
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  endpoints:
  - port: metrics
    interval: 15s
    path: /metrics
    scheme: http
```

---

## **Security Improvement Matrix: Before vs After**

### **Threat Mitigation Comparison**
```mermaid
graph TB
    subgraph "Threat Landscape"
        T1[Man-in-the-Middle]
        T2[Service Spoofing]  
        T3[Lateral Movement]
        T4[Credential Theft]
        T5[Runtime Attacks]
        T6[Data Exfiltration]
        T7[Privilege Escalation]
        T8[Supply Chain Attacks]
    end
    
    subgraph "Basic K8s (Minimal Protection)"
        B1[Network Policies Only]
        B2[Basic RBAC]
        B3[Container Isolation]
        
        T1 -.->|Vulnerable| B1
        T2 -.->|Vulnerable| B2
        T3 -.->|Partially Protected| B1
        T4 -.->|Vulnerable| B2
        T5 -.->|Minimal Protection| B3
        T6 -.->|Vulnerable| B1
        T7 -.->|Partially Protected| B2
        T8 -.->|Vulnerable| B3
    end
    
    subgraph "Complete Security Stack (Strong Protection)"
        S1[mTLS + SPIFFE/SPIRE]
        S2[Istio Service Mesh]
        S3[Falco + eBPF]
        S4[Zero Trust Policies]
        
        T1 -.->|Mitigated| S1
        T2 -.->|Mitigated| S1
        T3 -.->|Strongly Mitigated| S2
        T4 -.->|Mitigated| S1
        T5 -.->|Detected & Blocked| S3
        T6 -.->|Monitored & Alerted| S3
        T7 -.->|Prevented| S4
        T8 -.->|Detected| S3
    end
    
    style B1 fill:#ff6b6b
    style B2 fill:#ff6b6b
    style B3 fill:#ff6b6b
    style S1 fill:#51cf66
    style S2 fill:#51cf66
    style S3 fill:#51cf66
    style S4 fill:#51cf66
```

### **Security Metrics Improvement**
| **Security Aspect** | **Basic K8s** | **+ mTLS** | **+ SPIFFE/SPIRE** | **+ Istio** | **+ Falco/eBPF** |
|---------------------|---------------|------------|-------------------|-------------|------------------|
| **Identity Verification** | 30% | 70% | 95% | 95% | 95% |
| **Data Encryption** | 20% | 90% | 95% | 95% | 95% |
| **Access Control** | 40% | 60% | 80% | 95% | 95% |
| **Threat Detection** | 10% | 15% | 20% | 40% | 95% |
| **Incident Response** | 20% | 25% | 30% | 50% | 90% |
| **Compliance** | 30% | 60% | 80% | 85% | 95% |
| **Runtime Protection** | 25% | 30% | 35% | 45% | 95% |
| **Observability** | 20% | 40% | 60% | 85% | 95% |

---

## **Complete Integration Example: Real-world Scenario**

### **E-commerce Microservices with Full Security Stack**
```mermaid
graph TB
    subgraph "External Traffic"
        USER[User Browser]
        LB[Load Balancer<br/>TLS Termination]
        USER --> LB
    end
    
    subgraph "Kubernetes Cluster - Full Security Stack"
        subgraph "Ingress Namespace"
            IG[Istio Gateway<br/>• TLS 1.3<br/>• Certificate Management<br/>• WAF Rules]
            LB --> IG
        end
        
        subgraph "Frontend Namespace"
            WEB[Web Service<br/>Identity: spiffe://cluster/ns/frontend/sa/web]
            WEBB[Envoy Sidecar<br/>• mTLS<br/>• AuthZ Policies<br/>• Observability]
            WEB --- WEBB
            
            IG -.->|HTTPS| WEBB
        end
        
        subgraph "Services Namespace"
            API[API Gateway<br/>Identity: spiffe://cluster/ns/services/sa/api]
            APIB[Envoy Sidecar]
            API --- APIB
            
            ORDER[Order Service<br/>Identity: spiffe://cluster/ns/services/sa/order]
            ORDERB[Envoy Sidecar]
            ORDER --- ORDERB
            
            PAY[Payment Service<br/>Identity: spiffe://cluster/ns/services/sa/payment]
            PAYB[Envoy Sidecar]
            PAY --- PAYB
            
            WEBB -.->|mTLS| APIB
            APIB -.->|mTLS| ORDERB
            APIB -.->|mTLS| PAYB
        end
        
        subgraph "Data Namespace"
            DB[Database<br/>Identity: spiffe://cluster/ns/data/sa/postgres]
            DBB[Envoy Sidecar]
            DB --- DBB
            
            CACHE[Redis Cache<br/>Identity: spiffe://cluster/ns/data/sa/redis]
            CACHEB[Envoy Sidecar]
            CACHE --- CACHEB
            
            ORDERB -.->|mTLS| DBB
            PAYB -.->|mTLS| DBB
            APIB -.->|mTLS| CACHEB
        end
        
        subgraph "Security Infrastructure"
            SPIRES[SPIRE Server<br/>• Root CA<br/>• Identity Registry<br/>• Policy Engine]
            ISTIOD[Istiod<br/>• Service Mesh Control<br/>• Certificate Distribution<br/>• Policy Enforcement]
            FALCO[Falco<br/>• Runtime Monitoring<br/>• Anomaly Detection<br/>• Threat Response]
            
            SPIRES -.->|Certificates| API
            SPIRES -.->|Certificates| ORDER  
            SPIRES -.->|Certificates| PAY
            SPIRES -.->|Certificates| DB
            SPIRES -.->|Certificates| CACHE
            SPIRES -.->|Certificates| WEB
            
            ISTIOD -.->|Policies| APIB
            ISTIOD -.->|Policies| ORDERB
            ISTIOD -.->|Policies| PAYB
            ISTIOD -.->|Policies| DBB
            ISTIOD -.->|Policies| CACHEB
            ISTIOD -.->|Policies| WEBB
            
            FALCO -.->|Monitor| API
            FALCO -.->|Monitor| ORDER
            FALCO -.->|Monitor| PAY
            FALCO -.->|Monitor| DB
            FALCO -.->|Monitor| CACHE
        end
        
        subgraph "Observability"
            PROM[Prometheus<br/>Security Metrics]
            GRAF[Grafana<br/>Security Dashboard]
            JAEGER[Jaeger<br/>Trace Security Context]
            ELK[ELK Stack<br/>Security Event Correlation]
            
            PROM --> GRAF
            JAEGER --> GRAF
            ELK --> GRAF
        end
    end
    
    style SPIRES fill:#4ecdc4
    style ISTIOD fill:#45b7d1
    style FALCO fill:#ff6b6b
    style GRAF fill:#ffa726
```

### **Security Flow for a Payment Request**
```mermaid
sequenceDiagram
    participant U as User
    participant W as Web Service
    participant A as API Gateway  
    participant O as Order Service
    participant P as Payment Service
    participant D as Database
    participant F as Falco
    participant S as SPIRE
    
    Note over U,S: Complete Security Flow for Payment Processing
    
    U->>W: 1. HTTPS Payment Request
    
    Note over W,S: Identity Verification Phase
    W->>S: 2. Verify SVID (Identity)
    S-->>W: 3. Valid Identity Confirmed
    
    W->>A: 4. mTLS Request to API Gateway
    Note over A: 5. Envoy validates client cert
    Note over A: 6. Authorization policy check
    
    A->>O: 7. mTLS Request to Order Service  
    Note over O: 8. Validate API Gateway identity
    Note over F: 9. Monitor API call patterns
    
    O->>P: 10. mTLS Request to Payment Service
    Note over P: 11. Validate Order Service identity
    Note over P: 12. Check authorization policies
    Note over F: 13. Monitor payment request
    
    P->>D: 14. mTLS Request to Database
    Note over D: 15. Validate Payment Service identity
    Note over F: 16. Monitor database access
    
    D-->>P: 17. Encrypted Response
    P-->>O: 18. Encrypted Response
    O-->>A: 19. Encrypted Response
    A-->>W: 20. Encrypted Response
    W-->>U: 21. HTTPS Response
    
    Note over F: 22. Correlate all security events
    Note over F: 23. Generate security metrics
    Note over F: 24. Alert on any anomalies
```

##
##
