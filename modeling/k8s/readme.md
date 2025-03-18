┌─────────────────────────────────────────────────────────────────────────────────┐
│                             KUBERNETES CLUSTER                                  │
│                                                                                 │
│  ┌─────────────────────────────────┐    ┌─────────────────────────────────┐    │
│  │       NAMESPACE: trainee-123     │    │       NAMESPACE: trainee-456     │    │
│  │                                 │    │                                 │    │
│  │  ┌─────────────────────────┐    │    │  ┌─────────────────────────┐    │    │
│  │  │ Flask Application Pod   │    │    │  │ Flask Application Pod   │    │    │
│  │  │                         │    │    │  │                         │    │    │
│  │  │ - Label: trainee=123    │    │    │  │ - Label: trainee=456    │    │    │
│  │  │ - Istio Sidecar: ✓      │◄───┼────┼──┼─✗ BLOCKED BY CILIUM     │    │    │
│  │  │ - Service Account:      │    │    │  │ - Service Account:      │    │    │
│  │  │   trainee-123-sa        │    │    │  │   trainee-456-sa        │    │    │
│  │  └─────────────────────────┘    │    │  └─────────────────────────┘    │    │
│  │            ▲  │                 │    │            ▲  │                 │    │
│  │       mTLS │  │ mTLS            │    │       mTLS │  │ mTLS            │    │
│  │            │  ▼                 │    │            │  ▼                 │    │
│  │  ┌─────────────────────────┐    │    │  ┌─────────────────────────┐    │    │
│  │  │ Database Pod            │    │    │  │ Database Pod            │    │    │
│  │  │                         │    │    │  │                         │    │    │
│  │  │ - Label: trainee=123    │    │    │  │ - Label: trainee=456    │    │    │
│  │  │ - Istio Sidecar: ✓      │◄───┼────┼──┼─✗ BLOCKED BY CILIUM     │    │    │
│  │  │ - Network Policy:       │    │    │  │ - Network Policy:       │    │    │
│  │  │   allow-same-namespace  │    │    │  │   allow-same-namespace  │    │    │
│  │  └─────────────────────────┘    │    │  └─────────────────────────┘    │    │
│  │                                 │    │                                 │    │
│  └─────────────────────────────────┘    └─────────────────────────────────┘    │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                       SECURITY ENFORCEMENT LAYER                         │   │
│  │                                                                         │   │
│  │  ┌───────────────────────────┐      ┌────────────────────────────────┐ │   │
│  │  │ CILIUM (Network Layer)    │      │ ISTIO (Service Mesh Layer)     │ │   │
│  │  │ - Enforces:               │      │ - Enforces:                    │ │   │
│  │  │   * Trainee namespace     │      │   * Mutual TLS encryption      │ │   │
│  │  │     boundaries            │      │   * Service-level auth         │ │   │
│  │  │   * DNS filtering         │      │   * Request-level validation   │ │   │
│  │  │   * Egress controls       │      │   * Traffic routing rules      │ │   │
│  │  └───────────────────────────┘      └────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                       SHARED INFRASTRUCTURE                              │   │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐    │   │
│  │  │ Ingress Gateway   │  │ Kubernetes DNS    │  │ Monitoring Stack  │    │   │
│  │  │ (Istio-managed)   │  │ (ClusterIP)       │  │ (Prometheus)      │    │   │
│  │  └───────────────────┘  └───────────────────┘  └───────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘


```
Trainees can only access their own namespaces
All communication is encrypted with mTLS
Network policies block cross-namespace communication
External access is tightly controlled
All traffic is authenticated with proper service identities
Ingress is managed centrally but routed to specific trainee environments
```
