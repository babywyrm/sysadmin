
```mermaid
sequenceDiagram
    autonumber
    participant User as 👤 User (OIDC Auth)
    participant Gateway as 👮 Protocol Gateway
    participant Agent as 🤖 AI Agent Workload
    participant Tool as 🛠️ MCP Tool Workload
    participant IAM as ☁️ Cloud Identity (IRSA)
    participant Backend as 📂 External Service

    Note over User,Backend: Trust Boundary: Zero-Trust Kubernetes Cluster

    User->>Gateway: 1. Prompt + User Identity (Claims: Role/Team)
    
    rect rgb(240, 240, 240)
    Note right of Gateway: [LAYER 1: PROTOCOL GATEWAY]
    Gateway->>Gateway: 2. Validate User & Scope
    Gateway->>Gateway: 3. Mint Downstream JWT (Aud: specific-tool-id)
    end

    Gateway->>Agent: 4. Forward Scoped Token + Verified Intent
    
    rect rgb(220, 240, 220)
    Note right of Agent: [LAYER 2: WORKLOAD IDENTITY]
    Agent->>Tool: 5. Execute Tool (JWT + SPIFFE Identity)
    Note over Agent,Tool: mTLS Tunnel: Verified Peer-to-Peer
    end

    rect rgb(240, 220, 220)
    Note right of Tool: [LAYER 3: TOOL AUTHORIZATION]
    Tool->>Tool: 6. Verify JWT Audience == "self-id"
    Tool->>Tool: 7. Validate Request Context vs Session
    end

    rect rgb(220, 220, 240)
    Note right of Tool: [LAYER 4: CLOUD PERMISSIONS]
    Tool->>IAM: 8. Assume IAM Role (Web Identity)
    IAM-->>Tool: 9. Scoped AWS Credentials (STS)
    end

    Tool->>Backend: 10. API Call (Authenticated by Cloud IAM + JWT)
    Backend-->>User: 11. Sanitized Result
```

### 🔐 Why the Tool Connector is No Longer Vulnerable

By implementing this flow, you mitigate the primary risks associated with AI tool-calling:

1.  **Impersonation Prevention (Steps 3 & 6)**: The **Protocol Gateway** performs a "Token Exchange." It swaps the broad user login for a highly specific **Audience-Bound JWT**. If an attacker attempts to use a token meant for the "GitHub Tool" to access a "Payroll Tool," the Payroll workload will reject the token because the `aud` (Audience) claim does not match its unique ID.

2.  **Infrastructure Hardening (Step 5)**: We use **SPIFFE/mTLS** to ensure that network communication only occurs between verified peers. This prevents "lateral movement" within the cluster; even if a workload is compromised, it cannot spoof its identity to talk to other restricted tool connectors.

3.  **Credential Elimination (Steps 8 & 9)**: No static API keys or AWS secrets are stored in the Tool workloads. We utilize **Identity Roles for Service Accounts (IRSA)** to dynamically fetch temporary credentials. This ensures that if a tool workload is breached, the "blast radius" is limited to the specific, least-privilege permissions assigned to that pod's IAM role.

4.  **Team Isolation (Step 7)**: The original user’s team/department context is passed through as a signed claim in the downstream JWT. The Tool workload enforces this context, preventing an agent from accidentally accessing data belonging to a different department or tenant.

### 🚀 Summary for Public Documentation

This architecture represents a **Zero-Trust AI Mesh**. It moves security away from "Trusting the Prompt" and places it into the **Identity and Network layers**. Security is enforced through four distinct locks:
*   **The Token**: Verified Scope and Audience.
*   **The Workload**: Verified cryptographic identity (SPIFFE).
*   **The Network**: Verified encrypted path (mTLS).
*   **The Cloud**: Verified Least-Privilege IAM role (IRSA).
