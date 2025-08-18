

```mermaid
graph TD
    %% Executive Level
    EXEC[Executive Leadership<br/>CISO/CTO]
    
    %% Security Leadership
    EXEC --> SM[SecOps Manager<br/>Customer Escalations<br/>Major Incidents]
    EXEC --> EM[SecEng Manager<br/>Tool Architecture<br/>AI/ML Strategy]
    
    %% Team Level
    SM --> BT[Security Defense Team - Blue Team<br/>4 People]
    EM --> RT[Security Offense Team - Red Team<br/>4 People]
    
    %% Blue Team Roles
    BT --> SSE[Senior SOC Engineer<br/>L3 Escalations<br/>AI/ML Anomaly Detection]
    BT --> VME[Vulnerability Mgmt Engineer<br/>SaaS Scanning<br/>SBOM Tracking]
    BT --> IRL[Incident Response Lead<br/>Major Incidents<br/>Blue Team Coordination]
    BT --> CSE[Cloud Security Engineer<br/>AWS CloudTrail<br/>Infrastructure Security]
    
    %% Red Team Roles
    RT --> SRE[Senior Red Team Engineer<br/>Red/Blue Exercises<br/>AI/ML Attack Vectors]
    RT --> RTE[Red Team Engineer<br/>WebApp Pentesting<br/>AI/ML Model Testing]
    RT --> SA[Security Architect<br/>Threat Modeling<br/>AI/ML Security Design]
    RT --> STE[Security Tooling Engineer<br/>Tool Development<br/>WebApp Scan Tools]
    
    %% Cross-team collaboration
    BT <-.->|Peer Reviews<br/>Critical Decisions| RT
    SM <-.->|Cross-team<br/>Coordination| EM
    
    %% Escalation Flow (Top-Down)
    SSE --> L1[L1 Response<br/>SOC Engineer 24/7]
    L1 --> L2[L2 Response<br/>Senior SOC + IR Lead]
    L2 --> L3[L3 Response<br/>SecOps Manager]
    L3 --> EXEC
    
    %% Key Workflows (Top-Down)
    EXEC --> STRATEGY[Security Strategy]
    STRATEGY --> PLANNING[Planning & Architecture]
    PLANNING --> SA
    PLANNING --> VME
    
    SA --> DESIGN[Design & Review]
    DESIGN --> SRE
    DESIGN --> RTE
    
    SRE --> TESTING[Security Testing]
    TESTING --> VALIDATION[Validation & Deployment]
    VALIDATION --> SSE
    VALIDATION --> CSE
    
    VME --> SCANNING[Vulnerability Scanning]
    SCANNING --> REMEDIATION[Remediation & Monitoring]
    REMEDIATION --> IRL
    REMEDIATION --> STE
    
    %% Specialized Capabilities (Top-Down)
    EXEC --> CAPABILITIES[Specialized Security Capabilities]
    
    CAPABILITIES --> WEBAPP[WebApp Security<br/>DAST/SAST/WAF]
    CAPABILITIES --> AIML[AI/ML Security<br/>Model Testing/Monitoring]
    CAPABILITIES --> VULN[Vulnerability Management<br/>Risk Scoring/SBOM]
    CAPABILITIES --> CLOUD[Cloud Security<br/>AWS/Container/K8s]
    
    WEBAPP --> RTE
    WEBAPP --> VME
    WEBAPP --> CSE
    
    AIML --> SRE
    AIML --> SA
    AIML --> SSE
    
    VULN --> VME
    VULN --> SA
    VULN --> RTE
    
    CLOUD --> CSE
    CLOUD --> STE
    CLOUD --> SA
    
    %% Rotation (Bidirectional)
    BT -.->|Voluntary Rotation<br/>6 months| RT
    RT -.->|Voluntary Rotation<br/>6 months| BT
    
    %% Styling
    classDef executive fill:#ff6666
    classDef leadership fill:#ff9999
    classDef blueTeam fill:#99ccff
    classDef redTeam fill:#ffcc99
    classDef workflow fill:#ccffcc
    classDef capability fill:#ffccff
    
    class EXEC executive
    class SM,EM leadership
    class BT,SSE,VME,IRL,CSE blueTeam
    class RT,SRE,RTE,SA,STE redTeam
    class STRATEGY,PLANNING,DESIGN,TESTING,VALIDATION,SCANNING,REMEDIATION workflow
    class WEBAPP,AIML,VULN,CLOUD capability
