

```mermaid
graph TB
    %% Leadership Layer
    SM[SecOps Manager<br/>Customer Escalations<br/>Major Incidents]
    EM[SecEng Manager<br/>Tool Architecture<br/>AI/ML Strategy]
    
    %% Security Defense Team (Blue Team)
    subgraph BT[Security Defense Team - Blue Team]
        SSE[Senior SOC Engineer<br/>L3 Escalations<br/>AI/ML Anomaly Detection]
        VME[Vulnerability Mgmt Engineer<br/>SaaS Scanning<br/>SBOM Tracking]
        IRL[Incident Response Lead<br/>Major Incidents<br/>Blue Team Coordination]
        CSE[Cloud Security Engineer<br/>AWS CloudTrail<br/>Infrastructure Security]
    end
    
    %% Security Offense Team (Red Team)
    subgraph RT[Security Offense Team - Red Team]
        SRE[Senior Red Team Engineer<br/>Red/Blue Exercises<br/>AI/ML Attack Vectors]
        RTE[Red Team Engineer<br/>WebApp Pentesting<br/>AI/ML Model Testing]
        SA[Security Architect<br/>Threat Modeling<br/>AI/ML Security Design]
        STE[Security Tooling Engineer<br/>Tool Development<br/>WebApp Scan Tools]
    end
    
    %% Peer Review Hub
    subgraph PRH[Peer Review Hub]
        CR[Critical Reviews<br/>• High-Risk Deploys<br/>• New Microservices<br/>• AI/ML Models<br/>• WebApp Changes<br/>• Vuln Remediation]
    end
    
    %% Key Workflows
    subgraph WF[Key Workflows]
        MS[New Microservice]
        WA[WebApp Changes]
        AI[AI/ML Model]
        VI[Vuln Discovery]
        SI[Security Incident]
        RT_EX[Red Team Exercise]
    end
    
    %% Leadership connections
    SM --> BT
    EM --> RT
    SM -.-> RT
    EM -.-> BT
    
    %% Peer Review connections
    BT <--> PRH
    RT <--> PRH
    
    %% Rotation arrows
    BT -.->|Voluntary Rotation<br/>6 months| RT
    RT -.->|Voluntary Rotation<br/>6 months| BT
    
    %% Workflow connections
    MS --> SA
    SA --> SRE
    SRE --> VME
    VME --> SSE
    
    WA --> SA
    SA --> RTE
    RTE --> VME
    VME --> CSE
    
    AI --> SA
    SA --> SRE
    SRE --> SSE
    SSE --> IRL
    
    VI --> VME
    VME --> SA
    SA --> RTE
    RTE --> IRL
    
    SI --> SSE
    SSE --> IRL
    IRL --> SRE
    SRE --> VME
    
    RT_EX --> SRE
    SRE --> SA
    SA --> IRL
    IRL --> SSE
    
    %% Escalation flow
    subgraph ESC[Escalation Flow]
        L1[L1: SOC Engineer<br/>24/7 Rotation]
        L2[L2: Senior SOC + IR Lead<br/>Deep Analysis]
        L3[L3: SecOps Manager<br/>Customer Communication]
        EX[Executive: CISO/CTO<br/>Company-wide Impact]
    end
    
    L1 --> L2
    L2 --> L3
    L3 --> EX
    
    %% Specialized capabilities
    subgraph SC[Specialized Capabilities]
        WEBAPP[WebApp Security<br/>DAST/SAST/WAF]
        AIML[AI/ML Security<br/>Model Testing/Monitoring]
        VULN[Vulnerability Management<br/>Risk Scoring/SBOM]
        CLOUD[Cloud Security<br/>AWS/Container/K8s]
    end
    
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
    
    %% Styling
    classDef leadership fill:#ff9999
    classDef blueTeam fill:#99ccff
    classDef redTeam fill:#ffcc99
    classDef workflow fill:#ccffcc
    classDef review fill:#ffccff
    
    class SM,EM leadership
    class SSE,VME,IRL,CSE blueTeam
    class SRE,RTE,SA,STE redTeam
    class MS,WA,AI,VI,SI,RT_EX workflow
    class PRH,CR review
