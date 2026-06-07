```
[ USER / ATTACKER ]
          |
          | HTTP POST /ai/chat (Prompt Injection Vector)
          v
+-----------------------------+
|    ai-ops-service (LB)      |
+-------------|---------------+
              |
              v
+-----------------------------+      +-----------------------------+
|    Spring AI Orchestrator   | <==> |     Ollama LLM Pod          |
|        (Pod: Brain)         |      |     (Pod: Thinker)          |
| --------------------------- |      | --------------------------- |
| * Spring Boot 3.4           |      | * Llama 3.2 1B (Local)      |
| * Spring AI ChatClient      |      | * Port: 11434               |
| * DPoP Key Management       |      +-----------------------------+
| * Actuator (Health/Env)     |
+-------------|---------------+
              |
              | TOOL CALL: tool: "cluster_diagnostics"
              | AUTH: Authorization: DPoP <token>
              | AUTH: DPoP: <signed_jwt_proof>
              v
+-----------------------------+      +-----------------------------+
|   Python MCP Tool Server    |      |    Kubernetes API Server    |
|     (Pod: Heavy Lifter)     | <==> |    (The Control Plane)      |
| --------------------------- |      +-----------------------------+
| * RFC 9449 Validation       |
| * OS Subprocess Utilities   |
| * K8s ServiceAccount Token  |
+-----------------------------+
```

##
##

```mermaid
graph TD
    subgraph Public_Zone [Public Network]
        User((User/Attacker))
    end

    subgraph K3s_Cluster [K3s Cluster - Namespace: ai-ops]
        Gateway[Spring Cloud Gateway/LoadBalancer]
        
        subgraph Logic_Tier [Orchestration Layer]
            SpringApp[Spring AI Orchestrator<br/>'The Brain']
        end
        
        subgraph AI_Tier [Inference Layer]
            Ollama[Ollama Local LLM<br/>'The Thinker']
        end
        
        subgraph Tool_Tier [Execution Layer]
            PythonMCP[Python MCP Tool Server<br/>'The Heavy Lifter']
            K8sAPI[Kubernetes API]
        end
    end

    User -->|HTTPS/Chat| Gateway
    Gateway -->|Forward| SpringApp
    SpringApp <-->|Internal REST/Ollama Protocol| Ollama
    SpringApp -->|Signed JSON-RPC/DPoP| PythonMCP
    PythonMCP -->|Admin Operations| K8sAPI

