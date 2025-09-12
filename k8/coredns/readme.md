

```mermaid
flowchart TD
    subgraph Workloads["EKS Workloads"]
        P1[App Pod A<br/>Normal DNS]
        P2[App Pod B<br/>Needs rDNS]
    end

    subgraph CoreDNS["CoreDNS Deployment (kube-dns)"]
        C1[Cluster Service Lookup<br/>(svc.cluster.local)]
        C2[Forward unknown queries]
    end

    subgraph rDNS["rdns-resolver (Bind)"]
        R1[Recursive Resolver<br/>(.arpa lookups)]
    end

    subgraph Upstream["Upstream DNS (VPC / External)"]
        U1[Amazon VPC Resolver]
        U2[Root / TLD / Authoritative DNS]
    end

    %% Flows
    P1 --> CoreDNS
    CoreDNS -->|svc.local resolution| C1
    CoreDNS -->|external A/AAAA| C2 --> U1 --> U2

    P2 -->|dnsConfig: rdns-resolver IP| rDNS
    rDNS -->|recursive PTR / in-addr.arpa| U2

    %% Notes
    note right of CoreDNS
      * Default path for most pods
      * Handles cluster-local + forwards
    end

    note right of rDNS
      * Used only by pods explicitly configured
      * Heavy reverse DNS (PTR) traffic terminates here
      * Avoids hammering CoreDNS
    end


```

##
##


```mermaid
flowchart TD
    subgraph Pod["Pod (workload)"]
        A[App makes DNS query]
    end

    subgraph CoreDNS["CoreDNS (kube-dns)"]
        B1[Cluster-local resolution<br/>(svc.cluster.local)]
        B2[Forward unknown queries<br/>to upstream resolvers]
    end

    subgraph Upstream["Upstream Resolver (10.49.0.2)"]
        C1[Forward lookups<br/>google.com, cisco.com]
        C2[Reverse lookups<br/>in-addr.arpa / ip6.arpa]
    end

    subgraph Internet["Public DNS"]
        D1[Root Servers]
        D2[TLD Servers]
        D3[Authoritative DNS]
    end

    A --> CoreDNS
    CoreDNS -->|Cluster-local| B1
    CoreDNS -->|Forward . queries| B2 --> Upstream
    Upstream -->|Forward lookups| C1 --> Internet
    Upstream -->|Reverse lookups| C2 --> Internet
    Internet --> Upstream --> CoreDNS --> A

