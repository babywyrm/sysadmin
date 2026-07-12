# Falco: architecture & flows (visual)

Mermaid diagrams for the mental models behind the notes in this directory. They
render on GitHub and stay diff-friendly (no binary assets).

## 1. The event pipeline (kernel → alert)

How a syscall becomes an alert. The **driver** taps the kernel; **libs** capture
and hold state; the **container plugin** enriches events with container/k8s
metadata; the **rule engine** evaluates; **outputs** ship the alert.

```mermaid
flowchart LR
    K["Kernel<br/>syscalls / tracepoints"] --> D["Driver<br/>modern_ebpf | kmod | ebpf"]
    D --> L["libscap / libsinsp<br/>capture + process state"]
    L --> P["container plugin<br/>enrich: container.id, image, k8s.*"]
    P --> E["Rule engine<br/>rules · macros · lists · exceptions"]
    E --> O["Outputs<br/>stdout · JSON · gRPC · sidekick"]
```

Key point: the driver sees the **whole host kernel**, not one runtime — so events
from any container runtime (and bare host processes) all flow through the same
probe. Scoping to a workload happens later, in the rules, using enriched fields.

## 2. Why `k8s.*` / `container.*` fields work (or silently don't)

Container/K8s fields exist only because the **container plugin** attaches them
(Falco 0.41+). Misconfigure the plugin's engine sockets and those fields go empty —
and every rule that filters on them quietly stops matching. See
[`container-plugin-and-k8s-fields.md`](container-plugin-and-k8s-fields.md).

```mermaid
flowchart TD
    EV["raw syscall event<br/>pid · fd · args"] --> ENG
    subgraph ENG["container plugin engines (runtime sockets)"]
      C1["containerd"]
      C2["cri"]
      C3["docker"]
    end
    ENG --> ENR["enriched event<br/>container.id · image.repository<br/>k8s.ns.name · k8s.pod.name"]
    ENR --> R{"rule uses<br/>container/k8s fields?"}
    R -->|"plugin OK"| M["fields resolve → rule can match"]
    R -->|"plugin missing / wrong socket"| X["fields empty → rule silently never fires"]
```

## 3. Detecting docker.sock abuse: three layers

Each layer catches what the one before it misses. Client-name tripwires are cheap
but evadable; socket-connect is name-independent; behavioral/effect detection is
strongest. See [`detecting-docker-socket-abuse.md`](detecting-docker-socket-abuse.md).

```mermaid
flowchart TD
    A["adversary in a container<br/>with /var/run/docker.sock mounted"]
    A --> L1["Layer 1 — client tripwire<br/>proc.cmdline contains docker/nerdctl/…"]
    A --> L2["Layer 2 — socket connect<br/>connect() to docker.sock"]
    A --> L3["Layer 3 — behavioral effect<br/>privileged / host-mount container created"]
    L1 --> G1["GAP: misses raw API driven from code<br/>(no client string in argv)"]
    L2 --> OK2["name/argv independent → catches raw API"]
    L3 --> OK3["detects the outcome → strongest, hardest to evade"]
```

## 4. Which process field should I match on?

Field choice decides both whether the rule fires and how easily it's evaded. See
[`custom-rules-field-reliability.md`](custom-rules-field-reliability.md).

```mermaid
flowchart TD
    Q["What am I trying to catch?"] --> Q1{"the identity of the<br/>real binary on disk?"}
    Q1 -->|yes| F1["proc.exepath<br/>resolved /proc/pid/exe"]
    Q1 -->|no| Q2{"a specific tool<br/>invocation?"}
    Q2 -->|yes| F2["proc.cmdline contains …<br/>high-signal tripwire (evadable)"]
    Q2 -->|no| Q3{"is this the expected<br/>process for this workload?"}
    Q3 -->|yes| F3["anchor on ancestry +<br/>container.image.repository"]
    Q3 -->|no| F2
    W["proc.name = comm: ~15 chars, spoofable<br/>→ weakest; avoid as a sole signal"]
```

## 5. Prove the rule fires (loading ≠ firing)

A rule can load with `schema validation: ok` and never match. Close the loop. See
[`rule-testing-methodology.md`](rule-testing-methodology.md).

```mermaid
flowchart LR
    W["write / edit rule"] --> Lo{"loads?<br/>schema ok"}
    Lo -->|no| W
    Lo -->|yes| T["trigger known-good event<br/>tagged with a unique token"]
    T --> C{"YOUR alert appears?<br/>(grep the token)"}
    C -->|no| DIAG["add temp diag rule<br/>print actual fields"]
    DIAG --> W
    C -->|yes| N{"benign variant<br/>stays silent?"}
    N -->|no| W
    N -->|yes| SHIP["ship — remove diagnostics"]
```

## 6. Rule anatomy (quick reference)

```mermaid
flowchart TD
    RULE["- rule: &lt;name&gt;"]
    RULE --> DESC["desc: human explanation"]
    RULE --> COND["condition: &lt;filter expr&gt;<br/>uses macros + lists + fields"]
    RULE --> OUT["output: templated msg with %fields"]
    RULE --> PRIO["priority: EMERGENCY…DEBUG"]
    RULE --> TAGS["tags: [mitre_…, PCI_…, context]"]
    MAC["- macro: reusable condition fragment"] -.-> COND
    LST["- list: reusable value set"] -.-> COND
    EXC["exceptions / 'and not macro'"] -.-> COND
```
