# Threat Modeling Checklist for Java/Spring MVC Docker-based Microservices

---

## 1. Define Scope & Assets

* **Inventory Services**
  List each Spring MVC microservice (e.g. `user-service`, `order-service`).

* **Key Data**
  Identify sensitive data handled: PII, financial records, OAuth tokens, session IDs.

* **Trust Zones**
  Mark boundaries (e.g. public API gateway → internal service mesh → database).

---

## 2. Diagram & Data Flows

* **Data Flow Diagram (DFD)**

  * Clients → API Gateway → Spring MVC controllers
  * Service-to-service calls (REST/gRPC)
  * Databases, caches, message queues
  * External dependencies (OAuth server, Vault)
* **Trust Boundaries**
  Clearly delineate network, container, and process boundaries.

---

## 3. Entry Points & Assets

| Category              | Examples                                  |
| --------------------- | ----------------------------------------- |
| HTTP Endpoints        | `@RestController`, Spring MVC controllers |
| Actuator Endpoints    | `/actuator/health`, `/actuator/beans`     |
| Message Consumers     | `@KafkaListener`, RabbitMQ listeners      |
| Configuration Sources | `application.yml`, ENV variables          |
| Container Interfaces  | Docker socket, liveness/readiness probes  |

---

## 4. STRIDE Threat Enumeration

| STRIDE          | Threat Description           | Example                         |
| --------------- | ---------------------------- | ------------------------------- |
| **S**poofing    | Impersonation of identity    | JWT signature tampering         |
| **T**ampering   | Modification of data or code | SQL/NoSQL/Command injection     |
| **R**epudiation | Lack of trace/audit          | Missing correlation IDs in logs |
| **I**nfo Disc.  | Exposure of sensitive data   | Stack traces in error responses |
| **D**oS         | Resource exhaustion          | Unbounded file uploads          |
| **E**lev. Priv. | Unauthorized privilege gain  | Containers running as root      |

---

## 5. Design Controls & Hardening

### 5.1 Spring MVC–Specific Controls

| Control Area           | Recommendations                                                            |
| ---------------------- | -------------------------------------------------------------------------- |
| Authentication & Authz | Use Spring Security; annotate with `@PreAuthorize`; regenerate session IDs |
| Input Validation       | JSR-303 (`@Valid`); custom validators                                      |
| Output Encoding        | Thymeleaf auto-escaping; `StringEscapeUtils.escapeHtml4()`                 |
| CSRF & CORS            | Enable CSRF protection; restrict CORS to known origins                     |
| Exception Handling     | Global `@ControllerAdvice`; hide stack traces                              |
| Actuator Security      | Restrict/disable sensitive endpoints (`/env`, `/beans`) in production      |

### 5.2 Cryptography & Secrets

* **TLS Everywhere**: Enforce HTTPS for all client and inter-service traffic.
* **Encrypt at Rest**: Use AES-256 or DB-native encryption for sensitive fields.
* **Secrets Management**: Inject via Vault or Kubernetes Secrets; mount as read-only files.
* **Key Rotation**: Automate with Vault leases or CI/CD jobs.

### 5.3 Logging & Monitoring

* **Correlation IDs**: Generate per-request UUID, propagate via headers.
* **Structured Logs**: Emit JSON logs (use Logback encoder) for easy ingestion.
* **Audit Trails**: Log auth events, role changes, data exports.
* **Alerting**: Define Splunk/CloudWatch alerts on anomalous patterns (e.g. repeated failed logins).

### 5.4 Container & Deployment Hardening

| Layer            | Hardening Steps                                                                         |
| ---------------- | --------------------------------------------------------------------------------------- |
| Image Hygiene    | Use minimal base images (distroless/openjdk\:slim); scan with Trivy/Grype in CI         |
| Dockerfile       | Multi-stage builds; remove build tools; run as non-root user; read-only FS; drop caps   |
| Kubernetes       | `runAsNonRoot`; `readOnlyRootFilesystem`; NetworkPolicies; resource limits & quotas     |
| Runtime Security | Enforce Pod Security Policies or OPA/Gatekeeper to validate manifests at admission time |

### 5.5 Supply-Chain & CI/CD

| Practice            | Tool / Approach                                              |
| ------------------- | ------------------------------------------------------------ |
| Image Signing       | Docker Content Trust, Notary                                 |
| SBOM Generation     | Syft                                                         |
| Dependency Scanning | OWASP Dependency-Check, Snyk                                 |
| Automated Upgrades  | Renovate Bot                                                 |
| Secrets in Pipeline | Vault integration; avoid plaintext creds in Jenkinsfiles/GHA |
| SAST & DAST in CI   | CodeQL, OWASP ZAP                                            |

---

## 6. Threat-Model Review & Validation

1. **Peer Review Workshop**
   Walk through DFD and controls with dev, ops, and security teams.
2. **Automated Scans**
   Integrate SAST/DAST into CI pipelines; enforce blocking on critical findings.
3. **Penetration Test / Red Team**
   Exercise key attack paths against a staging environment.
4. **Periodic Reassessment**
   Revisit quarterly or whenever major features are released.

---

## 7. How to Use This Checklist

1. **Kick-off Meeting**: Align on scope, draw DFD, assign trust-boundary annotations.
2. **Backlog Remediation**: Track findings as tickets; assign owners and due dates.
3. **CI/CD Enforcement**: Automate scans, gate deployments on policy compliance.
4. **Governance**: Schedule regular audits, update SBOMs and image-scan policies.


