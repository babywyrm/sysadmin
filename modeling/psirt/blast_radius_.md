
# 📘 Blast Radius Calculus Runbook

## 1. Purpose

The goal of blast radius analysis is to **understand and limit how far an incident can spread** across:

* Systems (AWS accounts, CI/CD pipelines, Kubernetes clusters)
* Data (customer, internal, regulatory-sensitive)
* Business impact (customers, regions, products)
* Time (how long until recovery, how long exposure existed)

---

## 2. Core Principles

1. **Containment Before Measurement** – stop the bleeding first.
2. **Breadth Over Depth** – assess horizontally (what’s exposed) before vertical technical root cause.
3. **Customer-Centric View** – always frame radius in terms of customers affected.
4. **Forward & Backward Analysis** –

   * Backward: How long exposure existed.
   * Forward: What could happen if not contained.

---

## 3. Blast Radius Categories

| Category               | What to Check                                       | Tools / Evidence                   |
| ---------------------- | --------------------------------------------------- | ---------------------------------- |
| **Accounts & Regions** | Which AWS accounts/regions are impacted             | AWS Organizations, IAM, CloudTrail |
| **Services**           | Which AWS services or SaaS systems are affected     | S3, RDS, EKS, CI/CD, third-party   |
| **Data Exposure**      | What type of data was exposed and for how long      | S3 logs, DLP scans, VPC flow logs  |
| **Customers**          | Which customers or tenants are affected             | CRM, billing, product telemetry    |
| **CI/CD Artifacts**    | Which builds, images, or registries are compromised | SBOM, build logs, registry scans   |
| **Network Scope**      | Which VPCs, subnets, or clusters are reachable      | VPC peering, Transit Gateway       |
| **Temporal**           | How long exposure existed                           | CloudTrail history, retention logs |

---

## 4. Blast Radius Calculation Worksheet

```markdown
# Blast Radius Worksheet

## Accounts & Regions
- AWS Accounts impacted: 
- Regions impacted: 

## Services
- Cloud services impacted (e.g. S3, RDS, EKS, CI/CD):
- Third-party SaaS dependencies: 

## Data
- Type of data exposed (PII, credentials, configs, telemetry):
- Estimated volume: 
- Exposure duration: 

## Customers
- Customer segments impacted (Enterprise, Gov, Free-tier):
- Customer count estimate: 
- High-value/regulatory customers affected? (Y/N) 

## CI/CD
- Build pipelines impacted:
- Artifacts/registries impacted:
- Version/tag ranges: 

## Network
- VPCs/subnets involved: 
- Peered or cross-region connections:
- Internet-facing exposure? (Y/N)

## Temporal
- Earliest evidence of compromise:
- Detection timestamp:
- Time to containment:
```

---

## 5. Blast Radius Checklists

### 5.1 Incident Commander Quick Checklist

* [ ] Have we scoped impacted accounts and services?
* [ ] Have we determined customer exposure?
* [ ] Do we know **when** exposure began and ended?
* [ ] Have we estimated data volume and sensitivity?
* [ ] Have we identified lateral movement paths (CI/CD → prod, dev → prod)?
* [ ] Have we flagged external reporting requirements?

### 5.2 Engineer Investigation Checklist

* [ ] Pull CloudTrail logs for IAM anomalies
* [ ] Review S3/RDS access logs for unusual queries
* [ ] Audit build artifacts for tampering (hash diff, SBOM)
* [ ] Inspect container images/pods for backdoors
* [ ] Correlate GuardDuty/Inspector alerts

---

## 6. Prioritization Integration

The blast radius directly informs remediation buckets:

* **Large blast radius + customer data exposed** → 🔴 Immediate
* **Limited radius but product integrity degraded** → 🟠 Short-term
* **Narrow radius, no customer impact** → 🟡 Medium-term

---

## 7. Visual Model

```mermaid
flowchart TD
    A[Incident Detected] --> B[Containment Actions]
    B --> C{Blast Radius Analysis}
    C -->|Accounts/Regions| D[Affected AWS Accounts/Regions]
    C -->|Data| E[Type/Volume of Data Exposed]
    C -->|Customers| F[Customer Segments Impacted]
    C -->|CI/CD| G[Artifacts, Pipelines]
    C -->|Network| H[VPCs, Subnets, Connectivity]
    C -->|Temporal| I[Time of Exposure]
    C --> J[Prioritization Framework]
```

---

## 8. Example Walkthroughs

### Example 1: IAM Key Leak

* **Accounts & Regions**: 2 AWS accounts, us-east-1 + eu-central-1
* **Data**: Access to 3 S3 buckets with configs, no PII
* **Customers**: None directly affected (internal only)
* **Temporal**: Keys active 36 hours before revocation
* **Result**: Blast radius moderate → 🔴 Contain now, 🟠 patch + rotate secrets

### Example 2: Poisoned Build Artifact

* **Accounts & Regions**: 1 CI/CD account, global impact via registry
* **Data**: No direct customer data exposure
* **Customers**: 200 customers potentially pulled image version `1.2.4`
* **Temporal**: Artifact live for 5 days
* **Result**: Blast radius large due to customer exposure → 🔴 Suspend builds, notify customers

---

## 9. Output for Communications

Blast radius must always be part of updates:

```markdown
[Update @ 15:30 UTC]
- AWS Accounts impacted: 2
- Regions: us-east-1, eu-central-1
- Data: Config files, no PII
- Customers: None confirmed
- Exposure Duration: 36h
```

##
##
