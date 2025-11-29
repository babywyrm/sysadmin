
# AWS Employee Device Compromise — Professional Incident Response Matrix

## Executive Summary Document

I'll help you transform this into a production-ready IR matrix. Here's a comprehensive, professional framework:

---

## 📋 INCIDENT RESPONSE EXECUTION MATRIX v2.0

### Document Control
```yaml
Version: 2.0
Last Updated: 2025-11-28
Owner: Security Operations Manager
Review Cycle: Quarterly
Classification: INTERNAL - SECURITY SENSITIVE
```

---

## 🎯 PHASE-BASED EXECUTION FRAMEWORK

### PHASE 0: DECLARATION & MOBILIZATION (T+0 → T+5min)

| ID | Action | Owner | Dependencies | Success Criteria | Deliverable | Timeline |
|----|--------|-------|--------------|------------------|-------------|----------|
| P0-001 | Declare Incident (SEV1/SEV2) | SOC L2/L3 | Alert validation | Incident ticket created | INC-YYYYMMDD-### | 2 min |
| P0-002 | Activate War Room | IR Lead | P0-001 | Slack channel + Zoom active | #incident-YYYYMMDD | 3 min |
| P0-003 | Assign Roles (IC, Scribe, SMEs) | IR Lead | P0-002 | Role matrix populated | Roles document | 5 min |
| P0-004 | Initial Notification (CISO, Legal, HR) | IR Lead | P0-001 | Stakeholders notified | Email confirmation | 5 min |
| P0-005 | Freeze Change Controls | IR Lead | P0-002 | Deployments paused | Freeze confirmation | 3 min |

**Phase Deliverables:**
- ✅ Incident Declaration Record (`incidents/INC-{id}/declaration.json`)
- ✅ War Room Link & Role Assignment
- ✅ Initial Notification Log
- ✅ Change Freeze Confirmation

**Phase Exit Criteria:**
- [ ] Incident ticket created with severity assignment
- [ ] War room established with all critical roles present
- [ ] Stakeholders aware and change freeze in effect

---

### PHASE 1: RAPID CONTAINMENT (T+5 → T+15min)

#### 1A: Identity Lockdown (Parallel Execution)

| ID | Action | Owner | System | Command/API | Validation | Timeline | Rollback |
|----|--------|-------|--------|-------------|------------|----------|----------|
| P1-001 | Suspend Okta Account | IAM Admin | Okta | `POST /api/v1/users/{id}/lifecycle/suspend` | Account status = SUSPENDED | 30 sec | Yes |
| P1-002 | Terminate All Sessions | IAM Admin | Okta | `DELETE /api/v1/users/{id}/sessions` | Session count = 0 | 45 sec | No |
| P1-003 | Revoke OAuth Tokens | IAM Admin | Okta | `DELETE /api/v1/users/{id}/grants` | Token count = 0 | 60 sec | No |
| P1-004 | Remove MFA Factors | IAM Admin | Okta | `DELETE /api/v1/users/{id}/factors/{fid}` | Factor count = 0 | 30 sec | Yes |
| P1-005 | Snapshot IAM State (Pre-Revoke) | CloudSec | AWS | `aws iam get-user --user-name X` | JSON export saved | 20 sec | N/A |

#### 1B: AWS Access Revocation (Parallel Execution)

| ID | Action | Owner | System | Command/API | Validation | Timeline | Rollback |
|----|--------|-------|--------|-------------|------------|----------|----------|
| P1-101 | Apply Explicit DENY Policy | CloudSec | AWS IAM | Attach `DenyAllPolicy` | Policy attached | 15 sec | Yes |
| P1-102 | Delete Access Keys | CloudSec | AWS IAM | `aws iam delete-access-key` | Key count = 0 | 30 sec | No |
| P1-103 | Revoke STS Sessions | CloudSec | AWS STS | Policy update forces new auth | No active sessions | 45 sec | No |
| P1-104 | Tag User Account | CloudSec | AWS IAM | `aws iam tag-user` | Tag: Incident={id} | 10 sec | No |
| P1-105 | Scan Multi-Account Keys | CloudSec | AWS Orgs | Lambda scan function | Report generated | 2 min | N/A |

#### 1C: Endpoint Isolation (Parallel Execution)

| ID | Action | Owner | System | Command/API | Validation | Timeline | Rollback |
|----|--------|-------|--------|-------------|------------|----------|----------|
| P1-201 | Identify Active Devices | Response Eng | EDR | Query active endpoints | Device list | 20 sec | N/A |
| P1-202 | Network Isolate (Contain) | Response Eng | CrowdStrike | `contain` command | Status = Contained | 30 sec | Yes |
| P1-203 | Terminate User Processes | Response Eng | EDR | Kill process tree | Processes = 0 | 45 sec | No |
| P1-204 | Block at Firewall (IP/MAC) | NetSec | Palo Alto | Add block rule | Rule active | 60 sec | Yes |
| P1-205 | Disable VPN Access | NetSec | VPN Gateway | Revoke certificate | Cert invalid | 45 sec | Yes |

**Phase Deliverables:**
- ✅ Identity Revocation Report (`artifacts/phase1/identity_revocation.json`)
- ✅ AWS Access Summary (`artifacts/phase1/aws_access_summary.json`)
- ✅ Endpoint Isolation Confirmation (`artifacts/phase1/endpoint_status.json`)
- ✅ Pre-Revocation IAM Snapshot (`artifacts/phase1/iam_baseline.json`)

**Phase Exit Criteria:**
- [ ] Okta account suspended + all sessions terminated
- [ ] AWS access keys deleted + STS sessions invalidated
- [ ] Endpoint network-contained + processes killed
- [ ] All containment actions logged with timestamps

**Critical Success Metrics:**
- Time to Identity Revocation: **< 2 minutes**
- Time to AWS Lockdown: **< 3 minutes**
- Time to Endpoint Isolation: **< 2 minutes**

---

### PHASE 2: EVIDENCE COLLECTION (T+10 → T+30min)

#### 2A: Cloud Evidence (Parallel Collection)

| ID | Artifact | Owner | Source | Collection Method | Storage | Hash | Timeline |
|----|----------|-------|--------|-------------------|---------|------|----------|
| P2-001 | CloudTrail Logs (14d) | CloudSec | CloudTrail | Athena export to S3 | `s3://evidence/cloudtrail/` | SHA256 | 5 min |
| P2-002 | AWS Config Snapshots | CloudSec | Config | API export | `s3://evidence/config/` | SHA256 | 3 min |
| P2-003 | GuardDuty Findings | SOC | GuardDuty | JSON export | `s3://evidence/guardduty/` | SHA256 | 2 min |
| P2-004 | VPC Flow Logs | CloudSec | VPC | S3 sync | `s3://evidence/vpcflow/` | SHA256 | 4 min |
| P2-005 | S3 Access Logs | CloudSec | S3 Bucket | S3 sync | `s3://evidence/s3access/` | SHA256 | 3 min |
| P2-006 | IAM Activity Report | CloudSec | IAM Access Analyzer | CSV export | `s3://evidence/iam/` | SHA256 | 2 min |

#### 2B: Endpoint Forensics (Sequential Collection)

| ID | Artifact | Owner | Source | Tool | Storage | Timeline | Priority |
|----|----------|-------|--------|------|---------|----------|----------|
| P2-101 | Memory Dump | Forensics | EDR | Volatility | `forensics/memory/` | 8 min | P0 |
| P2-102 | Process List | Forensics | EDR | EDR API | `forensics/processes/` | 1 min | P0 |
| P2-103 | Network Connections | Forensics | EDR | Netstat capture | `forensics/network/` | 1 min | P0 |
| P2-104 | Running Services | Forensics | EDR | Service enumeration | `forensics/services/` | 1 min | P1 |
| P2-105 | File System Timeline | Forensics | EDR | MFT parse | `forensics/timeline/` | 10 min | P1 |
| P2-106 | Browser History | Forensics | EDR | BrowserHistory | `forensics/browser/` | 3 min | P2 |

#### 2C: Log Aggregation (Parallel Collection)

| ID | Artifact | Owner | Source | Query/Filter | Storage | Timeline |
|----|----------|-------|--------|--------------|---------|----------|
| P2-201 | SIEM Query Results | Detection | Splunk | User activity (48h) | `logs/siem/` | 3 min |
| P2-202 | Okta System Logs | IAM Admin | Okta | `/api/v1/logs` (14d) | `logs/okta/` | 2 min |
| P2-203 | GitHub Audit Log | DevSecOps | GitHub | Audit API | `logs/github/` | 2 min |
| P2-204 | Application Logs | SRE | Kibana | User session logs | `logs/app/` | 5 min |
| P2-205 | WAF Logs | NetSec | CloudFlare | IP-based filter | `logs/waf/` | 3 min |

**Phase Deliverables:**
- ✅ Cloud Evidence Package (`evidence/cloud_evidence_manifest.json`)
- ✅ Endpoint Forensic Package (`evidence/endpoint_forensics_manifest.json`)
- ✅ Log Aggregation Package (`evidence/logs_manifest.json`)
- ✅ Evidence Integrity Hashes (`evidence/SHA256SUMS`)

**Phase Exit Criteria:**
- [ ] All priority evidence collected and hashed
- [ ] Evidence uploaded to secure incident bucket
- [ ] Chain of custody documented
- [ ] Evidence manifest generated

---

### PHASE 3: BLAST RADIUS ANALYSIS (T+20 → T+40min)

#### 3A: AWS Impact Assessment

| ID | Analysis | Owner | Query/Tool | Output | Timeline | Severity Threshold |
|----|----------|-------|------------|--------|----------|-------------------|
| P3-001 | IAM Role Assumptions | CloudSec | Athena query | Assumed roles list | 5 min | Any cross-account |
| P3-002 | Resource Creation | CloudSec | CloudTrail filter | New resources | 8 min | EC2, Lambda, S3 |
| P3-003 | Policy Modifications | CloudSec | Config timeline | Changed policies | 5 min | Any inline policy |
| P3-004 | S3 Bucket Access | CloudSec | S3 access analyzer | Accessed buckets | 4 min | Public/sensitive |
| P3-005 | Secret Access | CloudSec | Secrets Manager logs | Retrieved secrets | 3 min | Production secrets |
| P3-006 | Database Connections | DBA | RDS/Aurora logs | DB connections | 6 min | Production DBs |

#### 3B: Network Path Analysis

| ID | Analysis | Owner | Tool | Output | Timeline |
|----|----------|-------|------|--------|----------|
| P3-101 | Exfiltration Detection | Detection | VPC Flow + SIEM | Unusual outbound | 8 min |
| P3-102 | C2 Communication | Threat Intel | Firewall + IDS | Suspicious IPs | 5 min |
| P3-103 | Lateral Movement | Detection | Network graph | Movement pattern | 10 min |
| P3-104 | VPN Access Pattern | NetSec | VPN logs | Connection timeline | 4 min |

#### 3C: Application Impact

| ID | Analysis | Owner | Tool | Output | Timeline |
|----|----------|-------|------|--------|----------|
| P3-201 | API Access Pattern | AppSec | API Gateway logs | Unusual endpoints | 6 min |
| P3-202 | Data Access Audit | AppSec | App logs + DB logs | Sensitive data access | 8 min |
| P3-203 | SaaS Integration Impact | IT Ops | SCIM/API logs | Compromised integrations | 5 min |

**Phase Deliverables:**
- ✅ Blast Radius Report (`analysis/blast_radius_summary.md`)
- ✅ Impacted Resources List (`analysis/impacted_resources.csv`)
- ✅ Attack Timeline (`analysis/attack_timeline.json`)
- ✅ Risk Assessment Matrix (`analysis/risk_matrix.csv`)

**Phase Exit Criteria:**
- [ ] Complete resource inventory of accessed systems
- [ ] Timeline of attacker activity established
- [ ] Impact severity assessed for each resource
- [ ] Lateral movement paths identified

---

### PHASE 4: THREAT HUNTING & IOC GENERATION (T+30 → T+50min)

| ID | Hunt Activity | Owner | Focus Area | Method | Output | Timeline |
|----|---------------|-------|------------|--------|--------|----------|
| P4-001 | Persistence Mechanism Hunt | Detection | AWS, Endpoints | SIEM queries | Persistence list | 10 min |
| P4-002 | Credential Reuse Detection | CloudSec | Multi-account scan | API calls | Reused keys | 8 min |
| P4-003 | Malware Artifact Analysis | Forensics | Endpoint files | YARA + sandbox | File hashes | 12 min |
| P4-004 | Network IOC Extraction | Threat Intel | Firewall, DNS | Pattern analysis | IP/domain list | 6 min |
| P4-005 | Process IOC Extraction | Forensics | Memory dump | String extraction | Process hashes | 8 min |
| P4-006 | TTPs Mapping | Red Team | All sources | MITRE ATT&CK | TTP matrix | 15 min |

**Phase Deliverables:**
- ✅ IOC Package (`iocs/ioc_feed.json`, `iocs/ioc_feed.stix`)
- ✅ TTP Matrix (`iocs/mitre_attack_mapping.json`)
- ✅ Hunting Report (`iocs/threat_hunt_results.md`)
- ✅ Yara Rules (`iocs/custom_yara_rules.yar`)

---

### PHASE 5: REMEDIATION & HARDENING (T+50 → T+120min)

#### 5A: Immediate Remediation

| ID | Action | Owner | System | Validation | Timeline | Priority |
|----|--------|-------|--------|------------|----------|----------|
| P5-001 | Rotate All AWS Secrets | CloudSec | Secrets Manager | All secrets rotated | 30 min | P0 |
| P5-002 | Rotate Database Passwords | DBA | RDS/Aurora | All passwords changed | 20 min | P0 |
| P5-003 | Update All API Keys | CloudSec | 1Password/Vault | All keys rotated | 25 min | P0 |
| P5-004 | Rebuild Compromised Instances | SRE | EC2 | New instances deployed | 45 min | P0 |
| P5-005 | Deploy IOC Blocklists | NetSec | Firewall/EDR | IOCs blocked | 15 min | P0 |

#### 5B: Detection Enhancement

| ID | Enhancement | Owner | System | Deliverable | Timeline |
|----|-------------|-------|--------|-------------|----------|
| P5-101 | Deploy New SIEM Rules | Detection | Splunk | Rules active | 20 min |
| P5-102 | Update GuardDuty Config | CloudSec | GuardDuty | Custom findings | 15 min |
| P5-103 | Deploy EDR Detections | Response Eng | CrowdStrike | IOAs active | 25 min |
| P5-104 | Update WAF Rules | NetSec | CloudFlare | Rules deployed | 10 min |

**Phase Deliverables:**
- ✅ Remediation Checklist (`remediation/checklist.md`)
- ✅ Secret Rotation Log (`remediation/secret_rotation.json`)
- ✅ Detection Deployment Log (`remediation/detection_updates.json`)
- ✅ Infrastructure Rebuild Report (`remediation/rebuild_summary.md`)

---

### PHASE 6: VALIDATION & CLOSURE (T+120min → T+4hr)

#### 6A: Technical Validation

| ID | Validation | Owner | Method | Pass Criteria | Timeline |
|----|------------|-------|--------|---------------|----------|
| P6-001 | Verify Zero Access | CloudSec | API test | All auth fails | 10 min |
| P6-002 | Verify Endpoint Isolation | Response Eng | Network test | No connectivity | 5 min |
| P6-003 | Verify Secret Rotation | CloudSec | Secret scan | All rotated | 15 min |
| P6-004 | Verify Detection Coverage | Detection | Test cases | All detect | 30 min |
| P6-005 | Continuous Monitoring | SOC | SIEM alerts | 4hr no activity | 240 min |

#### 6B: Documentation & Reporting

| ID | Document | Owner | Template | Audience | Timeline |
|----|----------|-------|----------|----------|----------|
| P6-101 | Technical Summary | IR Lead | Incident template | Security team | 45 min |
| P6-102 | Executive Brief | SecOps Mgr | Exec template | Leadership | 30 min |
| P6-103 | Timeline Report | Scribe | Timeline template | All stakeholders | 60 min |
| P6-104 | Evidence Catalog | Forensics | Catalog template | Legal/Compliance | 40 min |

**Phase Deliverables:**
- ✅ Validation Report (`validation/validation_results.json`)
- ✅ Technical Incident Report (`reports/technical_report.md`)
- ✅ Executive Summary (`reports/executive_summary.pdf`)
- ✅ Evidence Catalog (`reports/evidence_catalog.xlsx`)
- ✅ Lessons Learned Log (`reports/lessons_learned.md`)

---

## 📊 RESPONSIBILITY MATRIX (RACI)

| Phase | IR Lead | CloudSec | IAM Admin | Response Eng | Detection | Forensics | NetSec |
|-------|---------|----------|-----------|--------------|-----------|-----------|--------|
| P0: Declaration | **A** | C | C | I | C | I | I |
| P1A: Identity | **R** | C | **A** | I | I | I | I |
| P1B: AWS | **R** | **A** | C | I | I | I | C |
| P1C: Endpoint | **R** | C | I | **A** | I | I | C |
| P2: Evidence | **A** | **R** | C | **R** | **R** | **R** | C |
| P3: Analysis | **A** | **R** | I | C | **R** | C | **R** |
| P4: Hunting | **A** | C | I | C | **R** | **R** | C |
| P5: Remediation | **A** | **R** | C | **R** | **R** | I | **R** |
| P6: Validation | **A** | **R** | **R** | **R** | **R** | **R** | **R** |

**Legend:** A=Accountable | R=Responsible | C=Consulted | I=Informed

---

## 📈 KEY PERFORMANCE INDICATORS (KPIs)

### Incident Response Metrics

| Metric | Target | Critical Threshold | Measurement |
|--------|--------|-------------------|-------------|
| Time to Declaration | < 5 min | > 15 min | Alert → INC ticket |
| Time to Containment (Identity) | < 10 min | > 20 min | INC ticket → Okta suspended |
| Time to Containment (Cloud) | < 15 min | > 30 min | INC ticket → AWS locked |
| Time to Containment (Endpoint) | < 10 min | > 20 min | INC ticket → Device isolated |
| Evidence Collection Time | < 30 min | > 60 min | Containment → Evidence secured |
| Blast Radius Time | < 40 min | > 90 min | Evidence → Impact report |
| Time to Remediation Start | < 60 min | > 120 min | Analysis → First remediation |
| Time to Full Resolution | < 4 hr | > 8 hr | Declaration → Validation complete |

### Quality Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Evidence Integrity (Hash Verification) | 100% | All artifacts hashed + verified |
| Containment Success Rate | 100% | No missed access paths |
| Detection Coverage Post-Incident | > 95% | New detections cover identified TTPs |
| Documentation Completeness | 100% | All required deliverables present |
| Stakeholder Notification SLA | < 5 min | CISO/Legal/HR notified |

---

## 🔄 CONTINUOUS IMPROVEMENT PROCESS

### Post-Incident Review Workflow

```
Incident Closure → Assign Post-Mortem Owner → Schedule Review (within 72hr)
                                                       ↓
                                    Review Meeting (All stakeholders)
                                                       ↓
                    ┌──────────────────────────────────┴────────────────────────────────┐
                    ↓                                  ↓                                  ↓
           Gap Identification                 Process Improvement          Detection Enhancement
                    ↓                                  ↓                                  ↓
           Create JIRA Issues              Update Playbooks              Deploy New Rules
                    ↓                                  ↓                                  ↓
           Assign Owners + Due Dates       Version Control Update         Test in Lab
                    ↓                                  ↓                                  ↓
           Track to Completion             Training Update                Production Deploy
                    └──────────────────────────────────┬────────────────────────────────┘
                                                       ↓
                                        Quarterly Review of All Improvements
```

### Improvement Categories

| Category | Examples | Owner | Review Cycle |
|----------|----------|-------|--------------|
| **Detection Gaps** | Missed TTPs, Late alerts | Detection Engineer | Immediate |
| **Process Gaps** | Missing procedures, Unclear ownership | IR Lead | Weekly |
| **Tool Gaps** | Missing capabilities, Integration issues | Security Architect | Monthly |
| **Training Gaps** | Knowledge deficits, Skill gaps | Security Manager | Quarterly |
| **Documentation Gaps** | Missing runbooks, Outdated procedures | Technical Writer | Bi-weekly |

---

## 🔐 SECURITY CONTROLS VALIDATION

Post-incident validation checklist for all major security controls:

| Control Area | Validation Method | Owner | Frequency |
|--------------|-------------------|-------|-----------|
| Identity & Access | IAM policy review, STS session audit | IAM Security | Post-incident + Quarterly |
| Endpoint Security | EDR coverage test, isolation test | Response Engineer | Post-incident + Monthly |
| Network Security | Firewall rule review, segmentation test | NetSec | Post-incident + Monthly |
| Cloud Security | CloudTrail coverage, Config compliance | CloudSec | Post-incident + Weekly |
| Detection & Response | SIEM rule effectiveness, alert tuning | Detection Engineer | Post-incident + Bi-weekly |
| Secrets Management | Rotation validation, access audit | CloudSec | Post-incident + Weekly |

---

## 📁 ARTIFACT STORAGE STRUCTURE

```
/incidents/
├── INC-{YYYYMMDD}-{###}/
│   ├── declaration.json
│   ├── metadata/
│   │   ├── roles_assignment.json
│   │   ├── timeline.csv
│   │   └── decisions_log.md
│   ├── artifacts/
│   │   ├── phase1/
│   │   │   ├── identity_revocation.json
│   │   │   ├── aws_access_summary.json
│   │   │   └── endpoint_status.json
│   │   ├── phase2/
│   │   │   ├── cloud/
│   │   │   ├── endpoint/
│   │   │   └── logs/
│   │   └── SHA256SUMS
│   ├── analysis/
│   │   ├── blast_radius_summary.md
│   │   ├── attack_timeline.json
│   │   └── risk_matrix.csv
│   ├── iocs/
│   │   ├── ioc_feed.json
│   │   ├── ioc_feed.stix
│   │   └── mitre_attack_mapping.json
│   ├── remediation/
│   │   ├── checklist.md
│   │   └── secret_rotation.json
│   ├── validation/
│   │   └── validation_results.json
│   ├── reports/
│   │   ├── technical_report.md
│   │   ├── executive_summary.pdf
│   │   └── lessons_learned.md
│   └── postmortem/
│       ├── review_notes.md
│       └── action_items.csv
```

---

## 🎓 TRAINING & TABLETOP EXERCISES

| Exercise Type | Frequency | Duration | Participants | Objectives |
|---------------|-----------|----------|--------------|------------|
| Full IR Tabletop | Quarterly | 3 hours | All Security + Engineering leads | Test end-to-end process |
| Containment Drill | Monthly | 1 hour | IR Lead, CloudSec, IAM, Response Eng | Speed drills on Phase 1 |
| Evidence Collection Drill | Bi-monthly | 1.5 hours | CloudSec, Forensics, Detection | Artifact collection accuracy |
| Communication Drill | Quarterly | 45 min | IR Lead, Managers, Comms | Stakeholder notification |
| Tool Failure Scenario | Quarterly | 2 hours | All Security | Backup procedures when tools fail |

---


(..pending..)

1. **Add automation integration details** (SOAR playbook mappings, API scripts)?
2. **Create a companion README** for the matrix itself?
3. **Build out specific phase runbooks** with command-line examples?
4. **Add cost/resource planning** (required tools, team sizing)?
5. **Create visual workflow diagrams** in Mermaid format?

##
##

```
EMPLOYEE DEVICE COMPROMISE (AWS) — INITIAL RESPONSE CONCURRENCY MAP (..rc4..)
                   =================================================================================

TIME HORIZON:   T0 ───▶ T+15m ───▶ T+30m ───▶ T+45m ───▶ T+60m
                (Incident Declared)   (Containment)   (Investigation)   (Stabilization)


                                 ┌────────────────────────────────────────────────────────────┐
                                 │ INCIDENT DECLARED — SEV1 / SEV2                            │
                                 │ Device compromise with AWS‑linked credentials confirmed    │
                                 └───────────────────────┬────────────────────────────────────┘
                                                         │
                                                         ▼
               ┌───────────────────────────────────────────────────────────────────────────────┐
               │ INCIDENT COMMAND CELL  (T0 → T+10 min)                                         │
               │--------------------------------------------------------------------            │
               │ • Assign Incident Commander & Scribe                                           │
               │ • Open secure war room (Slack / Zoom)                                          │
               │ • Freeze deployments / notify stakeholders                                     │
               │ • Notify Legal / HR / Executives                                               │
               │ • Define log collection & metrics export interval                              │
               └──────────────────────┬─────────────────────────────────────────────────────────┘
                                      │
       ┌──────────────────────────────┼──────────────────────────────────────────────────────────┐
       │                              │                                                          │
       ▼                              ▼                                                          ▼
┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐
│ GLOBAL USER DEACTIVATION    │  │ ENDPOINT CONTAINMENT        │  │ IDENTITY CONTAINMENT        │  │ AWS BLAST RADIUS REVIEW     │
│ (“Kill Switch”) T0 → T+10m  │  │ (Response Eng T0 → T+20m)   │  │ (IAM Sec T0 → T+25m)        │  │ (CloudSec T10 → T40m)       │
│-----------------------------│  │-----------------------------│  │-----------------------------│  │------------------------------│
│ • Trigger Global Deactivation Runbook                        │  │ • Revoke STS sessions        │  │ • Query CloudTrail / Athena │
│ • Disable user via Okta / IdP                                │  │ • Disable access keys        │  │ • Review AWS Config drift   │
│ • Kill SSO & OAuth tokens org‑wide                           │  │ • Force MFA reset            │  │ • Evaluate GuardDuty alerts │
│ • Revoke STS sessions AWS‑org wide                           │  │ • Audit IAM trust policies   │  │ • Identify modified policies│
│ • Isolate endpoint (EDR quarantine)                          │  │                              │  │ • Map impacted resources    │
│ • Verify revocation across Okta / AWS / SaaS                 │  │                              │  │ • Establish blast‑radius    │
└──────────────┬───────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘
               │                                 │                                 │                                 │
               ├─────────────────────────────────┴─────────────────────────────────┼─────────────────────────────────┤
               │                                                                   │
               ▼                                                                   ▼
┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐
│ LOG & EVIDENCE CAPTURE      │  │ OBSERVABILITY / APP LOGS    │  │ THREAT HUNTING & DETECTION  │  │ COMMUNICATION & TRACKING    │
│ (SOC / Forensics T10 → T40m)│  │ (SRE / Logging T10 → T50m)  │  │ (SOC / Detection T20 → T50m)│  │ (Comms / IR Lead Cont.)     │
│------------------------------│  │----------------------------│  │------------------------------│ │------------------------------│
│ • Snapshot SIEM search sets  │  │ • Export Kibana queries     │  │ • SIEM anomaly sweeps       │  │ • Maintain incident log     │
│ • Archive S3 / VPC / ALB logs│  │ • Capture Grafana / Loki    │  │ • Role / asset correlation  │  │ • Compile exec summaries    │
│ • Hash + timestamp evidence  │  │ • Gather WebApp / API logs  │  │ • GuardDuty pattern checks  │  │ • Decision tracking         │
│ • Secure evidence S3 bucket  │  │ • Archive Prometheus data   │  │ • IOC sweeps / enrichment   │  │ • Stakeholder comms cadence │
│ • Create evidence manifest   │  │ • Ingest to Splunk pipeline │  │ • Validate signals vs app logs│ │ • Documentation continuity │
└──────────────┬───────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘
               │                                 │                                 │                                 │
               ├─────────────────────────────────┴─────────────────────────────────┴─────────────────────────────────┤
               │
               ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ OBSERVABILITY CORRELATION HUB  (SRE + SOC Continuous)                                                              │
│--------------------------------------------------------------------------------------------------------------------│
│ • Compare metrics vs events for confirmation and false‑positive reduction                                          │
│ • Detect anomaly spikes in system metrics (CPU / traffic / auth errors)                                            │
│ • Correlate app telemetry with CloudTrail and SIEM alerts                                                          │
│ • Confirm service health / impact scope                                                                            │
│ • Feed validated signals back to SOC and IR Lead                                                                   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                                         │
                                                         ▼
                                ┌──────────────────────────────────────────────────────────────┐
                                │ INITIAL CONTAINMENT VERIFIED  (≈ T+60 min)                   │
                                │--------------------------------------------------------------│
                                │ • Global Deactivation complete (Okta + AWS + SaaS verified)  │
                                │ • Endpoint & IAM access revoked org‑wide                     │
                                │ • CloudTrail & App logs secured and hashed                   │
                                │ • Observability layer confirms no further spread             │
                                │ • Proceed to Forensics / Blast‑Radius Deep‑Dive              │
                                └──────────────────────────────────────────────────────────────┘
```

##
##

```
GLOBAL USER / DEVICE DEACTIVATION — T0 → T+10 min
                     ==================================================

                                 ┌────────────────────────────────────────
                                 │ TRIGGER CONDITION
                                 │ • Confirmed device or identity compromise
                                 │ • AWS / Okta / SOC high‑confidence alert
                                 └──────────────────────┬─────────────────
                                                        │
                                                        ▼
                 ┌────────────────────────────────────────────────────────────
                 │ INCIDENT COMMAND CELL  (IR Lead / SecOps Manager)
                 │-------------------------------------------------------------
                 │ • Approve “Global Deactivation” (“Kill Switch”)
                 │ • Assign owners (IAM, CloudSec, Response, SOC)
                 │ • Open war room, notify HR / Legal / IT
                 └──────────────────────┬─────────────────────────────
                                        │
                                        ▼
┌──────────────────────────────────────────    ┌────────────────────────────────────────     ┌───────────────────────────────────────
│ IDENTITY PROVIDER / SSO  (Okta / Azure AD)   │ CLOUD (AWS Organization / IAM / STS)        │ ENDPOINT & NETWORK SYSTEMS (EDR / VPN)
│--------------------------------------------   │-------------------------------------------   │---------------------------------------
│ • Suspend user account                       │ • Revoke STS sessions                       │ • Isolate endpoint (EDR quarantine)
│ • Terminate sessions (web / mobile)          │ • Disable access keys                       │ • Disable VPN / remote access
│ • Revoke MFA / OAuth / refresh tokens        │ • Detach IAM policies                       │ • Revoke cert / token auth
│ • Enforce password and MFA reset             │ • Block AWS SSO / federated login           │ • Disable local / AD login
│ • Verify SCIM sync to SaaS targets           │ • Rotate shared keys if applicable          │ • Confirm device isolation event
└──────────────────────┬───────────────────     └──────────────────────┬────────────────      └──────────────────────┬────────────────
                       │                                        │                                     │
                       ├────────────────────────────────────────┴────────────────────────────────────┤
                       │
                       ▼
            ┌────────────────────────────────────────────────────────────────────────────
            │ BUSINESS / SAAS SYSTEMS (via SCIM or API Integration)
            │------------------------------------------------------------
            │ • Suspend email / calendar / office suite accounts
            │ • Deactivate collaboration apps (Slack / Teams / Jira)
            │ • Remove VCS access (GitHub / GitLab / Bitbucket)
            │ • Invalidate CI/CD tokens / PATs
            │ • Rotate secrets owned by compromised user
            └──────────────────────┬────────────────────────────
                                   │
                                   ▼
            ┌────────────────────────────────────────────────────────────────────────────
            │ VERIFICATION & COMMUNICATION
            │------------------------------------------------------------
            │ • SOC verifies no active sessions remain (Okta / AWS)
            │ • Confirm endpoint is isolated (EDR status = Quarantined)
            │ • IR Lead announces “Deactivation Complete” in war room
            │ • Upload revocation logs to incident evidence store
            │ • Update timeline + UTC completion timestamp
            └────────────────────────────────────────────────────────────
```

##
##

# Incident Response Deliverables and Artifact Collection (AWS Employee Device Compromise)

This section defines the specific **artifacts to collect**, **deliverables to produce**, and **responsible owners**
during each incident phase.  
All collections should follow evidence‑handling best practices (timestamps, integrity verification, secure storage).

---

## Phase 1 — Declaration and Coordination (T0 → T+10 min)

| Category | Artifact / Deliverable | Description | Owner | Storage Location |
|-----------|------------------------|-------------|--------|------------------|
| Incident Metadata | Incident Declaration Record | Incident ID, SEV level, timestamp, assigned roles | IR Lead | /incidents/metadata/ |
| Communications | War Room Log | Chat channel transcript link, decisions log | IR Lead / Scribe | /incidents/logs/ |
| Status Snapshot | Current AWS Account Context | List of active sessions, AWS Organizations map | CloudSec | /incidents/metadata/aws_context.json |

---

## Phase 2 — Containment (T+10 → T+25 min)

| Category | Artifact / Deliverable | Description | Owner | Purpose |
|-----------|------------------------|-------------|--------|----------|
| Endpoint Forensics | Memory capture, process list, open connections | Extracted from compromised endpoint | Response Engineer | Identify malware, active C2 |
| Endpoint Summary | Device metadata (OS, hostname, serial, IP, VPN IP) | Logged from EDR/MDM | Response Engineer | Trace network access |
| IAM Data | IAM user JSON dump (`aws iam get-user`) | Baseline of identity configuration | CloudSec | Reference before revocation |
| AWS Sessions | List of active sessions (`aws sts get-caller-identity`) | Determine active consoles/tokens | IAM Security | Revoke + verify lockout |
| Credential Audit | Access key list (`aws iam list-access-keys`) | Track key rotation | IAM Security | Audit / Rotation evidence |

Deliverables:
- Isolation confirmation log
- IAM/session revocation confirmation
- Initial endpoint image or memory dump
- Containment checklist (signed by IR Lead)

---

## Phase 3 — Blast Radius & Evidence Capture (T+20 → T+40 min)

| Category | Artifact / Deliverable | Description | Owner | Storage |
|-----------|------------------------|-------------|--------|----------|
| CloudTrail Snapshot | Exported logs (JSON/GZIP) for 14 days | CloudTrail & CloudWatch | CloudSec | s3://incident-evidence/cloudtrail/ |
| AWS Config Snapshot | JSON deltas of IAM, S3, VPC, Lambda configurations | CloudSec | s3://incident-evidence/config/ |
| GuardDuty Findings | All findings (JSON export) | SOC | s3://incident-evidence/guardduty/ |
| VPC Flow Logs | Network traffic related to user/device | CloudSec | s3://incident-evidence/vpcflow/ |
| S3 Access Logs | Requests or downloads during window | SOC | s3://incident-evidence/s3access/ |
| SIEM Query Results | Raw Splunk/Chronicle logs | Detection | /incidents/logs/siem_results.json |
| IP & IOC Table | Detected malicious IPs, hashes, domains | Threat Intel | /incidents/indicators/ioc_list.csv |
| IAM Role Usage | List of assumed roles + permissions | CloudSec | /incidents/aws/roles_usage.csv |

Deliverables:
- AWS artifact package (CloudTrail + Config + GuardDuty)
- IOC summary table
- IAM access report
- Log integrity hashes

---

## Phase 4 — Threat Hunting & Analysis (T+30 → T+50 min)

| Category | Artifact / Deliverable | Description | Owner | Purpose |
|-----------|------------------------|-------------|--------|----------|
| Correlated Event Timeline | Combined timeline: EDR + CloudTrail + SIEM | Detection / IR Lead | Build event chronology |
| IOC Pivot List | IPs, hashes, user‑agents, domains | Threat Intel | Feed detection tuning |
| Malicious Artifacts | Files downloaded, scripts, processes | Forensics | Reverse engineering / signature gen |
| AWS Service Footprint | EC2/Lambda/S3 created by actor | CloudSec | Identify persistence |
| Credential Propagation | Detect reused API keys / tokens | CloudSec | Scope lateral movement |

Deliverables:
- Unified incident timeline (CSV or Markdown)
- Threat‑intel IOCs ready for blocklists
- Initial impact statement

---

## Phase 5 — Verification & Stabilization (≈ T+60 min)

| Category | Artifact / Deliverable | Description | Owner | Purpose |
|-----------|------------------------|-------------|--------|----------|
| Verification Checklist | Confirm all credentials rotated, IAM disabled | IR Lead | Containment validation |
| Detection Validation | Confirm new SIEM / GuardDuty detections active | Detection Engineer | Continuous monitoring |
| Forensic Archive | Evidence package hash manifest | Forensics | Long‑term storage integrity |
| Communication Summary | Final update to leadership | Comms Officer | Status reporting |
| Lessons Log | Immediate observed gaps | IR Lead | Entry for post‑mortem |

Deliverables:
- Containment verification memo
- Final evidence hash log
- Executive summary update

---

## Common Artifacts Collected (Cross‑Phase Overview)

| Type | Collected From | Examples |
|------|----------------|-----------|
| **Cloud Logs** | CloudTrail, Config, GuardDuty, Security Hub | Auth events, configuration changes |
| **Identity Data** | IAM, AWS SSO, Okta, STS | Sessions, access keys, role assumptions |
| **Network Data** | VPC Flow, ELB, WAF, VPN | Source IPs, ports, traffic volume |
| **System Data** | Endpoint EDR, MDM, Sysmon | Running processes, binaries, connections |
| **Indicators of Compromise (IOCs)** | Threat Intel, Network, Files | IPs, hashes, URLs, domains |
| **Artifacts for Correlation** | SIEM Export, Athena Queries | Timeline data, alert correlation |
| **Evidence Integrity** | SHA256 Hash Log | Validation for post‑event audits |

---

## Artifact Storage and Retention Policy (Example)

| Location | Type | Access Control | Retention |
|-----------|------|----------------|-----------|
| `s3://incident-evidence/cloudtrail/` | CloudTrail, Athena, Config | Write‑once bucket, versioning enabled | 1 year minimum |
| `/incidents/forensics/<incident_id>/` | Endpoint images, logs | Restricted to Forensics group | Permanent |
| `/incidents/logs/` | Chat transcripts, SIEM exports | Secure share (read‑only) | 1 year |
| `/incidents/indicators/` | IOC lists, threat intel | SOC / Detection only | 6 months |
| `/docs/postmortems/` | Final reports | All Security leads | Permanent archive |

---

## Notes and Best Practices

- **All timestamp data must be in UTC**; record source offset if known.  
- Use **SHA256 hash + timestamp** for every log file or forensic image before upload.  
- Avoid opening collected samples on production systems — use isolated analysis.
- Always capture **pre\-revocation** IAM data before disabling users, to preserve an untouched reference.
- Integrate this list with your SOAR playbooks for automation:
  - CloudTrail → export to S3
  - IAM snapshot → JSON dump  
  - SIEM snapshot → auto‑export saved search

---

**File placement:**  
`/playbooks/incident-response/runbooks/aws_employee_device_artifact_matrix.md`

##
##

# Incident Correlation Schema — AWS Employee Device Compromise

**File Path:**  
`/playbooks/incident-response/schemas/aws_incident_correlation_schema.md`

**Purpose:**  
Map artifacts collected during the incident to corresponding detections, validation methods, and final lessons learned.  
Each record describes how evidence connects to investigation goals and where it feeds future detection logic.

---

## 1. Schema Overview

| Field | Description |
|--------|-------------|
| **Artifact_ID** | Unique identifier for the evidence item (cross‑referenced with artifact matrix) |
| **Artifact_Type** | Type of evidence collected (log, config, forensic image, alert, etc.) |
| **Detection_Source** | Where the signal originated (SIEM, GuardDuty, Athena, EDR, etc.) |
| **Detection_Gap_Found** | If this evidence revealed a gap in coverage |
| **Investigation_Link** | Related step, query, or hunt that used this data |
| **Impact_Insight** | What new understanding came from this artifact |
| **Improvement_Action** | Specific change to tooling, detection, or process |
| **Owner** | Who updates detections or processes based on this item |
| **Postmortem_Tag** | Tag used in the after‑action review (e.g. "DetectionCoverage", "PlaybookUpdate") |

---

## 2. Example Correlation Records

| Artifact_ID | Artifact_Type | Detection_Source | Detection_Gap_Found | Investigation_Link | Impact_Insight | Improvement_Action | Owner | Postmortem_Tag |
|--------------|----------------|------------------|---------------------|--------------------|----------------|--------------------|--------|----------------|
| A‑CT001 | CloudTrail Log Export (14 days) | GuardDuty / Athena Query | None | “Blast Radius” analysis (phase 3) | Identified creation of rogue IAM Role within 5 min of compromise | Add CloudTrail rule to alert on inline IAM role creation | CloudSec | DetectionCoverage |
| A‑IAM002 | IAM User Configuration Dump | Athena, Manual CLI | Partial | “Identity Containment” (phase 2) | Found active access key not rotated in >90 days | Add IAM key‑age policy; automate rotation alert | IAM Security | PolicyGap |
| A‑VPC003 | VPC Flow Logs | SIEM / Splunk query | True | “Blast Radius” – network path analysis | Revealed exfil via EC2 instance using same key | Add VPC Flow correlation to SIEM; build exfil detection rule | Detection Engineer | NetworkVisibility |
| A‑EDR004 | Memory Dump / Process Snapshot | Endpoint Agent | N/A | “Endpoint Forensics” (phase 2) | Uncovered running process using AWS CLI with cached tokens | Update EDR detections for CLI abuse; train staff | Forensics | EndpointCoverage |
| A‑SIEM005 | SIEM Query Export | Splunk – GuardDuty Bridge | True | “Threat Hunting” (phase 4) | Alerts fired 10 min late due to missing API log delay | Investigate log ingestion latency; improve pipeline monitoring | SOC Engineering | LoggingPipeline |
| A‑IOC006 | Indicator List (IPs, hashes) | Threat Intel + Manual Correl. | None | “Threat Hunting” (phase 4) | Linked malicious IP to external campaign | Feed IP to blocklists & threat feeds | Threat Intel | ThreatFeedUpdate |
| A‑POST007 | Unified Timeline Report | Consolidated Evidence | None | “Verification” (phase 5) | Demonstrated TTP pattern: token reuse + manual key create | Add analytic rule: *STS token re‑use after IAM create* | IR Lead / Detection Eng | DetectionEnhancement |

---

## 3. Schema Fields with Value Guidance

| Field | Expected Format | Example |
|--------|-----------------|----------|
| **Artifact_ID** | `A-<category><sequence>` | `A-CT001`, `A-IAM002` |
| **Artifact_Type** | Controlled vocabulary: `CloudTrail Log`, `VPC Flow`, `IAM Dump`, `Memory Image`, `SIEM Query`, `IOC List`, `Config Snapshot` |  |
| **Detection_Source** | AWS service or tool where the detection came from | `GuardDuty`, `Athena`, `Splunk`, `EDR` |
| **Detection_Gap_Found** | Boolean (`True/False`) | `True` |
| **Investigation_Link** | Incident phase or specific query reference | `"Blast Radius – step 3"` |
| **Impact_Insight** | Short sentence capturing what was learned | `"Exposed S3 bucket accessible via compromised key"` |
| **Improvement_Action** | Specific change to process or tool | `"Add automated S3 public-access auditing rule"` |
| **Owner** | Functional owner (e.g., SOC, Detection Engineer, CloudSec) | `"Detection Engineer"` |
| **Postmortem_Tag** | Tag used for grouping improvements | `"PlaybookUpdate"`, `"DetectionCoverage"`, `"Training"` |

---

## 4. Example Usage in Workflow

**a. During Investigation**
1. Each artifact logged in the artifact matrix receives an `Artifact_ID`.
2. When analysts find insight or detection gaps from that artifact, they create an entry in this schema.

**b. During Post‑Incident Review**
1. Group by `Postmortem_Tag` to generate lessons‑learned categories.
2. Each “Improvement Action” becomes a JIRA or GitHub issue for remediation tracking.

**c. After Review**
1. Security Engineering validates that new detection or policy has been implemented.
2. Close item with `Status = Verified` column (if you extend this as a CSV / YAML schema).

---

## 5. Suggested Storage and Automation

| System | Purpose | Notes |
|---------|----------|-------|
| `/incidents/schema/` folder | Raw Markdown / CSV record | Reference during ongoing incidents |
| GitHub Issues automation | Auto‑create remediation tasks from new records | Connect via GitHub Actions / webhook |
| Security Tool Wiki | Sync `Improvement_Action` + `Impact_Insight` for training | Continuous improvement docs |

---

## 6. Optional Extended Columns (for YAML or DB Integration)

For more automation or SOAR import, extend fields:

```yaml
Artifact_ID: A-CT001
Artifact_Type: CloudTrail Export
Detection_Source: GuardDuty
Detection_Gap_Found: false
Severity: High
Investigation_Link: Blast-Radius-Query
Impact_Insight: Rogue IAM role created via stolen token
Improvement_Action: Add analytic detection for CreateRole + unusual user
Owner: CloudSec
Postmortem_Tag: DetectionCoverage
Status: Open
Hash: 8c12b4e1...
Integrity_Checked: true
Timestamp_Recorded: 2025-10-03T20:15:00Z
```

---

##
##
