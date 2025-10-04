
```
EMPLOYEE DEVICE COMPROMISE (AWS) — INITIAL RESPONSE CONCURRENCY MAP (..rc4..)
                   =================================================================================

TIME HORIZON:   T0 ───▶ T+15m ───▶ T+30m ───▶ T+45m ───▶ T+60m
                (Incident Declared)   (Containment)   (Investigation)   (Stabilization)


                                 ┌────────────────────────────────────────────────────────────┐
                                 │ INCIDENT DECLARED — SEV1 / SEV2                            │
                                 │ Device compromise with AWS‑linked credentials confirmed     │
                                 └───────────────────────┬─────────────────────────────────────┘
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
