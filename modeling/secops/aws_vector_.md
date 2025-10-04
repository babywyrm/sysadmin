
```
EMPLOYEE DEVICE COMPROMISE (AWS) — INITIAL RESPONSE MAP
                          =======================================================

TIME HORIZON:   T0 ─────▶ T+15m ─────▶ T+30m ─────▶ T+45m ─────▶ T+60m
                (Incident Declared)    (Containment)    (Investigation)   (Stabilization)


                              ┌───────────────────────────────────────────────
                              │ INCIDENT DECLARED — SEV1/SEV2
                              │ Device compromise with AWS access confirmed
                              └─────────────────────────┬──────────────────────
                                                        │
                                                        ▼
              ┌────────────────────────────────────────────────────────────────────────
              │ INCIDENT COMMAND CELL (T0 → T+10m)
              │--------------------------------------------
              │ • Assign Incident Commander & Scribe
              │ • Create secure war room (Slack, Zoom)
              │ • Freeze deployments / Notify Engineering
              │ • Notify Legal / HR / Executive stakeholders
              │ • Record all actions with timestamps
              └───────────────┬────────────────────────────────────────────────────────
                              │
        ┌─────────────────────┼──────────────────────┬───────────────────────┐
        │                     │                      │                       │
        ▼                     ▼                      ▼                       ▼
┌───────────────────────      ┌─────────────────────  ┌─────────────────────  ┌───────────────────────
│ ENDPOINT CONTAINMENT        │ IDENTITY CONTAINMENT  │ AWS BLAST RADIUS     │ LOG & EVIDENCE CAPTURE
│ (Response Engineer)         │ (Cloud/IAM Security)  │ REVIEW (CloudSec)    │ (SOC / Forensics)
│ (T0 → T+20m)                │ (T0 → T+25m)          │ (T+10m → T+40m)      │ (T+10m → T+40m)
│-----------------------------│---------------------- │---------------------- │------------------------
│ • Isolate endpoint          │ • Revoke STS sessions │ • Query CloudTrail    │ • Snapshot CloudTrail
│ • Disable VPN / SSO         │ • Disable access keys │ • Review Config drift │ • Archive logs (S3/VPC)
│ • Capture memory / process  │ • Force MFA reset     │ • Identify policy     │ • Hash & store evidence
│ • Snapshot disk             │ • Audit AssumeRoles   │ • Run Athena queries  │ • Preserve integrity
└─────────────┬───────────────┴──────────────┬────────┴────────────┬────────┴───────────────
              │                              │                     │                        │
              ├──────────────────────────────┴───────┬─────────────┴────────────────────────┤
              │                                      │                                      │
              ▼                                      ▼                                      ▼
┌───────────────────────────      ┌───────────────────────────      ┌───────────────────────────
│ THREAT HUNTING & ANALYTICS      │ COMMUNICATION & TRACKING        │ INCIDENT COMMAND UPDATES
│ (SOC / Detection)               │ (Comms Officer / IR Lead)       │ (SecOps Manager / IR Lead)
│ (T+20m → T+50m)                 │ (Continuous)                    │ (Continuous)
│-------------------------------- │-------------------------------- │--------------------------------
│ • SIEM anomaly sweeps           │ • Maintain incident log         │ • Correlate findings
│ • Look for role assumptions     │ • Summarize findings            │ • Verify containment
│ • Investigate GuardDuty hits    │ • Update executives             │ • Transition phase
│ • Correlate attack indicators   │ • Coordinate decisions          │ • Update documentation
├─────────────────────────────────┴─────────────────────────────────┴───────────────────────────
│
▼
┌────────────────────────────────────────────────────────────────────────────
│ INITIAL CONTAINMENT VERIFIED (≈ T+60 min)
│-------------------------------------------
│ • All identities locked and sessions revoked
│ • CloudTrail / forensic logs preserved
│ • Blast radius mapped
│ • No ongoing attacker activity detected
│
│ NEXT PHASE → Detailed Forensics & Post‑Incident Review
└────────────────────────────────────────────────────────────────────────────
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

**Maintainers:** SOC / CloudSec / Forensics Teams  
**Last Updated:** 2025‑10‑03
