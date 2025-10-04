
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
