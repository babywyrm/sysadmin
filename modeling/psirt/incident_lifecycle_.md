# Incident Lifecycle ..beta..

## Phase 1: Detection & Triage
- Confirm signal (SOC, Bug Bounty, AWS GuardDuty, CI/CD anomaly).
- Classify incident type and severity (SEV1–SEV5).
- Assign IC and scribe immediately.

## Phase 2: Containment & Blast Radius
- Identify affected accounts, products, or regions.
- Contain: revoke keys, isolate pods, stop pipelines.
- Blast radius analysis worksheet:
  - AWS accounts & regions
  - Products/customers
  - CI/CD artifacts & registries

## Phase 3: Remediation & Recovery
- Define remediation buckets:
  - 🔴 **Critical now (hours)** – live exploit, customer impact.
  - 🟠 **Short-term (days)** – patch rollout, credential rotation.
  - 🟡 **Medium-term (weeks)** – infra hardening, pipeline fixes.
- Execute staged rollout with regression tests.

## Phase 4: Communication
- IC updates stakeholders every 60 minutes.
- Engineering updates every 30 minutes in channel.
- Exec briefing every 2–4 hours.
- External messaging reviewed by legal/PR.

## Phase 5: Closure & Lessons Learned
- Hold after-action within 48h.
- Document root cause, timeline, mitigation, and follow-up.
- Feed lessons into detection, monitoring, and PSIRT intake.

##
##
