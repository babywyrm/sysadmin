
# Global Account Deactivation Runbook ..beta..
### (Triggered at T0 — Employee Device / Account Compromise)

**Objective:**  
Immediately revoke, block, and expire all active sessions, credentials, and tokens for a single user or identity across all environments (endpoint, Okta, AWS, SaaS, code repos, VPN, etc.).

---

## 0. Trigger Condition

| Trigger | Examples |
|----------|-----------|
| Confirmed or suspected credential theft | Device malware, phishing, credential leak |
| High‑confidence SOC alert | CloudTrail anomaly, GuardDuty detection, impossible travel |
| Incident Commander directive | Declared SEV 1 or SEV 2 |

Immediate action — **no waiting for analysis**.

---

## 1. Incident Initiation Check

| Step | Description | Owner |
|------|--------------|--------|
| 1.1 | Validate identity of compromised user and collect key identifiers (email, username, employee ID, user UUID). | Incident Commander |
| 1.2 | Open incident channel / war room with “Kill User Access” label. | IR Lead |
| 1.3 | Confirm managerial & HR notification (to avoid unintentionally locking wrong user). | SecOps Manager |

---

## 2. Centralized Identity Provider (Okta or IdP)

| Action | Description | Owner | Tool / Example |
|---------|-------------|--------|----------------|
| Disable User Account | Suspend login via all federated apps. | IAM / Identity Engineer | Okta Admin → Users → Suspend User <br>or `okta-users deactivate <user-id>` |
| Clear Sessions | Terminate all web, desktop, and mobile sessions. | IAM / Okta Admin | `POST /api/v1/users/<userId>/lifecycle/reset_factors` |
| Revoke Refresh / OAuth Tokens | Disable all existing tokens across integrated apps. | IAM / Okta | `DELETE /api/v1/users/<userId>/tokens` |
| Force Password & MFA Reset | Ensure new device enrollment. | IAM / Okta | `okta-users change-password` |
| Verify Federation | Confirm SCIM or SSO pushes deactivation to downstream apps (Slack, GitHub, Jira). | Identity Engineer |

**Deliverables:**  
- Okta session revocation log  
- IdP deactivation confirmation screenshot / JSON export  

---

## 3. Cloud Environment (AWS Organization)

| Action | Description | Owner | Command / Note |
|---------|-------------|--------|----------------|
| Revoke AWS STS sessions | Expire all temp tokens. | CloudSec | `aws sts revoke-session --user-name <username>` |
| Deactivate Access Keys | Disable keys immediately. | CloudSec | `aws iam update-access-key --user-name <u> --status Inactive --access-key-id <k>` |
| Detach User Policies | Remove directly attached IAM policies. | CloudSec | `aws iam detach-user-policy ...` |
| Disable AWS SSO Account | Block federated login for that user. | IAM Admin | AWS SSO Console → Users → Disable |
| Search Organization for Collateral Keys | Repeat deactivation in all accounts (Org‑Linked). | CloudSec / Automation | `aws orgs list-accounts` + looped IAM disable script |

**Deliverables:**  
- AWS access revocation log (CLI output)  
- IAM JSON before/after snapshot  

---

## 4. Endpoint & Device Access

| Action | Description | Owner |
|---------|-------------|--------|
| Isolate device in EDR / MDM | Network quarantine mode. | Response Engineer |
| Disable VPN credentials | Immediately revoke certs / MFA tokens. | IT Network Ops |
| Remove from MDM group | Block OTA profiles; revoke admin privileges. | IT Ops |
| Lock out local OS login | If AD‑joined, disable AD account. | SysAdmin |

**Deliverables:**  
- EDR isolation event ID  
- VPN disconnect log entry  

---

## 5. SaaS / Business Systems

| Service | Example Revocation Method |
|----------|---------------------------|
| **Email / Office Suite** | Suspend mailbox, revoke OAuth tokens. |
| **Collaboration tools (Slack, Notion, Teams)** | Admin console → Deactivate user; end all sessions. |
| **Version control (GitHub / GitLab)** | Remove user + personal tokens (PATs). |
| **Issue tracking (Jira, Asana)** | Suspend account via SCIM or API. |
| **Password vaults / Secrets managers** | Invalidate access shares, rotate secrets owned by user. |

**Deliverables:**  
- “SaaS Access Removed” checklist (automated OKTA report)  

---

## 6. Network and Infrastructure Layers

| Action | Description | Owner |
|---------|-------------|--------|
| Firewall / VPN | Remove user IP / certificate from whitelist. | NetSec |
| JumpHost / Bastion | Expire session, change shared keys if used. | InfraSec |
| CI/CD Systems | Revoke API tokens, invalidate sessions. | DevSecOps |

---

## 7. Verification and Validation

| Step | Verification | Owner |
|------|---------------|--------|
| 7.1 | Check Okta event log for “deactivate” and “session termination” entries. | IAM Admin |
| 7.2 | Search AWS CloudTrail for any post‑revocation activity (must = 0). | CloudSec |
| 7.3 | Confirm endpoint isolation via EDR console. | Response Engineer |
| 7.4 | SOC verifies no new authentication logs from that user after T0 + 5 min. | SOC / Detection |

**Deliverables:**  
- Access termination verification report  
- Unified timeline entry (revocation completed @UTC timestamp)  

---

## 8. Automation / SOAR Hooks

| Function | Integration | Command |
|-----------|--------------|----------|
| SOAR Workflow Trigger | “User‑Deactivation” scenario | Auto‑calls Okta + AWS deactivation APIs |
| Evidence Export | S3 `incident-evidence/access_revocation/` | JSON of revoked sessions |
| Slack Notification | `#ir-warroom` confirmation bot | Posts “All sessions terminated for <user>” |

**Recommended Script Skeleton (Bash):**

```bash
#!/bin/bash
USER=$1
echo "[+] Starting global deactivation for: $USER"

# Okta deactivate
okta-users deactivate $USER
okta-sessions revoke --user-id $USER

# AWS org loop disable
for acct in $(aws orgs list-accounts --query "Accounts[].Id" --output text); do
  echo "  [-] Disabling in account $acct"
  aws iam update-access-key --access-key-id $(aws iam list-access-keys \
    --user-name $USER --query 'AccessKeyMetadata[].AccessKeyId' --output text) \
    --status Inactive --user-name $USER --profile $acct
done

echo "[+] Completed global session revoke at $(date -u)"
```

*(Integrate into SOAR or CI/CD pipeline for reproducible, audited execution.)*

---

## 9. Communication Deliverables

- IR Alert: “User ID <xyz> – Global Account Lockdown @ T0:00 UTC”
- Stakeholder brief: managers, HR, legal, engineering leadership.
- Post‑revocation validation summary added to incident channel.
- Add timeline entry to `/incidents/<id>/timeline.md`.

---

## 10. Post‑Lockdown Next Steps

1. Transition to **Endpoint Forensics**
2. Start **Blast Radius Assessment**
3. Confirm **User Re‑enable only after full incident closure**

---

**File:** `/playbooks/incident-response/runbooks/global_user_deactivation.md`  
**Maintainers:** Identity Security / SecOps / IR  
**Last Updated:** 2025‑10‑03
