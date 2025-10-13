
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

# Verbose Edition RC2

# Global Account Deactivation Runbook v2.0
**Critical Priority - Execute Immediately on Trigger**

## Improvements & Additions

### 0. Enhanced Trigger Conditions

| Trigger | Detection Source | Auto-Execute Threshold |
|---------|-----------------|----------------------|
| AWS Console login from TOR/VPN | GuardDuty `UnauthorizedAccess:IAMUser/TorIPCaller` | High confidence |
| Multiple failed MFA attempts + success | Okta System Log | 5+ failures in 10min |
| Credential stuffing pattern | WAF/Cloudflare | 100+ attempts |
| AWS Access Key used from new ASN | CloudTrail + threat intel | New country/ISP |
| Impossible travel (Okta + AWS) | >500 miles in <1 hour | Auto-trigger |
| Secrets push to public repo | GitHub/GitLab webhook | Instant |
| Privilege escalation detected | CloudTrail `AttachUserPolicy` | Auto-trigger |

**New**: Automated trigger via Lambda→EventBridge→Step Functions

---

### 1. Pre-Execution Checklist (Parallel - 60 seconds max)

```bash
#!/bin/bash
# pre-flight-check.sh
USER_EMAIL=$1

# Capture current state BEFORE revocation
echo "[*] Capturing pre-revocation state..."

# 1. Active sessions snapshot
aws sts get-session-token --query "Credentials.SessionToken" > /evidence/${USER_EMAIL}/aws-session-pre.json
okta-api-get /api/v1/users/${USER_ID}/sessions > /evidence/${USER_EMAIL}/okta-sessions-pre.json

# 2. Current resource ownership
aws resourcegroupstaggingapi get-resources --tag-filters Key=Owner,Values=${USER_EMAIL} \
  > /evidence/${USER_EMAIL}/aws-resources-owned.json

# 3. Active VPN connections
tailscale status | grep ${USER_EMAIL} > /evidence/${USER_EMAIL}/vpn-pre.txt

# 4. GitHub active sessions
gh api /user/sessions > /evidence/${USER_EMAIL}/github-sessions-pre.json

# 5. Running ECS/Lambda with user's execution role
aws ecs list-tasks --query "taskArns[?contains(@, '${USER_EMAIL}')]" \
  > /evidence/${USER_EMAIL}/ecs-tasks-pre.json
```

**New Step 1.4**: Snapshot current privilege level
- IAM policies (direct + group)
- Okta app assignments
- GitHub org/team memberships
- Slack workspace roles

---

### 2. Enhanced Identity Provider Actions

#### Additional Okta Steps:

```typescript
// okta-lockdown.ts
async function comprehensiveOktaLockdown(userId: string) {
  // Original steps +
  
  // 2.1 Remove from ALL groups (capture before removal)
  const groups = await oktaClient.listUserGroups(userId);
  await logToS3(`pre-revocation-groups/${userId}.json`, groups);
  await Promise.all(groups.map(g => 
    oktaClient.removeUserFromGroup(userId, g.id)
  ));

  // 2.2 Revoke ALL app assignments
  const apps = await oktaClient.listUserApps(userId);
  await Promise.all(apps.map(a => 
    oktaClient.revokeAppForUser(a.id, userId)
  ));

  // 2.3 Delete WebAuthn/FIDO2 factors
  await oktaClient.deleteUserFactor(userId, 'all');

  // 2.4 Set account to LOCKED_OUT (stronger than suspended)
  await oktaClient.lifecycleOperation(userId, 'deactivate', {
    sendEmail: false // Don't alert attacker
  });

  // 2.5 Invalidate IdP tokens at Okta → AWS federation layer
  await oktaClient.clearFederationCache(userId);
}
```

**New**: Add manual break-glass account check
```bash
# Verify user isn't the ONLY admin with access
ADMIN_COUNT=$(okta-users list --filter 'profile.role eq "SUPER_ADMIN"' | wc -l)
if [ $ADMIN_COUNT -eq 1 ]; then
  echo "[!] WARNING: This is the only super admin. Escalate to CISO."
  exit 1
fi
```

---

### 3. AWS Deep Lockdown

#### Enhanced AWS Actions:

```python
# aws-comprehensive-revoke.py
import boto3
from concurrent.futures import ThreadPoolExecutor

def nuclear_option_aws_lockdown(username, org_accounts):
    """
    Zero-trust revocation across AWS Organization
    """
    
    # 3.1 Attach explicit DENY policy (overrides all allows)
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:username": username
                }
            }
        }]
    }
    
    iam = boto3.client('iam')
    iam.put_user_policy(
        UserName=username,
        PolicyName='INCIDENT_RESPONSE_DENY_ALL',
        PolicyDocument=json.dumps(deny_policy)
    )
    
    # 3.2 Delete ALL access keys (not just disable)
    keys = iam.list_access_keys(UserName=username)
    for key in keys['AccessKeyMetadata']:
        iam.delete_access_key(
            UserName=username,
            AccessKeyId=key['AccessKeyId']
        )
    
    # 3.3 Remove from ALL groups
    groups = iam.list_groups_for_user(UserName=username)
    for group in groups['Groups']:
        iam.remove_user_from_group(
            GroupName=group['GroupName'],
            UserName=username
        )
    
    # 3.4 Terminate active console session via STS
    sts = boto3.client('sts')
    # This revokes temporary credentials issued to this user
    try:
        sts.revoke_session(UserName=username)
    except:
        pass  # May not exist for some user types
    
    # 3.5 Scan for assumed roles and attach deny
    for account in org_accounts:
        # Cross-account lockdown
        role_arn = f"arn:aws:iam::{account}:role/IncidentResponseRole"
        assumed = boto3.client('sts').assume_role(
            RoleArn=role_arn,
            RoleSessionName='GlobalUserLockdown'
        )
        
        child_iam = boto3.client(
            'iam',
            aws_access_key_id=assumed['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
            aws_session_token=assumed['Credentials']['SessionToken']
        )
        
        # Repeat key deletion in child account
        try:
            child_iam.put_user_policy(UserName=username, ...)
        except child_iam.exceptions.NoSuchEntityException:
            pass  # User doesn't exist in this account
    
    # 3.6 Tag user for forensics
    iam.tag_user(
        UserName=username,
        Tags=[
            {'Key': 'IncidentID', 'Value': incident_id},
            {'Key': 'RevokedAt', 'Value': datetime.utcnow().isoformat()},
            {'Key': 'Status', 'Value': 'COMPROMISED_LOCKED'}
        ]
    )
    
    # 3.7 Scan for Lambda functions with user's credentials in env vars
    lambda_client = boto3.client('lambda')
    functions = lambda_client.list_functions()
    for func in functions['Functions']:
        env = func.get('Environment', {}).get('Variables', {})
        if any(username in str(v) for v in env.values()):
            # Disable function
            lambda_client.update_function_configuration(
                FunctionName=func['FunctionName'],
                Environment={'Variables': {}}  # Clear all env vars
            )
            print(f"[!] Cleared env vars in {func['FunctionName']}")
```

**New**: Service-specific lockdowns

```bash
# 3.8 RDS credentials rotation
aws rds modify-db-instance --db-instance-identifier prod-db \
  --master-user-password $(openssl rand -base64 32) \
  --apply-immediately

# 3.9 Secrets Manager - rotate all secrets accessed by user
for secret in $(aws secretsmanager list-secrets --query "SecretList[?LastAccessedDate>'$(date -d '7 days ago' -I)'].Name" -o text); do
  aws secretsmanager rotate-secret --secret-id $secret --rotation-lambda-arn arn:aws:lambda:...
done

# 3.10 ECR - revoke image pull permissions
aws ecr set-repository-policy --repository-name prod-app --policy-text '{
  "Statement": [{
    "Effect": "Deny",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT:user/'$USER'"},
    "Action": "ecr:*"
  }]
}'

# 3.11 EKS - remove RBAC bindings
kubectl delete rolebinding user-${USER_EMAIL} --all-namespaces
kubectl delete clusterrolebinding user-${USER_EMAIL}
```

---

### 4. Endpoint - Aggressive Containment

```powershell
# windows-endpoint-nuke.ps1
param($UserEmail)

# 4.1 Kill all processes owned by user
Get-Process -IncludeUserName | 
  Where-Object {$_.UserName -like "*$UserEmail*"} | 
  Stop-Process -Force

# 4.2 Disable local account (if exists)
Disable-LocalUser -Name $UserEmail -ErrorAction SilentlyContinue

# 4.3 Revoke cached credentials
klist purge -li 0x3e7

# 4.4 Delete user profile (nuclear option)
# wmic useraccount where name='$UserEmail' delete

# 4.5 Block at firewall level
New-NetFirewallRule -DisplayName "BLOCK_$UserEmail" `
  -Direction Outbound -Action Block `
  -Owner (Get-LocalUser $UserEmail).SID

# 4.6 EDR-specific: CrowdStrike RTR
# cs-falcon rtr contain --hostname DEVICE_ID
```

**macOS additions:**
```bash
# 4.7 Revoke sudo, kill loginwindow
dscl . -delete /Users/$USER_EMAIL
killall -u $USER_EMAIL
pmset sleepnow  # Force device to sleep
```

---

### 5. SaaS - Automated Revocation Matrix

| Service | Primary Method | Backup Method | Verification |
|---------|---------------|---------------|--------------|
| **GitHub** | PAT deletion via API | Org owner removal | `gh api /orgs/ORGNAME/members` |
| **GitLab** | Block user + token revoke | Group owner removal | API check active tokens |
| **Slack** | SCIM deactivate | Admin console | `/admin/users#deactivated` |
| **Jira/Confluence** | Atlassian Admin API | Manual UI | `GET /rest/api/3/user?accountId=` |
| **Datadog** | Disable user API | Remove from all teams | `GET /api/v1/user/$email` |
| **PagerDuty** | Delete user | Remove from schedules | Check on-call rotation |
| **1Password** | Suspend vault access | Remove from groups | Vault access logs |
| **Sentry** | Revoke API tokens | Remove from org | Check project memberships |
| **Terraform Cloud** | Delete team membership | Revoke org token | `tfe teams list-memberships` |

**New**: Automated SaaS scanner
```typescript
// saas-revocation-engine.ts
const saasIntegrations = [
  { name: 'GitHub', revokeFunction: revokeGitHub },
  { name: 'GitLab', revokeFunction: revokeGitLab },
  // ...
];

async function executeParallelRevocation(userEmail: string) {
  const results = await Promise.allSettled(
    saasIntegrations.map(async (integration) => {
      const start = Date.now();
      await integration.revokeFunction(userEmail);
      return {
        service: integration.name,
        duration: Date.now() - start,
        status: 'revoked'
      };
    })
  );
  
  // Log failures for manual followup
  results
    .filter(r => r.status === 'rejected')
    .forEach(r => {
      pagerduty.trigger({
        summary: `Manual SaaS revocation needed: ${r.reason}`,
        severity: 'critical'
      });
    });
}
```

---

### 6. Network Layer - Full Isolation

```bash
# network-quarantine.sh

# 6.1 Firewall rules (AWS Security Groups)
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxx \
  --ip-permissions IpProtocol=-1,FromPort=-1,ToPort=-1,IpRanges="[{CidrIp=${USER_LAST_IP}/32}]"

# 6.2 VPN (Tailscale/WireGuard)
tailscale logout --user $USER_EMAIL
tailscale down --user $USER_EMAIL

# 6.3 Zero Trust (Cloudflare Access / AWS Verified Access)
cloudflared access revoke --user $USER_EMAIL

# 6.4 DNS sinkhole for user's device
# Add to internal DNS: user-device.internal → 0.0.0.0

# 6.5 Certificate revocation
openssl ca -revoke /etc/ssl/certs/${USER_EMAIL}.crt \
  -keyfile /etc/ssl/private/ca.key \
  -cert /etc/ssl/certs/ca.crt

# 6.6 Kubernetes Network Policy
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-${USER_EMAIL}
spec:
  podSelector:
    matchLabels:
      user: ${USER_EMAIL}
  policyTypes:
  - Ingress
  - Egress
EOF
```

---

### 7. Enhanced Verification (Continuous Monitoring)

```python
# verification-daemon.py
import time

def continuous_verification(user_email, duration_minutes=30):
    """
    Monitor for 30min post-revocation to catch delayed activity
    """
    end_time = time.time() + (duration_minutes * 60)
    
    checks = {
        'cloudtrail': check_cloudtrail_activity,
        'okta': check_okta_logs,
        'github': check_github_audit,
        'vpc_flow': check_vpc_flow_logs,
        'waf': check_waf_logs
    }
    
    while time.time() < end_time:
        for name, check_func in checks.items():
            activity = check_func(user_email, last_check=60)
            if activity:
                pagerduty.trigger(
                    summary=f"POST-REVOCATION ACTIVITY: {name}",
                    details=activity,
                    severity='critical'
                )
                
        time.sleep(60)  # Check every minute
    
    return generate_verification_report()
```

**New checks:**
- AWS CloudTrail: `userIdentity.principalId` contains user
- VPC Flow Logs: Source IP matches user's known IPs
- S3 access logs: Check for pre-signed URLs generated before revocation
- API Gateway logs: Token usage attempts
- Lambda execution logs: Role assumption attempts

---

### 8. SOAR Workflow (Step Functions)

```json
{
  "Comment": "Global User Deactivation v2",
  "StartAt": "ValidateInput",
  "States": {
    "ValidateInput": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:ValidateUserInput",
      "Next": "ParallelSnapshot"
    },
    "ParallelSnapshot": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "SnapshotOkta",
          "States": {
            "SnapshotOkta": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:...:SnapshotOktaState",
              "End": true
            }
          }
        },
        {
          "StartAt": "SnapshotAWS",
          "States": {
            "SnapshotAWS": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:...:SnapshotAWSState",
              "End": true
            }
          }
        }
      ],
      "Next": "ParallelRevocation"
    },
    "ParallelRevocation": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "RevokeOkta",
          "States": {
            "RevokeOkta": { "Type": "Task", "Resource": "...", "End": true }
          }
        },
        {
          "StartAt": "RevokeAWS",
          "States": {
            "RevokeAWS": { "Type": "Task", "Resource": "...", "End": true }
          }
        },
        {
          "StartAt": "RevokeSaaS",
          "States": {
            "RevokeSaaS": { "Type": "Task", "Resource": "...", "End": true }
          }
        },
        {
          "StartAt": "IsolateEndpoint",
          "States": {
            "IsolateEndpoint": { "Type": "Task", "Resource": "...", "End": true }
          }
        }
      ],
      "Next": "VerificationLoop"
    },
    "VerificationLoop": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:...:ContinuousVerification",
      "TimeoutSeconds": 1800,
      "Next": "GenerateReport"
    },
    "GenerateReport": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:...:GenerateFinalReport",
      "End": true
    }
  }
}
```

---

### 9. Communication Template

```markdown
## INCIDENT ALERT: Global Account Lockdown

**User:** {{USER_EMAIL}}  
**Incident ID:** {{INC_ID}}  
**Timestamp:** {{UTC_TIMESTAMP}}  
**Commander:** {{IC_NAME}}

### Actions Taken (T+5min)
- ✅ Okta: Suspended, all sessions terminated
- ✅ AWS: 47 access keys revoked across 12 accounts
- ✅ GitHub: User removed from org, 3 PATs deleted
- ✅ Endpoint: Device isolated via CrowdStrike
- ✅ VPN: Certificate revoked, 2 active connections terminated
- ✅ Network: Firewall rules applied, Zero Trust access blocked

### Verification Status (T+30min)
- ⚠️ CloudTrail: 0 events detected post-revocation
- ⚠️ Okta logs: 0 login attempts
- ⚠️ VPC Flow: No traffic from user's device IP
- ✅ All systems nominal - no residual access detected

### Next Actions
1. Forensic imaging of endpoint (assigned to: @forensics-team)
2. Email/Slack message review (assigned to: @legal)
3. Database query log analysis (assigned to: @data-team)
4. Customer impact assessment (assigned to: @support)

**Manual Re-Enable Approval Required From:**
- CISO
- Legal
- HR
- Incident Commander
```

---

### 10. Post-Lockdown Forensics Checklist

```bash
# forensics-collection.sh

USER=$1
INC_ID=$2

mkdir -p /forensics/${INC_ID}/${USER}

# 10.1 Collect CloudTrail for past 90 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=${USER} \
  --start-time $(date -d '90 days ago' +%s) \
  > /forensics/${INC_ID}/${USER}/cloudtrail-90d.json

# 10.2 S3 access patterns
aws s3api list-objects-v2 --bucket audit-logs \
  --query "Contents[?contains(Key, '${USER}')]" \
  > /forensics/${INC_ID}/${USER}/s3-access.json

# 10.3 Database query logs
psql -h prod-db -c "SELECT * FROM pg_stat_statements WHERE usename='${USER}'" \
  > /forensics/${INC_ID}/${USER}/db-queries.csv

# 10.4 GitHub audit log
gh api /orgs/ORGNAME/audit-log --paginate -q ".[] | select(.actor == \"${USER}\")" \
  > /forensics/${INC_ID}/${USER}/github-audit.json

# 10.5 Okta System Log (extended)
curl -X GET "https://DOMAIN.okta.com/api/v1/logs?since=90d&filter=actor.alternateId+eq+\"${USER}\"" \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  > /forensics/${INC_ID}/${USER}/okta-logs-90d.json

# 10.6 Slack export (requires manual approval)
# slack-export-user ${USER} --start-date 90d

# 10.7 Email headers (O365/Google Workspace)
# Analyze for phishing, lateral movement

# 10.8 EDR timeline
# crowdstrike-falcon forensics extract --user ${USER} --days 90
```

---

### 11. Automated Testing

```python
# test-runbook.py
import pytest

def test_user_revocation_completeness():
    """
    Monthly drill: Simulate compromise and verify all steps execute
    """
    test_user = "test-compromise-user@company.com"
    
    # Execute runbook
    incident_id = trigger_global_deactivation(test_user)
    
    # Wait for completion
    time.sleep(120)
    
    # Verify Okta
    okta_status = okta_client.get_user(test_user)['status']
    assert okta_status == 'DEPROVISIONED'
    
    # Verify AWS
    aws_keys = iam.list_access_keys(UserName=test_user)
    assert len(aws_keys['AccessKeyMetadata']) == 0
    
    # Verify GitHub
    gh_membership = gh_api(f'/orgs/ORGNAME/members/{test_user}')
    assert gh_membership.status_code == 404
    
    # Verify endpoint isolation
    edr_status = crowdstrike.get_device_state(test_user)
    assert edr_status['network_isolation'] == True
    
    # Verify logs collected
    assert os.path.exists(f'/evidence/{test_user}/aws-session-pre.json')
    
    # Cleanup test user
    restore_test_user(test_user)
```

---

### 12. Metrics & SLOs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Time to Okta suspension | < 60 seconds | EventBridge → Lambda latency |
| Time to AWS key revocation | < 90 seconds | Step Functions duration |
| Time to endpoint isolation | < 2 minutes | EDR API response time |
| False positive rate | < 5% | Manual review required / total triggers |
| Mean time to full revocation | < 5 minutes | T0 → final verification complete |
| Post-revocation activity detected | 0 events | CloudTrail/Okta logs in 30min window |

---

### Key Improvements Summary:

1. **Pre-revocation snapshots** - Evidence preservation before lockdown
2. **Parallel execution** - Reduce total time from ~10min → ~5min
3. **Explicit DENY policies** - Stronger than removal (survives cache)
4. **Cross-account enforcement** - AWS Organization-wide lockdown
5. **Service-specific actions** - RDS, ECR, EKS, Secrets Manager
6. **Continuous verification** - 30min monitoring post-revocation
7. **Automated SaaS matrix** - Parallel API calls to all services
8. **Network-layer blocking** - Firewall + DNS + cert revocation
9. **Forensics automation** - Immediate evidence collection
10. **Monthly testing** - Ensure runbook stays functional

**Estimated execution time: 3-5 minutes for complete lockdown**

##
##

