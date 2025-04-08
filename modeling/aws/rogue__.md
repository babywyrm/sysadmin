# Advanced Threat Modeling Workbook  
## Internal Threat Actor - AWS Environment - Beta Edition

---

## 🧭 Incident Overview

| Item                  | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| Incident ID           | `IR-YYYY-###`                                                 |
| Date Identified       |                                                               |
| Actor Type            | Internal / Insider / Privileged / Credential Compromise       |
| Origin                | GitHub / CLI / CI/CD / Console / VPN                          |
| Accounts Affected     | List AWS account IDs or Org units                             |
| Initial Entry Vector  | Describe known method (e.g., stolen key, misused pipeline)    |
| Current Status        | Ongoing / Contained / Eradicated                              |

---

## 🔐 Credential & Secret Exposure

### Terraform + CI Secrets

| Item                                  | Action                                | Status        | Notes                  |
|---------------------------------------|----------------------------------------|---------------|------------------------|
| TF private key rotation               | Rotate all `.pem`, `.tfvars`, SSH keys|               |                        |
| Terraform backend rekeying            | S3 / Terraform Cloud / DynamoDB       |               |                        |
| State file exposure review            | Pull history, grep for secrets        |               |                        |
| CI/CD secrets                         | Rotate GitHub Actions / GitLab / etc. |               |                        |

---

## 🧪 Artifact & Registry Compromise

### Container / Build Artifact Risk

| Item                                  | Action                                | Status        | Notes                  |
|--------------------------------------|----------------------------------------|---------------|------------------------|
| ECR tags & digests audit             | Compare known-safe vs unknown         |               |                        |
| Artifactory artifact hash integrity  | Diff artifact versions over time      |               |                        |
| GitHub release auditing              | Validate checksums on CLI builds      |               |                        |
| CI/CD pipeline tampering             | Review buildspecs, YAMLs, env vars    |               |                        |

---

## ☁️ Cloud Persistence Mechanisms

### IAM / Roles / STS

| Item                                  | Action                                | Status        | Notes                  |
|--------------------------------------|----------------------------------------|---------------|------------------------|
| IAM trust policy audit               | Identify risky `sts:AssumeRole` edges |               |                        |
| Role creation/modification log       | CloudTrail filter `CreateRole`, `PutRolePolicy` |         |                        |
| `iam:PassRole` usage scan            | Track delegation paths                |               |                        |
| IAM inline policies                  | Detect suspicious inline permissions  |               |                        |

### Lambda / Scheduled Backdoors

| Item                                  | Action                                | Status        | Notes                  |
|--------------------------------------|----------------------------------------|---------------|------------------------|
| Lambda `LastModified` timeline       | Sort all functions by timestamp       |               |                        |
| EventBridge scheduled tasks          | Detect non-team-created rules         |               |                        |
| StepFunctions or CW Events           | List state machines and cron rules    |               |                        |

---

## 📁 Data/Access Layer Exfil & Abuse

### Secrets, Keys, DNS, Network

| Item                                  | Action                                | Status        | Notes                  |
|--------------------------------------|----------------------------------------|---------------|------------------------|
| Secrets Manager & SSM audit          | Identify new/modified secrets         |               |                        |
| KMS key access logs                  | Track grant, decrypt, encrypt usage   |               |                        |
| DNS record manipulation              | Look for CNAMEs to attacker infra     |               |                        |
| VPC endpoints & flow logs            | Watch for internal exfil              |               |                        |

---

## 🕵️ Splunk IOCs and Queries

| Goal                                 | Splunk Search Snippet                                                                                           |
|--------------------------------------|------------------------------------------------------------------------------------------------------------------|
| IAM Role Abuse                       | `index=aws sourcetype="aws:cloudtrail" eventName IN ("PassRole","AssumeRole")`                                  |
| Secrets Enumeration                  | `index=aws sourcetype="aws:cloudtrail" eventName IN ("GetSecretValue","ListSecrets")`                           |
| Lambda Modifications                 | `index=aws sourcetype="aws:cloudtrail" eventSource=lambda.amazonaws.com eventName IN ("UpdateFunctionCode","CreateFunction")` |
| Schedule Time Bombs                 | `index=aws sourcetype="aws:cloudtrail" eventName IN ("PutRule", "PutTargets") sourceIPAddress!=internal_ranges` |
| Suspicious EC2 User Data             | `index=aws sourcetype="aws:cloudtrail" eventName="RunInstances" | search userData`                             |
| Artifact Push from Actor             | `index=aws sourcetype="aws:cloudtrail" eventName="PutImage" userIdentity.arn="arn:aws:iam::<acct>:user/badactor"` |
| Unexpected KMS Key Grants            | `index=aws sourcetype="aws:cloudtrail" eventName="CreateGrant"`                                                 |
| CloudTrail Logging Tampering        | `index=aws sourcetype="aws:cloudtrail" eventName IN ("StopLogging","DeleteTrail")`                              |
| Modified DNS Records                 | `index=aws sourcetype="aws:cloudtrail" eventName IN ("ChangeResourceRecordSets")`                               |
| New IAM Users                        | `index=aws sourcetype="aws:cloudtrail" eventName="CreateUser"`                                                  |
| CodeBuild Modification               | `index=aws sourcetype="aws:cloudtrail" eventName="UpdateProject"`                                               |
| Resource Tag Tampering               | `index=aws sourcetype="aws:cloudtrail" eventName="TagResource"`                                                 |

---

## ✅ Response Plan

| Action                                 | Owner         | Status        | Notes                      |
|----------------------------------------|---------------|---------------|----------------------------|
| Suspend actor's IAM principal(s)       |               |               |                            |
| Rotate critical TF and CI/CD secrets   |               |               |                            |
| Trigger full ECR image verification    |               |               |                            |
| Review Lambda schedule execution       |               |               |                            |
| Compile DNS + VPC endpoint inventory   |               |               |                            |

---

## 📎 Attachments

- [ ] IAM diff reports
- [ ] Lambda `LastModified` timeline
- [ ] Full GitHub diff by user/PR
- [ ] Athena/CloudTrail filtered logs

---

## 📝 Notes

Add notes, references, and tracking info here.

- Tag: `IR-YYYY-###`
- Timeline: [Start] → [Detection] → [Response] → [Recovery]
- Hash of affected binaries or artifacts (if any)


##
##

