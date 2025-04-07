


# 🛡️ AWS Threat Hunting & APT Detection Matrix


| Category                 | Threat Behavior / Indicator                                               | Relevant AWS Services              | Sample Events / APIs                                             | Detection Strategy                                                                                     | Priority |
|--------------------------|---------------------------------------------------------------------------|------------------------------------|------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|----------|
| **IAM Abuse & Priv Esc** | Role chaining, excessive permissions, inline policy abuse                | IAM, STS                            | `AssumeRole`, `AttachRolePolicy`, `PutUserPolicy`, `PassRole`    | Detect privilege escalation attempts, wide permissions, unexpected role usage                          | 🔴 High  |
|                          | Backdoor user/key creation                                               | IAM                                 | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`            | Monitor for user/key creation outside normal automation                                                | 🔴 High  |
|                          | Dormant key reuse or STS abuse                                           | IAM, STS                            | `AccessKeyUsed`, `AssumeRole`                                    | Detect sudden usage of long-dormant credentials                                                        | 🟠 Med   |
| **Network & Perimeter**  | C2 traffic, TOR/VPN egress, lateral movement                             | VPC, EC2, Flow Logs                 | VPC EGRESS to unknown IPs, odd ports                             | Monitor flow logs for unknown egress, odd ports, internal pivoting                                     | 🔴 High  |
|                          | Shadow VPC endpoints (SSM, SecretsMgr)                                   | VPC                                 | `CreateVpcEndpoint`                                              | Alert on endpoint creation to sensitive services                                                       | 🟠 Med   |
|                          | IGW/NAT/SG changes enabling exfil                                        | EC2, VPC                            | `CreateInternetGateway`, `ModifySecurityGroup`                   | Watch for unauthorized perimeter changes                                                               | 🔴 High  |
| **Data Exfil / Access**  | Unauthorized S3 downloads or KMS usage                                   | S3, KMS, SecretsManager             | `GetObject`, `GetSecretValue`, `Decrypt`                         | Look for spikes in downloads, access to sensitive buckets or secrets                                   | 🔴 High  |
|                          | EBS snapshot copying/sharing                                             | EC2                                 | `CreateSnapshot`, `CopySnapshot`, `ModifySnapshotAttribute`      | Track snapshot activity across regions or external sharing                                             | 🔴 High  |
| **Compute Abuse**        | Rogue EC2 or Lambda deployments                                          | EC2, Lambda                         | `RunInstances`, `CreateFunction`                                 | Detect compute provisioning from non-CI identities                                                     | 🔴 High  |
|                          | SSM/EC2 Connect misuse                                                   | SSM, EC2                            | `SendCommand`, `StartSession`, `SendSSHPublicKey`                | Look for session establishment not tied to approved jump users                                         | 🟠 Med   |
| **Detection Evasion**    | CloudTrail, GuardDuty, Config tampering                                  | CloudTrail, GuardDuty, Config       | `StopLogging`, `UpdateTrail`, `DeleteTrail`, `DisableGuardDuty` | High-priority alerts for detection tool tampering                                                      | 🔴 High  |
|                          | Alarm or log group deletion                                              | CloudWatch                          | `DeleteLogGroup`, `DeleteAlarms`                                 | Watch for deletion or silencing of telemetry sources                                                   | 🔴 High  |
| **Reconnaissance**       | Resource enumeration using `List*`, `Describe*` APIs                     | All                                 | `ListRoles`, `DescribeInstances`, `ListBuckets`                  | Detect bulk/odd enumeration activity, especially from temp credentials                                 | 🟠 Med   |
| **Persistence**          | IAM trust policy manipulation                                            | IAM                                 | `UpdateAssumeRolePolicy`                                         | Look for changes to who can assume what roles                                                          | 🔴 High  |
|                          | Malicious Lambda triggers (S3, EventBridge, etc.)                        | Lambda, S3, EventBridge             | `AddPermission`, `PutRule`, `PutTargets`                         | Track new triggers not tied to CI/CD systems                                                           | 🟠 Med   |
|                          | EC2 user-data modification                                               | EC2                                 | `ModifyInstanceAttribute`                                        | Detect if EC2 user-data is altered post-boot                                                           | 🟠 Med   |
| **Time/Geo Anomalies**   | Logins from new geographies or odd hours                                 | IAM, CloudTrail                     | `ConsoleLogin`, `AssumeRole`                                     | Correlate login sources with expected locations/timezones                                              | 🟠 Med   |
| **Credential Abuse**     | STS token reuse, access from unexpected services                         | STS                                 | `AssumeRole`, `GetCallerIdentity`                                | Watch for repeated token use from unknown IPs or unused services                                       | 🟠 Med   |
| **Cross-Account Movement** | Role assumption into sibling/linked accounts                           | STS                                 | `AssumeRole` across accounts                                     | Alert on cross-account role use outside approved patterns                                              | 🔴 High  |
| **Service Misuse**       | Abuse of SSM, Secrets Manager, Step Functions                            | SSM, SecretsMgr, StepFunctions      | `SendCommand`, `GetSecretValue`, `StartExecution`                | Look for control plane abuse for persistence or remote execution                                       | 🟠 Med   |




# Variation

This matrix identifies key behaviors and indicators of malicious activity or APT-style persistence in AWS. 
Includes detection strategies and Splunk query examples. Designed for SOC and security engineering teams using GitHub for documentation.

---

## 🔐 IAM Abuse & Privilege Escalation

| Threat Behavior                    | Sample Events / APIs                      | Detection Strategy                             | Splunk Query (Example) |
|-----------------------------------|-------------------------------------------|------------------------------------------------|-------------------------|
| Role chaining or excessive access | `AssumeRole`, `PassRole`                  | Detect role use outside known identities       | `eventName=AssumeRole | stats by roleArn` |
| Backdoor user/key creation        | `CreateUser`, `CreateAccessKey`           | Alert on unexpected credential creation        | `eventName=CreateAccessKey | stats by userName` |
| Dormant key reuse                 | `AccessKeyUsed`                           | Alert when unused keys are reactivated         | `AccessKeyUsed | transaction maxspan=30d | duration > 2592000` |

---

## 🌐 Network & Perimeter Threats

| Threat Behavior                    | Sample Events / APIs                      | Detection Strategy                             | Splunk Query (Example) |
|-----------------------------------|-------------------------------------------|------------------------------------------------|-------------------------|
| Unknown outbound traffic          | VPC Flow Logs                             | Monitor for egress to unknown/public IPs       | `direction=EGRESS | dstaddr!=internal | stats by dstaddr` |
| Shadow VPC endpoints              | `CreateVpcEndpoint`                       | Alert on endpoints to sensitive services       | `eventName=CreateVpcEndpoint | serviceName=ssm.*` |
| NAT/IGW or SG exposure            | `CreateNatGateway`, `AuthorizeSecurityGroupIngress` | Catch perimeter exfil setup        | `eventName IN (CreateNatGateway, AuthorizeSecurityGroupIngress)` |

---

## 📤 Data Exfiltration & Access

| Threat Behavior                     | Sample Events / APIs                          | Detection Strategy                          | Splunk Query (Example) |
|------------------------------------|-----------------------------------------------|---------------------------------------------|-------------------------|
| Secrets or object download         | `GetObject`, `GetSecretValue`                 | Alert on spikes or off-hours read access    | `eventName=GetObject | stats by user, time` |
| Snapshot copying/sharing           | `CopySnapshot`, `ModifySnapshotAttribute`     | Detect cross-region or external sharing     | `eventName=CopySnapshot` |

---

## 🧮 Compute Abuse & Backdoors

| Threat Behavior              | Sample Events / APIs                  | Detection Strategy                          | Splunk Query (Example) |
|-----------------------------|---------------------------------------|---------------------------------------------|-------------------------|
| Rogue EC2 or Lambda          | `RunInstances`, `CreateFunction`      | Detect infra launched outside of pipelines  | `eventName IN (RunInstances, CreateFunction)` |
| EC2 Connect / SSM abuse      | `SendCommand`, `StartSession`         | Alert on direct access via SSM              | `eventName=SendCommand | stats by user` |

---

## 🧼 Logging & Detection Evasion

| Threat Behavior                | Sample Events / APIs                              | Detection Strategy                          | Splunk Query (Example) |
|-------------------------------|---------------------------------------------------|---------------------------------------------|-------------------------|
| CloudTrail/GuardDuty tampering| `StopLogging`, `UpdateTrail`, `DisableGuardDuty`  | Alert on disabling security tooling         | `eventName IN (StopLogging, DisableGuardDuty)` |
| Alarm/log deletion             | `DeleteLogGroup`, `DeleteAlarms`                 | Alert on deletion of logging resources      | `eventName=DeleteLogGroup` |

---

## 🔍 Reconnaissance Behavior

| Threat Behavior               | Sample Events / APIs                      | Detection Strategy                          | Splunk Query (Example) |
|------------------------------|-------------------------------------------|---------------------------------------------|-------------------------|
| Mass enumeration              | `List*`, `Describe*`, `Get*` APIs         | Flag excessive info gathering from users    | `eventName IN (ListRoles, ListUsers) | stats by user` |

---

## 🛠️ Persistence Techniques

| Threat Behavior                    | Sample Events / APIs                    | Detection Strategy                          | Splunk Query (Example) |
|-----------------------------------|-----------------------------------------|---------------------------------------------|-------------------------|
| Trust policy manipulation         | `UpdateAssumeRolePolicy`               | Alert on changes to role trust              | `eventName=UpdateAssumeRolePolicy` |
| Malicious event triggers          | `PutRule`, `PutTargets`, `AddPermission`| Detect persistence via automation triggers  | `eventName IN (PutRule, PutTargets)` |
| EC2 user-data modification        | `ModifyInstanceAttribute`              | Detect backdoors via user-data              | `eventName=ModifyInstanceAttribute` |

---

## 🌍 Time & Region Anomalies

| Threat Behavior                 | Sample Events / APIs     | Detection Strategy                                | Splunk Query (Example) |
|--------------------------------|--------------------------|---------------------------------------------------|-------------------------|
| Unusual login time/location    | `ConsoleLogin`           | Alert on geo/time anomalies                       | `eventName=ConsoleLogin | where time < 6am OR geo!=US` |

---

## 🔁 Cross-Account Movement

| Threat Behavior                 | Sample Events / APIs | Detection Strategy                                | Splunk Query (Example) |
|--------------------------------|----------------------|---------------------------------------------------|-------------------------|
| Role assumption across accounts| `AssumeRole`         | Detect roles used in unexpected accounts          | `eventName=AssumeRole | stats by awsAccountId` |

---

## 🧪 Service Misuse

| Threat Behavior                    | Sample Events / APIs                 | Detection Strategy                          | Splunk Query (Example) |
|-----------------------------------|--------------------------------------|---------------------------------------------|-------------------------|
| Covert use of Step/SecretsMgr     | `StartExecution`, `GetSecretValue`   | Alert on misuse of automation or secrets    | `eventName IN (StartExecution, GetSecretValue)` |

---


- **🔍 Tune queries** to match normal behavior (e.g., your IAM roles, CIDR ranges, approved regions).
- **📌 Correlate** with CI/CD logs, JIRA changes, or incident tickets for validation.
- **🔁 Automate** alerting and ticket creation where feasible via SOAR.

