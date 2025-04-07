


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

# 🛡️ Advanced AWS Threat Hunting & APT Detection Matrix (Revised)

This matrix provides a comprehensive breakdown of AWS-based threat behaviors, associated API events, detection strategies,
and advanced Splunk queries. Optimized for blue teams and threat hunters in cloud environments.

---

## 🔐 IAM Abuse & Privilege Escalation

| Threat Behavior                    | Sample Events / APIs                      | Detection Strategy                             | Advanced Splunk Query |
|-----------------------------------|-------------------------------------------|------------------------------------------------|------------------------|
| Role chaining / excessive access  | `AssumeRole`, `PassRole`                  | Detect chained roles and excessive use         | ```spl index=aws sourcetype="aws:cloudtrail" eventName="AssumeRole" userIdentity.type="AssumedRole" | rex field=userIdentity.arn "arn:aws:sts::(?<accountId>[^:]+):assumed-role/(?<roleName>[^/]+)" | stats count by roleName, accountId, sourceIPAddress, awsRegion, userAgent | where count > 3 ``` |
| Creation of backdoor IAM creds    | `CreateUser`, `CreateAccessKey`           | Alert on IAM user/key creation outside of CI/CD| ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("CreateUser","CreateAccessKey") | search NOT userAgent="jenkins*" | stats count by userIdentity.arn, requestParameters.userName, sourceIPAddress, eventTime | where isnull(userIdentity.sessionContext.sessionIssuer.arn) ``` |
| Dormant key reuse                 | `AccessKeyUsed`                           | Alert on reactivation of unused credentials    | ```spl index=aws sourcetype="aws:cloudtrail" eventName="AccessKeyUsed" | transaction userIdentity.accessKeyId maxspan=45d | where duration > 2592000 | table userIdentity.accessKeyId, sourceIPAddress, duration, _time ``` |

---

## 🌐 Network & Perimeter Threats

| Threat Behavior                    | Sample Events / APIs                      | Detection Strategy                             | Advanced Splunk Query |
|-----------------------------------|-------------------------------------------|------------------------------------------------|------------------------|
| Unknown outbound traffic          | VPC Flow Logs                             | Detect traffic to unknown/non-corporate IPs    | ```spl index=vpcflow sourcetype="aws:cloudwatchlogs:vpcflow" direction=EGRESS action=ACCEPT | search NOT dstaddr IN ("10.*", "172.16.*", "192.168.*") | stats count, sum(bytes) by srcaddr, dstaddr, dstport, protocol | sort - count ``` |
| Shadow VPC endpoints              | `CreateVpcEndpoint`                       | Alert on covert endpoints to sensitive APIs    | ```spl index=aws sourcetype="aws:cloudtrail" eventName="CreateVpcEndpoint" | search requestParameters.serviceName IN ("ssm.*","secretsmanager.*","s3.*") | stats count by userIdentity.arn, awsRegion, sourceIPAddress, eventTime ``` |
| NAT Gateway or wide SGs created  | `CreateNatGateway`, `AuthorizeSecurityGroupIngress` | Detect perimeter openings              | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("CreateNatGateway","AuthorizeSecurityGroupIngress") | search requestParameters.cidrIp="0.0.0.0/0" | stats count by userIdentity.arn, sourceIPAddress, requestParameters.fromPort ``` |

---

## 📤 Data Exfiltration & Access

| Threat Behavior                 | Sample Events / APIs                      | Detection Strategy                           | Advanced Splunk Query |
|--------------------------------|-------------------------------------------|----------------------------------------------|------------------------|
| Bulk object or secret reads    | `GetObject`, `GetSecretValue`             | Alert on sudden large access to sensitive data | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("GetObject","GetSecretValue") | stats count, values(requestParameters.bucketName) by userIdentity.arn, sourceIPAddress, awsRegion | where count > 100 ``` |
| Snapshot sharing or copying    | `CopySnapshot`, `ModifySnapshotAttribute` | Detect potential exfil via snapshots         | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("CopySnapshot","ModifySnapshotAttribute") | search requestParameters.createVolumePermission.add[*].group="all" OR requestParameters.createVolumePermission.add[*].userId=* | stats by userIdentity.arn, eventTime, awsRegion ``` |

---

## 🧮 Compute Abuse & Backdoors

| Threat Behavior              | Sample Events / APIs                  | Detection Strategy                          | Advanced Splunk Query |
|-----------------------------|---------------------------------------|---------------------------------------------|------------------------|
| Rogue EC2 or Lambda deployed| `RunInstances`, `CreateFunction`      | Detect compute creation by non-CI identities| ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("RunInstances","CreateFunction") | search NOT userAgent="terraform*" | stats count by userIdentity.arn, requestParameters, awsRegion ``` |
| SSM or EC2 Connect backdoor | `SendCommand`, `StartSession`         | Detect command/session hijacking            | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("SendCommand","StartSession") | search NOT userIdentity.arn IN ("arn:aws:iam::123456789012:role/SSM-Automation-Role") | stats count by userIdentity.arn, sourceIPAddress, awsRegion, eventTime ``` |

---

## 🧼 Detection Evasion

| Threat Behavior              | Sample Events / APIs                      | Detection Strategy                          | Advanced Splunk Query |
|-----------------------------|-------------------------------------------|---------------------------------------------|------------------------|
| Trail or detection disabled | `StopLogging`, `DisableGuardDuty`        | Alert on tampering with audit logs          | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("StopLogging","DisableGuardDuty","UpdateTrail") | stats count by userIdentity.arn, sourceIPAddress, awsRegion, eventTime ``` |
| Log/Alarm deletion          | `DeleteLogGroup`, `DeleteAlarms`         | Detect disabling or erasing monitoring      | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("DeleteLogGroup","DeleteAlarms") | stats count by userIdentity.arn, awsRegion, sourceIPAddress, eventTime ``` |

---

## 🔍 Reconnaissance

| Threat Behavior              | Sample Events / APIs                    | Detection Strategy                          | Advanced Splunk Query |
|-----------------------------|-----------------------------------------|---------------------------------------------|------------------------|
| Enumeration (List*, Describe*) | `ListRoles`, `DescribeInstances`     | Detect excessive AWS recon                  | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("ListRoles","DescribeInstances","ListUsers") | stats count by userIdentity.arn, sourceIPAddress, awsRegion | where count > 20 ``` |

---

## 🛠️ Persistence Techniques

| Threat Behavior               | Sample Events / APIs                     | Detection Strategy                          | Advanced Splunk Query |
|------------------------------|------------------------------------------|---------------------------------------------|------------------------|
| Trust policy change          | `UpdateAssumeRolePolicy`                 | Alert on changes to assume role targets     | ```spl index=aws sourcetype="aws:cloudtrail" eventName="UpdateAssumeRolePolicy" | rex field=requestParameters.policyDocument "\"Principal\":\s*\{\"AWS\":\s*\"(?<principal>arn:aws:iam::[^:]+:role/[^"]+)\"" | stats count by principal, userIdentity.arn, eventTime ``` |
| Malicious event triggers     | `PutRule`, `PutTargets`, `AddPermission` | Detect persistent backdoor Lambda triggers  | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("PutRule","PutTargets","AddPermission") | stats count by userIdentity.arn, requestParameters, eventTime ``` |

---

## 🌍 Time & Region Anomalies

| Threat Behavior             | Sample Events / APIs         | Detection Strategy                          | Advanced Splunk Query |
|----------------------------|------------------------------|---------------------------------------------|------------------------|
| Unusual login location/time| `ConsoleLogin`               | Detect login from geo/time outside baseline | ```spl index=aws sourcetype="aws:cloudtrail" eventName="ConsoleLogin" responseElements.ConsoleLogin="Success" | eval hour=strftime(_time, "%H") | search hour<6 OR NOT awsRegion IN ("us-west-2","us-east-1") | stats count by userIdentity.arn, sourceIPAddress, hour ``` |

---

## 🔁 Cross-Account Movement

| Threat Behavior              | Sample Events / APIs     | Detection Strategy                          | Advanced Splunk Query |
|-----------------------------|--------------------------|---------------------------------------------|------------------------|
| Cross-account role use      | `AssumeRole`             | Detect assumption into external accounts    | ```spl index=aws sourcetype="aws:cloudtrail" eventName="AssumeRole" | rex field=requestParameters.roleArn "arn:aws:iam::(?<targetAccountId>[^:]+):role/(?<roleName>[^/]+)" | stats count by targetAccountId, roleName, userIdentity.arn, sourceIPAddress ``` |

---

## 🧪 Service Misuse

| Threat Behavior              | Sample Events / APIs               | Detection Strategy                          | Advanced Splunk Query |
|-----------------------------|------------------------------------|---------------------------------------------|------------------------|
| Covert use of AWS services  | `StartExecution`, `GetSecretValue` | Detect C2 or storage via misused services   | ```spl index=aws sourcetype="aws:cloudtrail" eventName IN ("StartExecution","GetSecretValue") | search NOT userAgent="my-pipeline-agent*" | stats count by userIdentity.arn, awsRegion, eventTime ``` |

---

## ✅ Pro Tips

- Replace `index=aws` and `index=vpcflow` with your actual indexes.
- Use `lookup` tables for:
  - Known CI/CD IAM roles
  - Expected IP ranges
  - Authorized regions
- Save queries as correlation searches, then automate alerting with Slack or JIRA integrations.


