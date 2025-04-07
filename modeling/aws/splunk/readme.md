

# 🛡️ AWS Threat Hunting & APT Detection Queries for Splunk

# Operational playbook to detect malicious behavior, persistence, and post-exploitation activity across AWS using CloudTrail, Flow Logs, and IAM telemetry.

---

## 📘 General Notes

- Replace `index=aws` with your actual CloudTrail index.
- Replace `index=vpcflow` with your VPC Flow Logs index if different.
- Tune IAM roles, source IPs, and region filters to your org’s normal patterns.
- This guide includes **behavioral**, **privilege escalation**, and **exfiltration** hunts.

---

## 🎯 CORE DETECTIONS

### ✅ 1. **Access Key Misuse / Unusual Access**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName=ConsoleLogin OR userIdentity.accessKeyId=* 
| stats count by userIdentity.arn, sourceIPAddress, eventTime, eventName
| search sourceIPAddress!=<your_corporate_IP_range>
```

---

### 🗑️ 2. **Mass Deletion Events**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("DeleteObject", "TerminateInstances", "DeleteTrail", "DeleteBucket", "DeleteSecurityGroup") 
| stats count by userIdentity.arn, eventName, sourceIPAddress, awsRegion, eventTime
```

> Tip: Look for a **high count** of similar destructive events within a short time window.

---

### ➕ 3. **New User or Access Key Creation**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("CreateUser", "CreateAccessKey", "CreateLoginProfile", "AttachUserPolicy", "PutUserPolicy") 
| stats count by userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress, eventTime
```

---

### 📤 4. **Data Exfiltration (Download APIs)**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("GetObject", "GetSecretValue", "DownloadDBLogFilePortion") 
| stats count by userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress, eventTime
```

> Alert on spikes or **large numbers** of `GetObject` from a single user/session.

---

### 🛑 5. **GuardDuty/Trail/SecurityHub Disabling**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "DisableSecurityHub", "DisableGuardDuty") 
| stats count by userIdentity.arn, eventName, sourceIPAddress, awsRegion, eventTime
```

---

## 🕵️‍♀️ APT / PERSISTENCE BEHAVIOR DETECTION

### 🧬 6. **IAM Enumeration (Recon Behavior)**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("ListRoles", "ListUsers", "GetUser", "ListPolicies", "ListAccessKeys") 
| stats count by userIdentity.arn, eventName, sourceIPAddress, awsRegion
```

---

### 🕸️ 7. **STS AssumeRole from New Regions or Identities**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName="AssumeRole" 
| stats count by userIdentity.arn, requestParameters.roleArn, sourceIPAddress, awsRegion, eventTime
```

---

### 🔐 8. **IAM Privilege Escalation Attempts**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("iam:PassRole", "iam:CreatePolicy", "iam:AttachRolePolicy", "PutRolePolicy", "UpdateAssumeRolePolicy") 
| stats count by userIdentity.arn, eventName, requestParameters.roleName, sourceIPAddress, eventTime
```

---

### 🛰️ 9. **Snapshot Copying / Data Leakage via Snapshots**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("CreateSnapshot", "CopySnapshot", "ModifySnapshotAttribute") 
| stats count by userIdentity.arn, eventName, sourceIPAddress, requestParameters, eventTime
```

---

### 🛠️ 10. **Rogue EC2 / Lambda / VPC Deployments**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("RunInstances", "CreateFunction", "CreateVpcEndpoint") 
| stats count by userIdentity.arn, eventName, awsRegion, sourceIPAddress, eventTime
```

---

### 💀 11. **SSM Session Abuse or EC2 Connect Hijacking**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("SendCommand", "StartSession", "SendSSHPublicKey", "StartInstances") 
| stats count by userIdentity.arn, sourceIPAddress, awsRegion, eventTime
```

---

### 🧙 12. **Access Key Dormant Then Suddenly Active**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName="AccessKeyUsed" 
| transaction userIdentity.accessKeyId maxspan=30d
| search duration > 2592000  // >30 days dormant
| table userIdentity.accessKeyId, sourceIPAddress, eventTime
```

---

## 🌐 VPC FLOW LOG HUNTS

### 🚨 13. **Unexpected Outbound Connections (Exfil/Beaconing)**

```spl
index=vpcflow sourcetype="aws:cloudwatchlogs:vpcflow" 
action=ACCEPT direction=EGRESS 
| search dstaddr!=<your_internal_IP_range>
| stats count by srcaddr, dstaddr, dstport, protocol, bytes, packets
| sort - count
```

---

### 🚧 14. **Traffic on Unexpected Ports**

```spl
index=vpcflow sourcetype="aws:cloudwatchlogs:vpcflow" 
action=ACCEPT dstport IN (22, 3389, 5985, 8080, 8443, 31337)
| stats count by srcaddr, dstaddr, dstport, protocol, bytes, packets
```

---

### 🌍 15. **East-West Lateral Movement**

```spl
index=vpcflow sourcetype="aws:cloudwatchlogs:vpcflow" 
action=ACCEPT direction=INGRESS 
| stats count by srcaddr, dstaddr, dstport, protocol
| where srcaddr LIKE "10.%" AND dstaddr LIKE "10.%"
```

---

## 🛡️ BONUS: Multi-Account/Org Wide Monitor (Splunk ES Style)

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName=* 
| stats count by awsAccountId, eventName, userIdentity.arn, sourceIPAddress, awsRegion
```

Use this to:
- Build baselines
- Map normal vs anomalous actions
- Feed threat scoring rules or correlation searches

---

## 🧰 Toolchain Suggestions

Pair this with:

| Tool            | Use Case                             |
|-----------------|--------------------------------------|
| Prowler         | Baseline config security             |
| CloudSplaining  | IAM policy risk scoring              |
| PMapper         | Privilege escalation path mapping    |
| Cartography     | Infra + identity graphing            |
| Steampipe       | Custom SQL compliance/threat queries |
