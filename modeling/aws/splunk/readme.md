

# 🛡️ AWS APT Threat Hunting Queries in Splunk

Splunk searches for identifying advanced attacker behavior using CloudTrail and Flow Logs. 
Use with your configured data sources (e.g., `aws:cloudtrail`, `aws:cloudwatchlogs:vpcflow`, etc.)

---

## 📘 General Notes
- Replace `index=aws` with your actual index name.
- Tune region/IP/account filters to your environment.
- Use `stats`, `timechart`, or `table` for visual dashboards.

---

## 🔍 1. **SSM, EC2 Connect, and Lateral Movement Tools**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("SendCommand", "StartSession", "SendSSHPublicKey", "StartInstances", "AttachVolume") 
| stats count by eventName, userIdentity.arn, sourceIPAddress, awsRegion, eventTime
```

---

## 🎭 2. **Unexpected STS AssumeRole Activity**

```spl
index=aws sourcetype="aws:cloudtrail" eventName="AssumeRole"
| stats count by userIdentity.arn, requestParameters.roleArn, sourceIPAddress, awsRegion, eventTime
```

> 🔥 Watch for `AssumeRole` from federated users or cross-account IDs.

---

## 🏗️ 3. **Suspicious EC2 / Lambda / VPC Endpoint Creations**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("RunInstances", "CreateFunction", "CreateVpcEndpoint") 
| stats count by userIdentity.arn, eventName, awsRegion, sourceIPAddress, requestParameters, eventTime
```

---

## 🔐 4. **IAM Role and Policy Modifications**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("PutRolePolicy", "CreatePolicy", "AttachRolePolicy", "UpdateAssumeRolePolicy") 
| stats count by userIdentity.arn, eventName, requestParameters.roleName, awsRegion, sourceIPAddress, eventTime
```

---

## 📅 5. **Dormant Access Key Suddenly Used**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName="AccessKeyUsed" 
| transaction userIdentity.accessKeyId maxspan=30d
| search duration > 2592000  // >30 days dormant
| table userIdentity.accessKeyId, sourceIPAddress, eventTime
```

> 💡 You may need to enable `AccessKeyUsed` events via CloudTrail’s data events.

---

## 🧼 6. **Trail / Logging Tampering**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DisableSecurityHub") 
| stats count by userIdentity.arn, eventName, sourceIPAddress, awsRegion, eventTime
```

---

## 🧭 7. **VPC Flow Log: Unexpected Outbound Traffic**

> Use this to identify traffic going to suspicious IPs, e.g. TOR, VPN, external C2.

```spl
index=vpcflow sourcetype="aws:cloudwatchlogs:vpcflow" 
action=ACCEPT direction=EGRESS 
| search dstaddr!=<internal IP ranges>
| stats count by srcaddr, dstaddr, dstport, protocol, bytes, packets
| sort - count
```

---

## 🧬 8. **IAM Privilege Escalation via PassRole or CreatePolicy**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("iam:PassRole", "iam:CreatePolicy", "iam:AttachRolePolicy") 
| stats count by userIdentity.arn, eventName, requestParameters.roleName, awsRegion, sourceIPAddress
```

---

## 🛰️ 9. **Snapshot Copy or Sharing (Data Exfil Path)**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("CreateSnapshot", "CopySnapshot", "ModifySnapshotAttribute") 
| stats count by userIdentity.arn, eventName, sourceIPAddress, requestParameters, eventTime
```

---

## 🕵️‍♀️ 10. **IAM Enumeration (Recon Behavior)**

```spl
index=aws sourcetype="aws:cloudtrail" 
eventName IN ("ListRoles", "ListUsers", "GetUser", "ListPolicies", "ListAccessKeys") 
| stats count by userIdentity.arn, eventName, sourceIPAddress, awsRegion
```

---

## 🛠️ Tips for Splunk Flow Log Integration

If you're pulling logs from an S3 flow logs bucket:
1. Ensure you’re ingesting to `sourcetype=aws:cloudwatchlogs:vpcflow`.
2. Use props/transforms to parse if needed (e.g. CSV fields: `srcaddr`, `dstaddr`, `srcport`, etc.).
3. Consider auto-tagging outbound vs inbound traffic via the interface ID.

---



Happy hunting 🧙‍♂️
