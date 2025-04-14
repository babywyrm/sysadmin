
---

# AWS Threat Hunting & APT Detection Runbook (Beta)

**Version:** 0.9 
**Last Updated:** [someday]

**Objective:**  
To proactively detect, investigate, and respond to malicious activity and advanced persistent threats (APTs) in the AWS environment. 
This runbook is designed for a SOC team (approximately five members) and includes roles, responsibilities, and detailed Splunk queries for rapid triage.

---

## 1. Overall Methodology

### 1.1. Preparation  
Before active threat hunting begins, ensure that you have:

- **Centralized Logging & SIEM Ingestion:**  
  * CloudTrail logs are collected across all regions.
  * VPC Flow Logs are enabled for all critical VPCs.
  * Logs are ingested into your SIEM (e.g., Splunk) with dedicated indexes (for example: `aws` for CloudTrail; `vpcflow` for VPC Flow).
  
- **Baseline Configurations:**  
  * A documented inventory of IAM roles, policies, networks, instances, and other resources.
  * Lookup tables for expected IP ranges, standard IAM accounts (CI/CD service accounts), and approved regions.
  
- **Detection Tools:**  
  * AWS GuardDuty is enabled.
  * AWS Config is tracking critical changes.
  * Splunk dashboards and alerts are preconfigured for known threat indicators.

### 1.2. Team Structure & Responsibilities
For a SOC team of five, you can structure roles as follows:

1. **Team Lead / Incident Manager (Person A):**  
   - Oversee overall operations, make decisions on threat prioritization, and coordinate communications with management and external partners.
   
2. **Cloud Forensics Specialist (Person B):**  
   - Focus on log correlation, evidence collection (CloudTrail, VPC Flow, Config logs) and forensic analysis of compromised IAM roles, EC2 instances, etc.
   
3. **Threat Intelligence & Triage Analyst (Person C):**  
   - Monitor alerts for indicators like IAM abuse, network anomalies, and suspicious API calls. Initiate triage procedures.
   
4. **Network Security Analyst (Person D):**  
   - Analyze VPC Flow Logs and CloudWatch metrics for exfiltration, unexpected egress, or lateral movement.
   
5. **Endpoint / Compute Analyst (Person E):**  
   - Investigate unusual EC2 or Lambda deployments, identify rogue compute assets, and validate any anomalies such as unauthorized deployments.

Each analyst is responsible for monitoring specific detection queries, documenting findings, and escalating when multiple alerts or corroborating evidence is available.

---

## 2. Threat Categories and Detailed Splunk Queries

Below is a menu of threat categories, investigative steps, and sample Splunk queries for each. Use these queries as a starting point, and tune thresholds or enrich with your environment-specific fields.

### 2.1. IAM Abuse & Privilege Escalation

#### Indicators:
- Unusual role chaining or role assumption.
- Creation of IAM users, roles, or access keys outside normal operations.
- Policy changes that grant excessive privileges.

#### Sample Splunk Queries:
- **Role Chaining / AssumeRole Events:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName="AssumeRole" userIdentity.type="AssumedRole"
  | stats count by userIdentity.arn, sourceIPAddress, eventTime, requestParameters.roleArn
  | sort 0 - count
  ```
- **Creation of Backdoor Credentials:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("CreateUser", "CreateAccessKey", "CreateLoginProfile")
  | table eventTime, eventName, userIdentity.arn, requestParameters.userName, sourceIPAddress
  ```
- **Policy Modification / Inline Policy Changes:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("PutUserPolicy", "AttachRolePolicy", "PutRolePolicy")
  | table eventTime, eventName, userIdentity.arn, requestParameters.policyName, sourceIPAddress
  ```

#### Triage Steps:
1. Verify if the actions align with the approved automation (check roles, CIDRs, associated service accounts).
2. Correlate with user activity and incident timelines.
3. If abuse is confirmed, isolate affected credentials and escalate immediately.

---

### 2.2. Network & Perimeter Threats

#### Indicators:
- Unapproved egress traffic to non-corporate IPs or suspicious ports.
- Creation of unexpected VPC endpoints or unauthorized SG modifications.
  
#### Sample Splunk Queries:
- **Unknown Egress Traffic:**
  ```spl
  index=vpcflow sourcetype="aws:cloudwatchlogs:vpcflow" direction=EGRESS action=ACCEPT 
  | where NOT cidrmatch("10.0.0.0/8", srcaddr) AND NOT cidrmatch("192.168.0.0/16", srcaddr)
  | stats count by dstaddr, dstport, srcaddr, interfaceId
  | sort 0 - count
  ```
- **Unauthorized SG/Intranet Changes:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("CreateSecurityGroup", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress")
  | table eventTime, eventName, userIdentity.arn, requestParameters, sourceIPAddress
  ```

#### Triage Steps:
1. Identify the source of unusual traffic—whether it is from production or suspect instances.
2. Verify if any IPS/IDS or firewall rules enforced by AWS (like Security Groups) have been tampered with.
3. Alert network security analysts to perform deeper packet inspection and further monitor exfiltration channels.

---

### 2.3. Data Exfiltration & Access

#### Indicators:
- Bulk S3 download activities from unusual IPs.
- Unauthorized KMS usage or Secrets Manager retrievals.

#### Sample Splunk Queries:
- **Suspicious S3 Downloads or Listing:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("GetObject", "ListBucket")
  | stats count by requestParameters.bucketName, sourceIPAddress, userIdentity.arn
  | where count > 50
  ```
- **KMS / Secrets Manager Access:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("Decrypt", "GetSecretValue")
  | table eventTime, eventName, userIdentity.arn, requestParameters, sourceIPAddress
  ```

#### Triage Steps:
1. Compare activity profiles against the baseline. Significant deviations in S3 read operations should trigger immediate alerts.
2. Investigate if the accessed secrets or objects are sensitive and if they originate from unauthorized sources.
3. Apply tighter IAM policies and network isolation as necessary.

---

### 2.4. Compute Abuse & Backdoors

#### Indicators:
- Rogue EC2 instances or Lambda functions.
- Abnormal SSM or EC2 Connect sessions from unexpected users.

#### Sample Splunk Queries:
- **Unauthorized Instance Launches:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName="RunInstances"
  | stats count by userIdentity.arn, sourceIPAddress, requestParameters.instanceType
  | sort 0 - count
  | where count > 1
  ```
- **SSM and EC2 Connect Sessions:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("SendCommand", "StartSession")
  | table eventTime, eventName, userIdentity.arn, sourceIPAddress
  ```

#### Triage Steps:
1. Identify off-hours or unapproved instance spawns.
2. Quickly verify the instance details in the AWS console; if anomalies are found, isolate the instance.
3. Investigate whether the new deployment was initiated by a legitimate automation system.

---

### 2.5. Detection Evasion

#### Indicators:
- Disabling or modification of CloudTrail, GuardDuty, or other critical logging services.
- Deletion of CloudWatch log groups or alarms.

#### Sample Splunk Queries:
- **Audit Log Tampering:**
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("StopLogging", "DeleteTrail", "DisableGuardDuty", "DeleteLogGroup", "DeleteAlarms")
  | table eventTime, eventName, userIdentity.arn, sourceIPAddress
  ```

#### Triage Steps:
1. Rapidly check the health status of CloudTrail, GuardDuty, and CloudWatch.
2. Confirm with your AWS admin team whether any planned updates are affecting logging.
3. If malicious, lock down the environment and preserve logs for forensic analysis.

---

## 3. Incident Response & Escalation

### 3.1. Immediate Actions (when high severity detections occur)
- **Isolate Affected Resources:**  
  Block endpoints, quarantine suspect EC2 instances via security groups, or use AWS Systems Manager to disable network access.
- **Revoke/Roll Credentials:**  
  Immediately disable or rotate compromised IAM credentials.
- **Notify Incident Response:**  
  The SOC Team Lead must notify internal stakeholders and trigger incident response protocols.

### 3.2. Forensic Collection
- **Preserve CloudTrail & VPC Logs:**  
  Archive the logs associated with suspicious events.
- **Snapshot Resources:**  
  If compute instances are affected, create snapshots for later forensic analysis.
- **Document Findings:**  
  Use your SIEM and ticketing system to track events, mitigating steps, and timeline.

### 3.3. Post-Incident Activities
- **Review and Update Policies:**  
  Adjust IAM, Security Group, and audit policies to close exploited gaps.
- **Conduct a “Lessons Learned” Session:**  
  Perform a retrospective review with the SOC team to improve detection, response, and preventive measures.
- **Report to Stakeholders:**  
  Prepare an incident summary including timeline, affected assets, remediation steps, and further recommendations.

---

## 4. SOC Team Workflow for a Malicious Actor

### Assignment:
- **Team Lead (Person A):**  
  - Monitor overall alerts; coordinate triage tasks and assign roles based on detected events.
  
- **IAM/Cloud Log Analyst (Person B):**  
  - Focus on IAM abuse queries (role assumption, credential creation) and cross-verify against known baselines.
  
- **Network/Forensics Analyst (Person C):**  
  - Drill down on VPC Flow anomalies and instance-level network traffic. Isolate suspicious compute instances if necessary.
  
- **Compute & Endpoint Specialist (Person D):**  
  - Focus on unusual EC2/Lambda deployments and SSM/EC2 Connect sessions; quickly verify in the AWS console.
  
- **Data & Exfil Analyst (Person E):**  
  - Monitor S3, KMS, and Secrets Manager activities. Identify evidence of data exfiltration and coordinate artifact collection.

### Triage Process:
1. **Initial Rapid Assessment:**  
   - Review high-priority alerts from IAM abuse and network logs.
   - Use pre-configured Splunk dashboards to visualize correlations (e.g., multiple AssumeRole events followed by unusual egress traffic).
   
2. **Role Correlation & Investigation:**  
   - Cross-correlate IAM events and user logins with abnormal compute activity.
   - Validate whether actions align with scheduled/approved automation.
   
3. **Resource Isolation:**  
   - If a particular instance is suspected of persistence or backdoor creation, immediately apply a restrictive security group.
   - Initiate a log freeze for further forensic review.
   
4. **Notification & Escalation:**  
   - SOC Lead documents incident details and alerts management if high-priority threats are confirmed.
   - Share IOCs (e.g., suspect IPs, API calls) for broader threat intelligence and remediation.

---

## 5. Reporting and Documentation

- **Incident Ticketing:**  
  Create a detailed incident ticket with timestamps, affected services, and remedial steps taken.
- **Forensic Archive:**  
  Save raw CloudTrail, VPC Flow, and SIEM query outputs for further analysis.
- **Post-Incident Review:**  
  Conduct a debrief and update your community playbook with improvements to detection and response strategies.

---

## 6. Continuous Improvement

- **Simulated Red Team Exercises:**  
  Regularly run table-top exercises and simulated intrusion drills to ensure that the SOC is ready.
- **Tuning & Calibration:**  
  Adjust Splunk queries and thresholds based on evolving threat intelligence and lessons learned.
- **Policy Updates:**  
  Periodically review AWS IAM and network policies to ensure that they continue to enforce the principle of least privilege.

---
