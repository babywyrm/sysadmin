

# AWS Threat Hunting & APT Detection Runbook – Extended Version (Beta)

**Version:** 0.99b
**Last Updated:** [latest]

**Objective:**  
Detect, investigate, and respond to malicious activity in an AWS environment using a combination of cloud-native logging, SIEM queries (e.g., Splunk), and specialized security tools. This guide is optimized for a SOC team of five and outlines a top‑down approach, recommended tooling, syntax examples, and team assignments.

---

## 1. Overall Methodology

### 1.1. Preparation & Instrumentation

Before you begin the active threat hunt, ensure:

- **CloudTrail Logging:**  
  - CloudTrail should be enabled across all regions and configured to send logs to a secure central S3 bucket.
  - Sample CLI command to test CloudTrail logging:
    ```bash
    aws cloudtrail lookup-events --max-results 10
    ```
  
- **VPC Flow Logs and GuardDuty:**  
  - Verify that VPC Flow Logs are enabled on all critical VPCs.
  - Ensure GuardDuty is activated and that alerts are forwarded into your SIEM.
  - Use [Prowler](https://github.com/toniblyx/prowler) for a security audit of your AWS environment:
    ```bash
    ./prowler -M csv > prowler_report.csv
    ```
  
- **SIEM Integration (Splunk Example):**  
  - Ensure that CloudTrail and VPC Flow Logs are ingested into Splunk with appropriate indexes (`aws` and `vpcflow`).
  - Validate index health by running:
    ```spl
    index=aws | stats count by eventName
    ```

### 1.2. Baseline Establishment

- **Asset Inventory:** Document all IAM users, roles, policies, EC2 instances, VPC network architecture, and storage configurations.
- **Lookup Tables:** Prepare lookup tables for:
  - Expected IP ranges (corporate ranges)
  - Authorized IAM roles for CI/CD
  - Allowed security group configurations
- **Tooling Setup:**  
  - Install AWS CLI, Prowler, and any custom scripts (such as those used for CVE hunting).
  - Update your SIEM with predefined dashboards and alert thresholds.

---

## 2. Threat Categories, Tools, and Detailed Splunk Queries

Below, each threat category is paired with recommended tools, sample Splunk queries, and CAS (critical analysis steps) tactics.

### 2.1. IAM Abuse & Privilege Escalation

**Threat Behavior:**  
- Role chaining, inline policy abuse, or creation of backdoor credentials.

**Tools & Commands:**
- **AWS CLI:**  
  ```bash
  aws iam list-users --output table
  aws iam list-roles --output table
  aws iam get-role --role-name <ROLE_NAME>
  ```
- **Prowler:**  
  ```bash
  ./prowler -c check16    # Check for weak or residual IAM permissions
  ```

**Splunk Queries:**
- **AssumeRole Events:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName="AssumeRole" userIdentity.type="AssumedRole"
  | stats count by userIdentity.arn, requestParameters.roleArn, sourceIPAddress
  ```
- **Credential Creation Alerts:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("CreateUser", "CreateAccessKey", "CreateLoginProfile")
  | table eventTime, eventName, userIdentity.arn, requestParameters.userName, sourceIPAddress
  ```

**Triage Steps:**
1. **Correlation:** Link role assumption events to unexpected user activities.
2. **Verification:** Check against approved role names and service accounts.
3. **Escalation:** If anomalies are confirmed, isolate compromised identities immediately.

---

### 2.2. Network & Perimeter Threats

**Threat Behavior:**  
- Outbound C2 traffic, unusual network configurations, shadow endpoints.

**Tools & Commands:**
- **AWS CLI/VPC Flow Logs:**  
  ```bash
  aws ec2 describe-security-groups --output table
  aws ec2 describe-vpcs --output table
  ```
- **Prowler:**  
  ```bash
  ./prowler -c check68    # Evaluate VPC configuration and IGW/NAT
  ```

**Splunk Queries:**
- **Out-of-Band Egress Traffic:**  
  ```spl
  index=vpcflow sourcetype="aws:cloudwatchlogs:vpcflow" direction=EGRESS action=ACCEPT
  | where NOT cidrmatch("10.0.0.0/8", srcaddr) AND NOT cidrmatch("192.168.0.0/16", srcaddr)
  | stats count by dstaddr, dstport, sourceIPAddress
  | sort 0 - count
  ```
- **Unauthorized SG Changes:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("CreateSecurityGroup", "AuthorizeSecurityGroupIngress")
  | table eventTime, eventName, userIdentity.arn, requestParameters, sourceIPAddress
  ```

**Triage Steps:**
1. **Baseline Comparison:** Use lookup tables to determine if egress destinations are expected.
2. **IC Response:** Engage the network security analyst for further packet inspection if anomalies are found.

---

### 2.3. Data Exfiltration & Access

**Threat Behavior:**  
- Unauthorized or bulk data downloads, unexpected KMS usage.

**Tools & Commands:**
- **AWS CLI (for S3):**  
  ```bash
  aws s3 ls s3://<bucket_name> --recursive
  ```
- **AWS Config:**  
  Review historical configuration changes related to S3 and KMS.

**Splunk Queries:**
- **Bulk S3 Reads:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("GetObject", "ListBucket")
  | stats count by requestParameters.bucketName, sourceIPAddress, userIdentity.arn
  | where count > 50
  ```
- **KMS or Secrets Access:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("Decrypt", "GetSecretValue")
  | table eventTime, eventName, userIdentity.arn, sourceIPAddress
  ```

**Triage Steps:**
- **Threshold Alerts:** Focus on accounts exceeding normal bucket access volumes.
- **Immediate Revocation:** Rapidly revoke credentials if data exfiltration is in progress.

---

### 2.4. Compute Abuse & Backdoors

**Threat Behavior:**  
- Rogue EC2/Lambda deployments, unauthorized SSM sessions.

**Tools & Commands:**
- **AWS CLI for Compute:**  
  ```bash
  aws ec2 describe-instances --output table
  aws lambda list-functions --output table
  ```
- **Prowler:**  
  ```bash
  ./prowler -c check5     # Check for unauthorized instance launches
  ```

**Splunk Queries:**
- **Rogue EC2 Launches:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName="RunInstances"
  | stats count by userIdentity.arn, requestParameters.instanceType, sourceIPAddress
  | where count > 1
  ```
- **SSM/EC2 Connect Activities:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("SendCommand", "StartSession")
  | table eventTime, eventName, userIdentity.arn, sourceIPAddress
  ```

**Triage Steps:**
- **Immediate Isolation:** Quarantine any rogue instance found by modifying its security groups.
- **Confirmation:** Check instance tags and creation details against approved asset inventory.

---

### 2.5. Detection Evasion

**Threat Behavior:**  
- Tampering with CloudTrail, GuardDuty, Config, or deletion of critical log groups.

**Tools & Commands:**
- **AWS CLI for CloudTrail:**  
  ```bash
  aws cloudtrail describe-trails --output table
  ```
- **CloudWatch Logs:**  
  Review log group retention and alarm configurations.

**Splunk Queries:**
- **Audit Log Tampering:**  
  ```spl
  index=aws sourcetype="aws:cloudtrail" eventName IN ("StopLogging", "DeleteTrail", "DisableGuardDuty", "DeleteLogGroup", "DeleteAlarms")
  | table eventTime, eventName, userIdentity.arn, sourceIPAddress
  ```

**Triage Steps:**
- **Verification:** Immediately check the status of CloudTrail, GuardDuty, and CloudWatch.
- **Retain Evidence:** Ensure backups of any deleted logs for forensic analysis.

---

## 3. Incident Response & Team Workflow

### 3.1. Triage & Escalation

1. **Initial Alert Handling:**
   - **Person C (Threat Intelligence & Triage Analyst):**  
     - Monitor dashboards, receive alert notifications.
     - Prioritize events based on risk level (e.g., IAM abuse or network exfiltration = High).

2. **Rapid Investigation:**
   - **Person B (Cloud Forensics Specialist)** and **Person D (Network Security Analyst):**  
     - Simultaneously review CloudTrail, VPC Flow Logs, and SIEM alerts.
     - Confirm whether the observed activity deviates from your baseline.

3. **Resource Isolation:**
   - **Person D (Network Security Analyst):**  
     - If a suspicious EC2 instance is found or unusual VPC traffic is detected, immediately isolate that instance or restrict its network access through updated SGs.
   - **Person A (Team Lead)**:  
     - Coordinate the overall effort and maintain communication with management.

4. **Follow-Up Analysis:**
   - **Person E (Metrics & Data Analyst):**  
     - Produce thread timelines using SIEM and AWS Config data.
     - Assemble evidence for likely privilege escalation or lateral movement.

5. **Documentation & Reporting:**
   - Consolidate data (log snapshots, timestamps, correlated alerts) into incident reports.
   - Use ticketing systems to track resolution and communicate with stakeholders.

### 3.2. Tooling for Forensics

- **Prowler:** Use for detailed configuration security audits.
  ```bash
  ./prowler -M csv -c all > prowler_full_report.csv
  ```
- **AWS CLI & CloudWatch:**  
  Use the AWS CLI to retrieve detailed logs:
  ```bash
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --max-results 20
  ```
- **SIEM Tools (Splunk):**  
  Create dashboards that cross-reference IAM changes with VPC Flow Logs.
- **Network Forensics Tools:**  
  Use packet capture (e.g., tcpdump on suspected instances) for additional evidence.

---

## 4. Remediation & Continuous Improvement

1. **Immediate Remediation:**
   - Disable suspicious IAM credentials immediately.
   - Isolate and quarantine compromised compute resources.
   - Intensify logging on affected workloads and enforce strict VPC controls.

2. **Post-Incident Actions:**
   - Document lessons learned and update SOC procedures and runbooks.
   - Conduct a post-incident review meeting with all team members.
   - Update threat indicators (IOCs) in your SIEM and share with threat intelligence partners.

3. **Continuous Improvement:**
   - Regularly update your Splunk queries and baselines.
   - Schedule periodic access reviews of IAM roles and policies.
   - Simulate attack scenarios using red teaming exercises (e.g., capture the flag drills) and adjust detection thresholds accordingly.
   - Evaluate new tool integrations (e.g., AWS Security Hub, custom Lambda functions for event correlation) to automate detection and response steps.

---

## 5. Reporting & Communication

- **Internal Reporting:**  
  - Maintain a dedicated incident response log.
  - Create weekly reports summarizing alerts, triage outcomes, and remediation actions.

- **Communications:**  
  - Ensure that the Team Lead (Person A) is the point of contact for communications with both internal stakeholders and, if necessary, external MSSPs or law enforcement.
  - Use secure messaging channels (e.g., Slack with proper security policies) to coordinate investigations.

---

