# AWS-Specific Purple Team Framework ( Beta Edition )


---

## 1. Overview

AWS offers tremendous scale and flexibility—but also a broad attack surface spanning compute, storage, identity, networking, and more. An AWS-focused Purple Team exercise ensures your organization can:

- **Emulate** modern AWS-native threats end-to-end  
- **Validate** preventive controls (IAM policies, VPC hardening, image security)  
- **Improve** detection engineering on CloudTrail, CloudWatch, GuardDuty, and custom telemetry  
- **Refine** incident response runbooks for AWS containment & recovery  

---

## 2. Key AWS Attack Vectors & Defenses

| **Attack Vector**                                  | **Red Team Tools / Techniques**                                                                                              | **Blue Team Controls & Defenses**                                                                                                                                      | **Detection & Telemetry**                                                                                                                                           |
|----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **1. SSM Session Manager Abuse**                   | - Steal existing IAM credentials, attach `AmazonSSMManagedInstanceCore` role<br>- Invoke `aws ssm start-session`              | - IAM policy: least-privilege, deny `ssm:StartSession` unless required<br>- Session Manager logging → CloudWatch Logs<br>- Enforce MFA on SSM StartSession                                                     | - CloudWatch Log Insights: session start events from `/aws/ssm/SessionLogs`<br>- GuardDuty “UnauthorizedAccess:EC2/SSMAssumeRole” finding                           |
| **2. EC2 Instance Metadata API SSRF**              | - SSRF exploit to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`<br>- Retrieve temporary IAM creds       | - Enforce IMDSv2 only (`HttpTokens=required`)<br>- Block HTTP metadata access from application subnets via network policies                                                                | - VPC flow logs: HTTP requests to 169.254.169.254<br>- CloudTrail API errors if IMDSv2 enforced                                                                           |
| **3. AMI Tampering / Golden AMI Poisoning**        | - Launch benign AMI, install backdoor, snapshot as new AMI<br>- Use CLI/API to deregister replaced AMI                        | - Enforce image pipeline with AWS Image Builder + image-signing (Code Signing for EC2)<br>- IAM deny `ec2:DeregisterImage`/`ModifyImageAttribute` for dev roles                                             | - CloudTrail: Monitor `DeregisterImage`, `RegisterImage`, `CreateImage` calls<br>- Config rule: AMIs outside approved list                                             |
| **4. ECR Image Poisoning**                         | - Push malicious container (e.g. cryptominer) to ECR repo<br>- Abuse `docker pull` on target EC2                             | - Require image signing & validation (e.g. Cosign)<br>- Enforce ECR repository policies, block unscanned images<br>- Lifecycle policies removing untagged images                                         | - ECR image scan CI: block high-severity CVEs<br>- CloudWatch Events on `PutImage`, `CompleteLayerUpload`                                                                 |
| **5. Lambda Code Injection**                       | - Upload manipulated ZIP via `aws lambda update-function-code`<br>- Invoke vulnerable function to achieve RCE                  | - Require code-signing by trusted key (`--code-signing-config-arn`)<br>- IAM policy restrict `lambda:UpdateFunctionCode`<br>- VPC-isolate Lambdas handling sensitive data                            | - CloudTrail: `UpdateFunctionCode`, `Invoke` calls outside dev hours<br>- AWS Config rule: Lambda functions without code-signing config                                |
| **6. CloudTrail / Log Tampering**                  | - Stop logging (`StopLogging`), delete trails, or disable S3 bucket notifications                                           | - Enforce CloudTrail multi-region + organization trails<br>- S3 Object Lock on log bucket<br>- IAM deny removal of trail without approval                                                         | - CloudWatch Alarm on `StopLogging` API calls<br>- AWS Config Managed Rule: `cloudtrail-enabled`                                                                         |
| **7. IAM Role Chaining & Privilege Escalation**    | - Abuse `sts:AssumeRole` chaining to get elevated role<br>- Exploit overly broad policies (wildcards)                        | - IAM policy simulation tests<br>- IAM Access Analyzer findings<br>- Deny policies: `NotAction` patterns, explicit `Deny` on `iam:PassRole`                                                          | - CloudTrail insights: unusual `AssumeRole` sequences<br>- GuardDuty “PrivilegeEscalation:IAM” findings                                                               |
| **8. S3 Bucket Exfiltration / Host Buckets**       | - Upload malicious code to public bucket, trigger Lambda via S3 event<br>- Abuse misconfigured host-style bucket subdomain   | - Block public ACLs with S3 Block Public Access<br>- Enforce encryption-at-rest/in-transit<br>- Bucket policies restrict `s3:PutObject`                                                             | - S3 Data Events: PutObject from unexpected source IPs<br>- VPC Flow Logs: outbound data to unknown IP addresses                                                        |
| **9. KMS Key Misuse**                              | - Perform unauthorized `Encrypt`/`Decrypt` calls<br>- Try data recovery via `GenerateDataKey`                                 | - Key policies restricting principals, require `kms:ViaService` conditions<br>- Enable key rotation and CloudTrail logging                                                                          | - CloudTrail: `GenerateDataKey`, `Decrypt` calls flagged<br>- CloudWatch metric alarm on unusual KMS usage                                                              |
| **10. Network Misconfig — Security Group Over-Permissive** | - Open wide ingress/egress rules, pivot via compromised instance                                                        | - Audit SGs: no 0.0.0.0/0 on management ports<br>- AWS Firewall Manager policies for guardrails<br>- Enforce least-privilege SG constructs                                                               | - Config rule: `restricted-common-ports`<br>- VPC Flow Logs + Athena: spikes in unexpected ingress                                                                    |

---

## 3. Sample Purple-Team Scenarios

Below are end-to-end scenarios pairing Red and Blue activities. Use these as templates for your AWS exercises.

### Scenario A: SSM Session Hijack

1. **Red Team**  
   - Phish a developer to obtain AWS access keys with `AmazonSSMManagedInstanceCore`.  
   - Run:  
     ```bash
     aws configure set aws_access_key_id <KEY>
     aws configure set aws_secret_access_key <SECRET>
     aws ssm start-session --target i-0abcdef1234567890
     ```  
2. **Blue Team**  
   - Verify AWS Config rule `ssm-session-manager-enabled` is in place.  
   - CloudWatch Logs Insights:  
     ```sql
     filter @logStream like /ssm-session-manager/ 
     | filter eventName = "StartSession"
     ```  
   - GuardDuty: review “SSMAssumeRole” findings.  
3. **Post-mortem**  
   - Tighten IAM: require MFA on SSM actions.  
   - Add CloudWatch Alarm on unauthorized StartSession calls.

---

### Scenario B: AMI Poisoning & Detection

1. **Red Team**  
   - Launch an existing approved AMI, install a reverse shell, create new AMI:  
     ```bash
     INSTANCE_ID=i-0abcdef…
     aws ec2 create-image --instance-id $INSTANCE_ID \
       --name "poisoned-ami-$(date +%F)" --no-reboot
     aws ec2 run-instances --image-id ami-XXXXXXX --count 1 …
     ```  
2. **Blue Team**  
   - AWS Config: enforce “approved-ami-ids” rule.  
   - CloudTrail: detect `CreateImage` calls by unexpected IAM principal.  
   - SNS → PagerDuty alert on unapproved AMI usage.  
3. **Post-mortem**  
   - Implement Image Builder pipeline + automated Scanning + Code Signing.  
   - Revoke permissions: deny `ec2:CreateImage` for non-build roles.

---

### Scenario C: ECR Image Poisoning & Prevention

1. **Red Team**  
   - Build and tag a malicious image:  
     ```bash
     docker build -t 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest .
     docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest
     ```  
2. **Blue Team**  
   - Enforce ECR Image Scanning Policy: block push if critical CVEs.  
   - Require image signing; validate in deployment pipelines.  
   - CloudWatch Event Rule: on `PushImage` → Lambda verifies signature.  
3. **Post-mortem**  
   - Integrate Cosign + Notation in CI/CD.  
   - Harden IAM: restrict `ecr:PutImage` to build pipeline role.

---

### Scenario D: Metadata API SSRF → IAM Exfiltration

1. **Red Team**  
   - Exploit SSRF in web app to call metadata API:  
     ```
     curl --resolve example.internal:80:10.0.0.5 \
       http://example.internal/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
     ```  
2. **Blue Team**  
   - Enforce IMDSv2 only on all EC2 instances.  
   - VPC Flow Logs: detect HTTP requests to 169.254.169.254.  
   - WAF rule: block requests with Host header `169.254.169.254`.  
3. **Post-mortem**  
   - Automate IMDSv2 enforcement via Systems Manager State Manager.  
   - Add CloudWatch Alarm on unauthorized metadata calls.

---

## 4. Offensive & Defensive Toolkits

- **Red Team**  
  - Pacu, CloudGoat, AWS CLI, SSM CLI, SSRF PoC scripts, custom Lambda payloads  
  - Terraform modules to spin up “vulnerable” lab environment  

- **Blue Team**  
  - AWS Config rules (managed & custom), Security Hub, GuardDuty, CloudWatch Logs Insights  
  - AWS Detective, Macie, Inspector, CloudTrail Lake queries  
  - SOAR: AWS Chatbot + Slack/PagerDuty integrations for automated runbooks  

---

## 5. Detection Engineering & SOAR Playbooks

1. **CloudWatch Event → Lambda Detector**  
   - On undesired API call (e.g. `CreateImage`), trigger Lambda to validate caller and quarantine resources.  
2. **GuardDuty Custom Actions**  
   - Tag affected EC2/EBS/S3 resources for isolation.  
   - Post to Slack channel and create Jira ticket automatically.  
3. **SSM Run Command Remediation**  
   - Auto-apply IAM Deny policy when unauthorized session is detected.  

---

## 6. AWS Purple-Team Maturity Model

| **Level**       | **Threat Understanding**                            | **Detection Understanding**                           |
|-----------------|-----------------------------------------------------|-------------------------------------------------------|
| **1 – Ad-Hoc**  | One-off manual exercises with basic CTI             | Rudimentary CloudTrail dashboard; alerts by vendor    |
| **2 – Automated** | Scripted scenarios via Pacu / CloudGoat pipelines  | Automated CloudWatch Insights, Config rules enforced  |
| **3 – Integrated** | CI/CD-triggered emulations on PRs / nightly runs  | SOAR playbooks, GuardDuty custom rules, ChatOps       |
| **4 – Autonomous** | AI-driven TTP mapping & emulation recommendations | ML anomaly detection on CloudTrail Lake, proactive drift alerts |

---

## 7. Next Steps

1. **Customize** the vectors & scenarios for your AWS account structure and teams.  
2. **Automate** regularly in CI/CD (e.g. GitHub Actions: `on: schedule`) to catch configuration drift.  
3. **Iterate** detection playbooks as new TTPs emerge—leverage AWS Security Hub findings for prioritization.  
4. **Measure** Mean Time To Detect (MTTD) / Time To Remediate (MTTR) and track improvements over time.

---

