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


##
##
##
##

##
# Enhanced AWS-Focused Purple Team Framework
##

## Enhanced Attack Vector Matrix

| Attack Vector | Offensive Tools & Techniques | Defensive Tools & Measures |
|---------------|------------------------------|----------------------------|
| **IAM Privilege Escalation** | • Pacu (`iam__enum_roles`, `iam__privesc`) <br>• AWS CLI enumeration (`aws iam list-policies`, `aws iam simulate-principal-policy`) <br>• Cloudsploit IAM scanner <br>• Rhino Security Labs' AWS_Escalate.py | • AWS IAM Access Analyzer <br>• AWS Config IAM managed rules (e.g. `iam-user-no-policies`, `iam-password-policy`) <br>• Enforce least-privilege roles, custom IAM permission boundaries <br>• CloudTrail logging and GuardDuty IAM anomaly detection <br>• IAM Access Analyzer custom rules validation <br>• SCPs (Service Control Policies) to prevent privilege escalation paths |
| **SSM Command & Control Abuse** | • SSM Session Manager port forwarding and Run Command injection <br>• Pacu `ssm__run_command`, `ssm__port_forward` modules <br>• Direct AWS CLI abuse (`aws ssm send-command`) <br>• Command document parameter manipulation | • Restrict SSM RunCommand permissions via IAM conditions <br>• AWS Config SSM rules (e.g. `ssm-managed-instance-no-public-access`) <br>• Session Manager logging to CloudWatch Logs and S3 <br>• GuardDuty SSM anomaly alerts <br>• Enforce SSM Session Manager preferences (KMS encryption, logging required) <br>• SSM Parameter Store encryption for sensitive parameters <br>• CloudWatch Logs Insights queries for suspicious command patterns |
| **Instance Metadata Service Abuse** | • SSRF via compromised application to IMDSv1 <br>• `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/…` <br>• Container escape to host IMDS access <br>• Lambda environment variable extraction | • Enforce IMDSv2 only (`HttpTokens=required`, `HttpPutResponseHopLimit=1`) <br>• AWS Config rules for IMDS enforcement <br>• GuardDuty EC2 anomaly detection (suspicious metadata access patterns) <br>• VPC endpoint policies restricting IMDS actions <br>• Web application firewall rules to block SSRF attempts |
| **S3 Bucket Misconfiguration** | • Pacu (`s3__list_buckets`, `s3__enum`, `s3__get_public_data`) <br>• `aws s3api list-buckets --query "Buckets[].Name"` <br>• S3Scanner automated discovery <br>• Object-level permission manipulation <br>• Bucket policy manipulation | • S3 Block Public Access at account and bucket levels <br>• AWS Config rules (e.g. `s3-bucket-public-read-prohibited`) <br>• CloudTrail S3 Data Events logging <br>• GuardDuty S3 Protection <br>• S3 server-side encryption with KMS (SSE-KMS) <br>• S3 object lock for critical data <br>• S3 Access Points with restrictive policies <br>• Macie for sensitive data discovery |
| **ECR Image Poisoning** | • Push malicious image to ECR via stale credentials or improperly scoped role <br>• `docker push` to unauthorized repository <br>• Base image substitution in CI/CD pipelines <br>• Supply chain attacks via dependencies | • ECR image scanning (Amazon Inspector) <br>• ECR repository policies (deny push from non-approved principals) <br>• CloudTrail ECR API call logging (PushImage/DeleteImage) <br>• Amazon EventBridge rules triggering validation functions (Lambda) <br>• ECR pull-through cache configuration validation <br>• Image signing and verification (Notary, cosign) <br>• Container image Software Bill of Materials (SBOM) validation |
| **AMI Tampering** | • Build or register malicious AMI via `aws ec2 register-image` <br>• Modify launch permissions to share malicious AMI <br>• Insert backdoor into base AMI during golden image creation <br>• AMI volume snapshot extraction and modification | • AWS Config AMI owner and image blocklists <br>• CloudTrail EC2 RegisterImage, DeregisterImage event alerts <br>• Enforce AMI signing and image provenance (EC2 Image Builder signing) <br>• GuardDuty EC2 anomaly detection (new AMI usage) <br>• AWS Organizations SCP to restrict AMI usage to approved sources <br>• Regular AMI scanning and validation in CI/CD pipeline |
| **VPC Egress & Network Pivoting** | • SSH tunneling and ProxyCommand via compromised EC2 <br>• Pacu `vpc__subnet_enum`, `ecs__proxy_ecs` <br>• DNS tunneling via Route 53 <br>• WebSocket persistent connections <br>• ICMP tunneling (ptunnel-ng) | • VPC Flow Logs analysis for unusual tunnels <br>• AWS Network Firewall and Security Groups least-privilege <br>• Route 53 Resolver DNS Firewall for suspicious domains <br>• GuardDuty network anomaly detection <br>• VPC Endpoint policies restricting services <br>• Network Access Analyzer for path validation <br>• Traffic Mirroring for deep packet inspection |
| **KMS Key Misuse** | • `aws kms decrypt` with stolen credentials <br>• Pacu `kms__decrypt_key` <br>• Key policy manipulation to grant access <br>• Cross-account key sharing | • KMS key policies restrict decrypt to specific principals <br>• CloudTrail KMS Data Events logging <br>• GuardDuty KMS anomaly detection <br>• AWS Config rules for KMS key rotation and deletion protection <br>• Automated key policy reviews <br>• KMS grants with constraints <br>• Multi-Region key replication monitoring |
| **STS Token Exfiltration** | • Chained `AssumeRole` to access cross-account resources <br>• Pacu `sts__enum_roles`, custom scripts to exfiltrate tokens via HTTP <br>• Token extraction from ECS/EKS container environments <br>• Session stealing from compromised applications | • Restrict IAM trust policies (source-account condition) <br>• CloudTrail STS AssumeRole event monitoring, GuardDuty anomaly alerts <br>• Short-lived credentials (maximum session duration) <br>• External ID requirements for cross-account roles <br>• MFA enforcement for sensitive role assumption <br>• Condition keys for IP restriction on AssumeRole |
| **Lambda Code Injection** | • Deploy function with malicious code via `aws lambda update-function-code` <br>• Pacu `lambda__execute_function`, Metasploit AWS Lambda modules <br>• Third-party dependency poisoning <br>• Environment variable manipulation | • Lambda code signing enforcement <br>• AWS Config Lambda rules (e.g. `lambda-function-public-network-access`) <br>• AWS WAF on API Gateway with JSON body inspection <br>• Lambda layer provenance validation <br>• Lambda function URLs with authorization <br>• Lambda resource-based policies <br>• Lambda function environment variable encryption |
| **CloudTrail Log Tampering** | • `aws cloudtrail delete-trail`, delete S3 objects directly <br>• Modify CloudTrail configuration to exclude events <br>• S3 lifecycle policies for early log deletion <br>• Cross-account log bucket permission abuse | • Enable CloudTrail log file validation (digests) <br>• AWS Config CloudTrail rules (e.g. `cloudtrail-enabled`, `cloudtrail-log-file-validation-enabled`) <br>• GuardDuty S3 Data Event detection for CloudTrail buckets <br>• Secondary logging destination (cross-account) <br>• CloudTrail Lake with immutable storage <br>• S3 Object Lock for CloudTrail buckets <br>• CloudTrail Insights for unusual management events |
| **EKS/ECS Cluster Compromise** | • Kubernetes RBAC abuse via overprivileged ServiceAccounts <br>• Container escape techniques (e.g., mounting host filesystems) <br>• ECS task definition manipulation to escalate privileges <br>• EKS control plane API server access | • EKS pod security standards enforcement <br>• AWS Config rules for EKS cluster security <br>• GuardDuty Kubernetes audit log monitoring <br>• ECS task role least privilege enforcement <br>• Security groups limiting pod-to-pod communication <br>• AWS Fargate for isolation <br>• Amazon Inspector for container vulnerability scanning <br>• EKS add-on for runtime security (Calico, Falco) |
| **Secrets Management Exploitation** | • Extract secrets from Secrets Manager/Parameter Store <br>• `aws secretsmanager get-secret-value` with compromised credentials <br>• Environment variable extraction from runtime environments <br>• API key extraction from deployment artifacts | • Secrets Manager rotation schedules <br>• Resource-based policies for secrets access control <br>• CloudTrail data events for secrets access <br>• GuardDuty for anomalous secrets access <br>• AWS KMS customer-managed keys for secrets encryption <br>• IAM condition keys limiting secret access by service/resource <br>• Parameter Store SecureString with automatic rotation |
| **EventBridge Rule Manipulation** | • Modify rules to disable security automation <br>• Create rogue rules for event interception <br>• Delete critical security event rules <br>• Modify targets to redirect events | • CloudTrail tracking of EventBridge API calls <br>• AWS Config rules for EventBridge configuration <br>• IAM policies limiting EventBridge modification <br>• EventBridge rule versions and validation <br>• Cross-account event duplication for critical security events <br>• Change detection automation via AWS Config |
| **CloudFormation/CDK Backdooring** | • Insert malicious resources in templates <br>• Modify IAM roles in deployment templates <br>• Custom resource Lambda backdoors <br>• CDK construct tampering | • CloudFormation drift detection <br>• AWS Config rules for stack resources <br>• CloudFormation guard policy validation <br>• Template hash validation pre-deployment <br>• IAM permissions boundary on CloudFormation service role <br>• Mandatory code review for infrastructure code <br>• StackSets with administrative account control |

##
##

## Detection Engineering Guide (Template)

### CloudWatch Logs Insights Queries

```
# Suspicious IAM Policy Changes
filter eventName = "CreatePolicy" or eventName = "PutRolePolicy" or eventName = "AttachRolePolicy" 
| stats count(*) as event_count by eventName, userIdentity.userName, userIdentity.type, sourceIPAddress
| sort event_count desc

# Unusual Instance Metadata Service Access 
filter @message like /169.254.169.254/ and @message like /security-credentials/
| stats count(*) as access_count by @logStream, @message
| sort access_count desc

# Suspicious AWS Config Changes
filter eventSource = "config.amazonaws.com" and eventName in ["DeleteConfigRule", "PutConfigRule", "DeleteConfigurationRecorder", "StopConfigurationRecorder"]
| stats count(*) as event_count by eventName, userIdentity.userName, sourceIPAddress
```

### GuardDuty Custom Findings and Filtering

| Finding Type | Description | Response Threshold |
|--------------|-------------|-------------------|
| IAMUserWithTempCredentialsAssumingRole | Temporary credentials being used to assume role across accounts | Medium - High |
| UnusualS3BucketAccessByIdentity | Access to S3 bucket by identity (IAM role/user) that has not previously accessed it | Medium |
| ECRImageLayerScanFindingMitigated | Image vulnerabilities identified in ECR | Low - Medium |
| ExposedAccessKey | Access key exposed in public repository | Critical |
| UnauthorizedAccess:IAMUser/MaliciousIPCaller | API calls from known malicious IP address | High |

## New Section: Response Automation Playbooks

### Detection & Response Pipeline Architecture

1. **Event Source Tier**: CloudTrail, VPC Flow Logs, GuardDuty, AWS Config, Application Logs
2. **Processing Tier**: CloudWatch Logs, EventBridge Rules, Lambda Functions
3. **Analysis Tier**: Security Lake, CloudWatch Insights, Third-party SIEM
4. **Response Tier**: AWS Systems Manager Automation, Lambda Remediations, Security Hub

### Automated Response Template (SSM Automation)

```yaml
name: IAMRolePrivilegeEscalationResponse
description: Responds to detected IAM role privilege escalation attempt
assumeRole: "arn:aws:iam::${AWS::AccountId}:role/SecurityAutomationRole"
parameters:
  RoleName:
    type: String
    description: The name of the role with suspicious policy changes
  EventID:
    type: String
    description: The CloudTrail event ID to reference
mainSteps:
  - name: IsolateRole
    action: aws:executeAwsApi
    inputs:
      Service: iam
      Api: PutRolePolicy
      RoleName: "{{RoleName}}"
      PolicyName: TemporaryDenyAll
      PolicyDocument: '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
  - name: NotifySecurityTeam
    action: aws:executeAwsApi
    inputs:
      Service: sns
      Api: Publish
      TopicArn: arn:aws:sns:${AWS::Region}:${AWS::AccountId}:SecurityIncidents
      Message: |
        Potential privilege escalation detected for role: {{RoleName}}
        Event ID: {{EventID}}
        Temporary isolation policy applied. Manual investigation required.
  - name: CreateSecurityHubFinding
    action: aws:executeAwsApi
    inputs:
      Service: securityhub
      Api: BatchImportFindings
      Findings:
        - SchemaVersion: "2018-10-08"
          Title: "IAM Role Privilege Escalation"
          Description: "Potential privilege escalation detected for role {{RoleName}}"
          ProductArn: "arn:aws:securityhub:{{global:REGION}}:{{global:ACCOUNT_ID}}:product/{{global:ACCOUNT_ID}}/default"
          AwsAccountId: "{{global:ACCOUNT_ID}}"
          Types: ["Unusual Behaviors/IAM:PrivilegeEscalation"]
          Severity: 
            Label: HIGH
```

## New Section: AWS Security Benchmarks Integration

| Benchmark | Controls Relevant to Purple Team | Implementation |
|-----------|----------------------------------|----------------|
| CIS AWS Foundations | 1.2: IAM password policy <br>2.1-2.9: CloudTrail configuration <br>3.1-3.14: Monitoring and logging <br>4.1-4.16: Networking security | AWS Config Conformance Packs <br>Security Hub CIS standard <br>Custom compliance checks |
| AWS Well-Architected Security Pillar | SEC 1: Identity and access management <br>SEC 3: Detection <br>SEC 4: Infrastructure protection <br>SEC 9: Incident response | Security Hub frameworks <br>Game day scenarios <br>Architectural reviews |
| NIST 800-53 | AC-2: Account Management <br>AU-2: Audit Events <br>SI-4: System Monitoring <br>CM-6: Configuration Settings | AWS Audit Manager <br>AWS Control Tower <br>Custom compliance checking Lambda functions |

## Usage Guidance (Expanded)

1. **Select relevant vectors** based on your AWS footprint and threat model:
   - Align with organization-specific threat intelligence
   - Prioritize based on existing security gaps and high-value assets

2. **Configure red team tools** in a controlled lab account:
   - Create separate, isolated AWS accounts for offensive security testing
   - Implement strong detective controls in test environments
   - Use AWS Organizations with SCPs to prevent accidental scope expansion

3. **Implement and validate defenses**:
   - Build layered detection capabilities across multiple services
   - Test each control with documented evasion techniques
   - Create baseline detection times for each attack scenario

4. **Automate** emulation and detection:
   - Develop attack simulation modules in AWS CDK/CloudFormation
   - Create CI/CD pipelines that deploy both attack and defense components
   - Schedule regular detection validation runs in non-production environments

5. **Measure success**:
   - Track detection coverage against AWS service utilization
   - Monitor mean time to detect (MTTD) and respond (MTTR) trends
   - Calculate security control efficacy (true positive rate)
   - Document verification of defensive control implementation

6. **Document and Learn**:
   - Create runbooks for each attack vector with IoCs
   - Build knowledge base of effective defenses and detection strategies
   - Maintain library of evasion techniques and detection evolution

7. **Evolve the Framework**:
   - Regularly update based on new AWS service features
   - Incorporate emerging cloud attack techniques
   - Adapt detection logic as adversaries evolve

