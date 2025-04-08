# 🛡️ Threat Modeling Workbook: Internal Threat Actor - AWS Environment - 

## Incident Overview

| Item                  | Details                                      |
|-----------------------|----------------------------------------------|
| Date Identified       | YYYY-MM-DD                                   |
| Actor Type            | Internal (ex-employee / contractor / etc.)   |
| Initial Access Vector | e.g., compromised GitHub, CLI, VPN           |
| Scope of Access       | Org-wide / Single Account / Dev-only         |
| Current Status        | Investigating / Contained / Remediated       |

---

## 🔐 Credential Risk: Terraform / CI/CD / GitHub

### Terraform Private Keys / State

- [ ] Rotate all `*.pem` or SSH private keys
- [ ] Rotate backend access to remote state (e.g. S3, Terraform Cloud)
- [ ] Audit for hardcoded credentials in `terraform.tfvars` or `provider` blocks

### GitHub Access & Commits

- [ ] Pull audit logs from GitHub (last 200 days)
- [ ] Review:
  - [ ] Commits to `.github/workflows/`
  - [ ] Secrets added via GitHub Actions or Copilot
  - [ ] New OAuth apps, webhooks, deploy keys

---

## 🧪 Artifact & Build Pipeline Integrity

### Container Registries

- [ ] Identify all modified/pushed ECR images by actor
- [ ] Cross-check SHA digests with trusted source
- [ ] Audit for unusual tags (e.g., `latest`, `test`, `debug`, misspelled services)

### CI/CD Pipelines

- [ ] Validate CodeBuild/CodePipeline jobs
- [ ] Look for:
  - [ ] Malicious `buildspec.yml` stages
  - [ ] Artifacts pulled from external sources
  - [ ] New pipelines created by actor

---

## ☁️ AWS Persistence Mechanisms

### IAM / Roles / STS

- [ ] Audit IAM role trust policies (look for `sts:AssumeRole`)
- [ ] Review `iam:PassRole` usage
- [ ] Check STS logs for chained role assumptions
- [ ] Disable unused roles created or modified by actor

### Lambda Functions

- [ ] Review `LastModified` timestamps
- [ ] Search for Lambdas with:
  - [ ] Scheduled triggers (EventBridge, Cron)
  - [ ] Obfuscated code
  - [ ] Environment variables with secrets
  - [ ] Dynamic eval, downloads, or unusual APIs

### Scheduled Jobs

- [ ] List all EventBridge rules and targets
- [ ] Detect any “dormant” or time-bomb Lambdas
- [ ] StepFunctions or CloudWatch rules owned by attacker?

### Secrets Manager / Parameter Store

- [ ] Review new secrets added by actor
- [ ] Check secret rotation status
- [ ] Look for suspicious `KMSKeyId` values or aliases

---

## 🔒 Data Access / Exfiltration Paths

### S3 Buckets

- [ ] Run `s3:PutBucketPolicy` and `PutObjectAcl` history
- [ ] Check for new `aws:Principal` values added
- [ ] Look for excessive `ListBucket`, `GetObject` usage

### KMS Keys

- [ ] Identify new keys created or assigned
- [ ] Review key grants and aliases
- [ ] Detect keys with unusual policies

### VPC Endpoints

- [ ] Audit newly created `Interface` or `Gateway` endpoints
- [ ] Look for endpoints pointing to external/unowned domains
- [ ] DNS-based callback exfiltration?

---

## 🌐 DNS, Edge, and External Exposure

### Route53 / Domains

- [ ] Check all hosted zones for modified records
- [ ] Detect:
  - [ ] CNAMEs pointing to attacker infra
  - [ ] A records pointing to EC2s not in inventory
- [ ] Scan for dangling subdomains / subdomain takeover risks

---

## ✅ Response Plan


