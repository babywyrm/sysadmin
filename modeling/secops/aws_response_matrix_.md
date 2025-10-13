
# Matrix

```
Phase	Process ID	Action	Target System	Execution Time	Dependencies	Owner	Priority	Rollback Required
PHASE 0: PRE-FLIGHT (T+0 to T+30s)								
0	PRE-001	Validate incident trigger & user identity	Incident Management	5s	None	IR Lead	P0	No
0	PRE-002	Create incident channel & war room	Slack/Teams	10s	PRE-001	IR Lead	P0	No
0	PRE-003	Notify stakeholders (CISO, Legal, HR)	Communication Platform	15s	PRE-001	IR Lead	P0	No
0	PRE-004	Snapshot current user state (Okta)	Okta API	20s	PRE-001	IAM Admin	P0	No
0	PRE-005	Snapshot current user state (AWS)	AWS API	25s	PRE-001	CloudSec	P0	No
0	PRE-006	Snapshot active sessions (all systems)	Multi-system	30s	PRE-001	SecOps	P0	No
0	PRE-007	Identify user's current IP/location	SIEM/EDR	15s	PRE-001	SOC	P1	No
0	PRE-008	Check if user is only admin	IAM Systems	10s	PRE-001	IAM Admin	P0	No
PHASE 1: IDENTITY REVOCATION (T+30s to T+90s)								
1	IDN-001	Suspend Okta account	Okta Admin Console	5s	PRE-004	IAM Admin	P0	Yes
1	IDN-002	Terminate all Okta sessions	Okta API	10s	IDN-001	IAM Admin	P0	No
1	IDN-003	Revoke all OAuth/refresh tokens	Okta API	15s	IDN-001	IAM Admin	P0	No
1	IDN-004	Remove from all Okta groups	Okta API	20s	IDN-001	IAM Admin	P0	Yes
1	IDN-005	Revoke all Okta app assignments	Okta API	25s	IDN-001	IAM Admin	P0	Yes
1	IDN-006	Delete all MFA factors	Okta API	10s	IDN-001	IAM Admin	P0	Yes
1	IDN-007	Clear Okta federation cache	Okta API	5s	IDN-001	IAM Admin	P0	No
1	IDN-008	Disable Azure AD account (if applicable)	Azure AD	15s	PRE-004	IAM Admin	P0	Yes
1	IDN-009	Revoke Google Workspace access (if applicable)	Google Admin	15s	PRE-004	IAM Admin	P0	Yes
PHASE 2: CLOUD INFRASTRUCTURE (T+30s to T+120s)								
2	CLD-001	Attach explicit DENY policy to IAM user	AWS IAM	10s	PRE-005	CloudSec	P0	Yes
2	CLD-002	Delete all AWS access keys (primary account)	AWS IAM	15s	CLD-001	CloudSec	P0	Yes
2	CLD-003	Revoke active STS sessions	AWS STS	10s	CLD-001	CloudSec	P0	No
2	CLD-004	Remove from all IAM groups	AWS IAM	20s	CLD-001	CloudSec	P0	Yes
2	CLD-005	Detach all IAM policies	AWS IAM	20s	CLD-001	CloudSec	P0	Yes
2	CLD-006	Disable AWS SSO/IAM Identity Center	AWS SSO	15s	PRE-005	CloudSec	P0	Yes
2	CLD-007	Tag user account (IncidentID, Status)	AWS IAM	5s	CLD-001	CloudSec	P1	No
2	CLD-008	Scan Organization for cross-account keys	AWS Organizations	60s	CLD-002	CloudSec	P0	No
2	CLD-009	Revoke keys in all child accounts	AWS IAM (multi-account)	90s	CLD-008	CloudSec	P0	Yes
2	CLD-010	Apply DENY policy in all child accounts	AWS IAM (multi-account)	90s	CLD-008	CloudSec	P0	Yes
2	CLD-011	Revoke assumed role sessions	AWS IAM	30s	CLD-003	CloudSec	P0	No
2	CLD-012	Check for service-linked roles	AWS IAM	20s	CLD-001	CloudSec	P1	No
2	CLD-013	Disable Azure subscriptions access	Azure CLI	30s	PRE-005	CloudSec	P0	Yes
2	CLD-014	Revoke GCP service account keys	GCP IAM	30s	PRE-005	CloudSec	P0	Yes
PHASE 3: SECRETS & CREDENTIALS (T+30s to T+180s)								
3	SEC-001	Rotate AWS Secrets Manager secrets	Secrets Manager	120s	CLD-002	CloudSec	P0	No
3	SEC-002	Rotate RDS master passwords	RDS API	90s	CLD-002	DBA	P0	No
3	SEC-003	Rotate Redis/ElastiCache passwords	ElastiCache API	60s	CLD-002	CloudSec	P1	No
3	SEC-004	Revoke database user accounts	PostgreSQL/MySQL	45s	SEC-002	DBA	P0	Yes
3	SEC-005	Rotate API keys in 1Password	1Password API	60s	IDN-001	SecOps	P0	No
3	SEC-006	Rotate HashiCorp Vault tokens	Vault API	30s	CLD-002	SecOps	P0	No
3	SEC-007	Invalidate JWT tokens	Auth Service	15s	IDN-002	AppSec	P0	No
3	SEC-008	Clear Redis session cache	Redis CLI	10s	IDN-002	SRE	P0	No
3	SEC-009	Rotate SSH keys on bastion hosts	Bastion Servers	45s	NET-003	SRE	P1	Yes
3	SEC-010	Revoke certificates (client certs)	PKI/CA	30s	NET-005	NetSec	P1	Yes
PHASE 4: ENDPOINT CONTAINMENT (T+30s to T+120s)								
4	EPT-001	Identify user's active devices	EDR/MDM	10s	PRE-007	IR Engineer	P0	No
4	EPT-002	Isolate device in EDR (network contain)	CrowdStrike/SentinelOne	20s	EPT-001	IR Engineer	P0	Yes
4	EPT-003	Kill all user processes	EDR API	15s	EPT-002	IR Engineer	P0	No
4	EPT-004	Lock device screen	MDM (Intune/Jamf)	10s	EPT-001	IT Ops	P1	Yes
4	EPT-005	Disable local user account	OS Commands	15s	EPT-002	IT Ops	P1	Yes
4	EPT-006	Revoke cached credentials	Kerberos/OS	10s	EPT-002	IT Ops	P1	No
4	EPT-007	Block device at firewall (MAC/IP)	Firewall	20s	EPT-001	NetSec	P0	Yes
4	EPT-008	Disable WiFi/Ethernet adapters	MDM	15s	EPT-002	IT Ops	P1	Yes
4	EPT-009	Remove from MDM groups	Intune/Jamf	20s	EPT-001	IT Ops	P1	Yes
4	EPT-010	Revoke device certificates	MDM/PKI	25s	EPT-001	IT Ops	P1	Yes
4	EPT-011	Capture memory dump (if feasible)	EDR	180s	EPT-002	Forensics	P2	No
4	EPT-012	Initiate disk imaging	Forensics Tool	300s+	EPT-002	Forensics	P2	No
PHASE 5: NETWORK LOCKDOWN (T+30s to T+90s)								
5	NET-001	Terminate active VPN sessions	VPN Controller	10s	EPT-001	NetSec	P0	No
5	NET-002	Revoke VPN certificates	VPN/PKI	15s	NET-001	NetSec	P0	Yes
5	NET-003	Block user IP at perimeter firewall	Firewall API	20s	PRE-007	NetSec	P0	Yes
5	NET-004	Revoke Tailscale/ZeroTier access	ZT Platform	15s	NET-001	NetSec	P0	Yes
5	NET-005	Block at Cloudflare Access/Zero Trust	Cloudflare API	20s	NET-001	NetSec	P0	Yes
5	NET-006	Add IP to WAF blocklist	WAF (CloudFlare/AWS)	15s	PRE-007	NetSec	P0	Yes
5	NET-007	Revoke AWS Verified Access grants	AWS Verified Access	20s	CLD-001	CloudSec	P0	Yes
5	NET-008	Update security group rules (remove user IPs)	AWS EC2	30s	PRE-007	CloudSec	P1	Yes
5	NET-009	Sinkhole DNS for user devices	Internal DNS	25s	EPT-001	NetSec	P1	Yes
5	NET-010	Block at API Gateway	AWS API Gateway	20s	CLD-001	CloudSec	P0	Yes
5	NET-011	Apply Kubernetes Network Policy	K8s API	30s	CLD-001	SRE	P1	Yes
PHASE 6: SAAS & APPLICATIONS (T+30s to T+180s)								
6	SAS-001	Revoke GitHub org membership	GitHub API	15s	IDN-001	DevSecOps	P0	Yes
6	SAS-002	Delete GitHub Personal Access Tokens	GitHub API	20s	SAS-001	DevSecOps	P0	No
6	SAS-003	Revoke GitHub SSH keys	GitHub API	15s	SAS-001	DevSecOps	P0	Yes
6	SAS-004	Remove from GitLab groups	GitLab API	15s	IDN-001	DevSecOps	P0	Yes
6	SAS-005	Delete GitLab access tokens	GitLab API	20s	SAS-004	DevSecOps	P0	No
6	SAS-006	Deactivate Slack user (via SCIM)	Slack API	15s	IDN-001	IT Ops	P0	Yes
6	SAS-007	Terminate Slack sessions	Slack API	10s	SAS-006	IT Ops	P0	No
6	SAS-008	Suspend Jira account	Jira API	20s	IDN-001	IT Ops	P1	Yes
6	SAS-009	Suspend Confluence account	Confluence API	20s	IDN-001	IT Ops	P1	Yes
6	SAS-010	Revoke Datadog API keys	Datadog API	15s	IDN-001	SRE	P1	No
6	SAS-011	Remove from PagerDuty	PagerDuty API	20s	IDN-001	SRE	P1	Yes
6	SAS-012	Revoke Terraform Cloud tokens	TFC API	15s	IDN-001	SRE	P0	No
6	SAS-013	Suspend Sentry account	Sentry API	15s	IDN-001	DevOps	P1	Yes
6	SAS-014	Revoke DockerHub tokens	DockerHub API	20s	IDN-001	DevOps	P1	No
6	SAS-015	Revoke NPM/PyPI tokens	Package Registry	25s	IDN-001	DevOps	P1	No
6	SAS-016	Suspend Salesforce user	Salesforce API	20s	IDN-001	IT Ops	P1	Yes
6	SAS-017	Revoke Zoom account	Zoom API	15s	IDN-001	IT Ops	P2	Yes
6	SAS-018	Disable email forwarding rules	O365/Gmail API	30s	IDN-009	IT Ops	P0	Yes
6	SAS-019	Revoke email OAuth grants	O365/Gmail API	25s	IDN-009	IT Ops	P0	No
6	SAS-020	Suspend Notion account	Notion API	15s	IDN-001	IT Ops	P2	Yes
PHASE 7: CONTAINER & ORCHESTRATION (T+60s to T+180s)								
7	CTR-001	Revoke Kubernetes RBAC bindings	kubectl	30s	CLD-001	SRE	P0	Yes
7	CTR-002	Delete Kubernetes ServiceAccount	kubectl	20s	CTR-001	SRE	P0	Yes
7	CTR-003	Revoke ECR repository permissions	AWS ECR	25s	CLD-001	CloudSec	P1	Yes
7	CTR-004	Block Docker registry access	Registry API	20s	CLD-001	DevOps	P1	Yes
7	CTR-005	Terminate user's running pods	kubectl	30s	CTR-001	SRE	P1	No
7	CTR-006	Revoke Helm chart access	Helm/ArgoCD	25s	CTR-001	SRE	P1	Yes
7	CTR-007	Remove from ArgoCD/FluxCD	GitOps Platform	30s	SAS-001	SRE	P1	Yes
7	CTR-008	Disable ECS task definitions with user role	AWS ECS	45s	CLD-001	CloudSec	P1	No
7	CTR-009	Stop Lambda functions using user credentials	AWS Lambda	60s	CLD-001	CloudSec	P1	No
PHASE 8: CI/CD & AUTOMATION (T+60s to T+180s)								
8	CIC-001	Revoke Jenkins tokens	Jenkins API	20s	IDN-001	DevOps	P1	No
8	CIC-002	Disable CircleCI contexts	CircleCI API	25s	IDN-001	DevOps	P1	Yes
8	CIC-003	Revoke GitHub Actions secrets	GitHub API	30s	SAS-001	DevSecOps	P0	No
8	CIC-004	Disable GitLab CI/CD variables	GitLab API	25s	SAS-004	DevSecOps	P1	No
8	CIC-005	Revoke BuildKite tokens	BuildKite API	20s	IDN-001	DevOps	P1	No
8	CIC-006	Suspend Ansible Tower/AWX user	AWX API	25s	IDN-001	SRE	P1	Yes
8	CIC-007	Revoke Terraform Cloud run tokens	TFC API	20s	SAS-012	SRE	P1	No
8	CIC-008	Disable Spinnaker user	Spinnaker API	30s	IDN-001	SRE	P2	Yes
PHASE 9: DATA & STORAGE (T+90s to T+240s)								
9	DAT-001	Revoke S3 bucket policies (user-specific)	AWS S3	30s	CLD-001	CloudSec	P1	Yes
9	DAT-002	Invalidate S3 pre-signed URLs	AWS S3	45s	CLD-001	CloudSec	P0	No
9	DAT-003	Revoke CloudFront signed cookies/URLs	CloudFront	30s	CLD-001	CloudSec	P1	No
9	DAT-004	Block user in DynamoDB access policies	DynamoDB	35s	CLD-001	CloudSec	P1	Yes
9	DAT-005	Revoke Snowflake user	Snowflake	40s	IDN-001	Data Eng	P1	Yes
9	DAT-006	Revoke BigQuery access	GCP BigQuery	35s	CLD-014	Data Eng	P1	Yes
9	DAT-007	Revoke Databricks workspace access	Databricks API	30s	IDN-001	Data Eng	P1	Yes
9	DAT-008	Disable MongoDB Atlas user	Atlas API	25s	IDN-001	DBA	P1	Yes
9	DAT-009	Revoke Elasticsearch/OpenSearch access	ES API	30s	IDN-001	SRE	P1	Yes
9	DAT-010	Check for database replication accounts	Multiple DBs	60s	SEC-004	DBA	P2	No
PHASE 10: MONITORING & LOGGING (T+0s to T+300s - Continuous)								
10	MON-001	Enable enhanced CloudTrail logging	AWS CloudTrail	10s	PRE-001	CloudSec	P0	No
10	MON-002	Create SIEM alert rule for user activity	Splunk/ELK	20s	PRE-001	SOC	P0	No
10	MON-003	Monitor CloudTrail for post-revocation activity	CloudTrail	1800s	CLD-002	SOC	P0	No
10	MON-004	Monitor Okta logs for bypass attempts	Okta	1800s	IDN-002	SOC	P0	No
10	MON-005	Monitor VPC Flow Logs for user IPs	VPC Flow Logs	1800s	NET-003	SOC	P0	No
10	MON-006	Monitor GitHub audit log	GitHub	1800s	SAS-001	DevSecOps	P0	No
10	MON-007	Monitor WAF logs for user patterns	WAF	1800s	NET-006	SOC	P0	No
10	MON-008	Monitor database query logs	DB Logs	1800s	SEC-004	DBA	P0	No
10	MON-009	Alert on any token refresh attempts	Auth Service	1800s	IDN-002	AppSec	P0	No
10	MON-010	Track API Gateway access attempts	API Gateway	1800s	NET-010	SOC	P0	No
PHASE 11: FORENSICS COLLECTION (T+120s to T+600s)								
11	FOR-001	Collect CloudTrail logs (90 days)	AWS S3	180s	MON-001	Forensics	P1	No
11	FOR-002	Collect Okta system logs (90 days)	Okta API	120s	MON-004	Forensics	P1	No
11	FOR-003	Collect VPC Flow Logs	AWS S3	150s	MON-005	Forensics	P1	No
11	FOR-004	Collect GitHub audit logs	GitHub API	90s	MON-006	Forensics	P1	No
11	FOR-005	Collect EDR telemetry	EDR Platform	240s	EPT-002	Forensics	P1	No
11	FOR-006	Collect email logs and headers	O365/Gmail	180s	SAS-018	Forensics	P1	No
11	FOR-007	Export Slack DMs and channels	Slack API	300s	SAS-006	Forensics	P2	No
11	FOR-008	Collect database query history	DB Export	240s	SEC-004	Forensics	P1	No
11	FOR-009	Collect WAF logs	WAF S3	120s	MON-007	Forensics	P2	No
11	FOR-010	Snapshot user's cloud resources	AWS/GCP	180s	CLD-005	Forensics	P1	No
11	FOR-011	Collect SIEM query results	SIEM	120s	MON-002	Forensics	P1	No
11	FOR-012	Document timeline of user actions	Incident Portal	300s	Multiple	Forensics	P1	No
PHASE 12: COMMUNICATION (T+0s to T+300s)								
12	COM-001	Post initial alert to incident channel	Slack	30s	PRE-002	IR Lead	P0	No
12	COM-002	Notify CISO	Email/Phone	60s	PRE-003	IR Lead	P0	No
12	COM-003	Notify Legal	Email/Phone	90s	PRE-003	IR Lead	P0	No
12	COM-004	Notify HR	Email/Phone	90s	PRE-003	IR Lead	P0	No
12	COM-005	Notify user's manager	Email/Phone	120s	PRE-003	HR	P0	No
12	COM-006	Post Phase 1 completion update	Slack	120s	IDN-007	IR Lead	P0	No
12	COM-007	Post Phase 2 completion update	Slack	180s	CLD-011	IR Lead	P0	No
12	COM-008	Post full lockdown confirmation	Slack	300s	Multiple	IR Lead	P0	No
12	COM-009	Update incident ticket with actions taken	JIRA/ServiceNow	360s	Multiple	IR Lead	P0	No
12	COM-010	Prepare stakeholder brief	Document	600s	Multiple	IR Lead	P1	No
PHASE 13: VALIDATION (T+300s to T+1800s)								
13	VAL-001	Verify Okta account status = DEPROVISIONED	Okta API	10s	IDN-001	IAM Admin	P0	No
13	VAL-002	Verify 0 active Okta sessions	Okta API	10s	IDN-002	IAM Admin	P0	No
13	VAL-003	Verify AWS access keys = 0	AWS IAM	15s	CLD-002	CloudSec	P0	No
13	VAL-004	Verify no CloudTrail activity post-revocation	CloudTrail	60s	CLD-002	CloudSec	P0	No
13	VAL-005	Verify endpoint isolation status	EDR	15s	EPT-002	IR Engineer	P0	No
13	VAL-006	Verify VPN sessions terminated	VPN Logs	10s	NET-001	NetSec	P0	No
13	VAL-007	Verify GitHub membership removed	GitHub API	10s	SAS-001	DevSecOps	P0	No
13	VAL-008	Verify database access revoked	DB Connection Test	20s	SEC-004	DBA	P0	No
13	VAL-009	Verify Kubernetes access revoked	kubectl	15s	CTR-001	SRE	P0	No
13	VAL-010	Test authentication attempts (should fail)	Test Script	30s	IDN-001	SecOps	P0	No
13	VAL-011	Continuous monitoring validation (30min)	SIEM/SOC	1800s	Multiple	SOC	P0	No
13	VAL-012	Generate validation report	Script	60s	Multiple	SecOps	P0	No
```

```
T+0s ════════════════════════════════════════════════════════════
     ║ PRE-001 ════╗
     ║ PRE-007     ║
     ║ PRE-008     ║
     ╠═════════════╩════════════════════════════════════════════
     ║ PRE-002 (Incident Channel)
     ║ PRE-003 (Notifications)
     ╠═════════════════════════════════════════════════════════
T+30s║ PARALLEL SNAPSHOT
     ║ ┌─ PRE-004 (Okta Snapshot)
     ║ ├─ PRE-005 (AWS Snapshot)
     ║ └─ PRE-006 (Session Snapshot)
     ╠═════════════════════════════════════════════════════════
     ║
T+30s║ PARALLEL PHASE 1 (Identity) + PHASE 2 (AWS) + PHASE 4 (Endpoint)
     ║ ┌─ IDN-001 → IDN-002 → IDN-003 → IDN-004 → IDN-005 → IDN-006
     ║ ├─ CLD-001 → CLD-002 ──┬─→ CLD-003
     ║ │                      ├─→ CLD-004
     ║ │                      ├─→ CLD-005
     ║ │                      └─→ CLD-008 ──→ CLD-009/010 (Org-wide)
     ║ └─ EPT-001 → EPT-002 ──┬─→ EPT-003
     ║                        ├─→ EPT-007
     ║                        └─→ EPT-004/005/006
     ╠═════════════════════════════════════════════════════════
T+60s║ PARALLEL PHASE 5 (Network) + PHASE 6 (SaaS) + PHASE 3 (Secrets)
     ║ ┌─ NET-001 ──┬─→ NET-002
     ║ │            ├─→ NET-003
     ║ │            ├─→ NET-004/005/006
     ║ │            └─→ NET-007/008/009/010
     ║ ├─ SAS-001 → SAS-002 → SAS-003 (GitHub)
     ║ ├─ SAS-004 → SAS-005 (GitLab)
     ║ ├─ SAS-006 → SAS-007 (Slack)
     ║ ├─ SAS-008/009 (Atlassian)
     ║ ├─ SAS-010 thru SAS-020 (All other SaaS - parallel)
     ║ └─ SEC-001 → SEC-002 → SEC-003 → SEC-004 (Secrets rotation)
     ╠═════════════════════════════════════════════════════════
T+90s║ PARALLEL PHASE 7 (Containers) + PHASE 8 (CI/CD) + PHASE 9 (Data)
     ║ ┌─ CTR-001 → CTR-002 → CTR-003 → ... → CTR-009
     ║ ├─ CIC-001 → CIC-002 → CIC-003 → ... → CIC-008
     ║ └─ DAT-001 → DAT-002 → DAT-003 → ... → DAT-010
     ╠═════════════════════════════════════════════════════════
T+120s PARALLEL PHASE 11 (Forensics) - While others complete
     ║ ┌─ FOR-001 (CloudTrail Collection)
     ║ ├─ FOR-002 (Okta Logs)
     ║ ├─ FOR-003 (VPC Flows)
     ║ ├─ FOR-004 (GitHub Audit)
     ║ ├─ FOR-005 (EDR Telemetry)
     ║ └─ FOR-006 thru FOR-012 (All forensic evidence)
     ╠═════════════════════════════════════════════════════════
T+300s PHASE 13 (Validation) - Sequential checks
     ║ VAL-001 → VAL-002 → VAL-003 → ... → VAL-010
     ║ ┌─ VAL-011 (30-minute continuous monitoring)
     ║ └─ VAL-012 (Final report generation)
     ╠═════════════════════════════════════════════════════════
T+1800s END
```

##
##

```
EMPLOYEE DEVICE COMPROMISE (AWS) — INITIAL RESPONSE CONCURRENCY MAP (..rc4..)
                   =================================================================================

TIME HORIZON:   T0 ───▶ T+15m ───▶ T+30m ───▶ T+45m ───▶ T+60m
                (Incident Declared)   (Containment)   (Investigation)   (Stabilization)


                                 ┌────────────────────────────────────────────────────────────┐
                                 │ INCIDENT DECLARED — SEV1 / SEV2                            │
                                 │ Device compromise with AWS‑linked credentials confirmed    │
                                 └───────────────────────┬────────────────────────────────────┘
                                                         │
                                                         ▼
               ┌───────────────────────────────────────────────────────────────────────────────┐
               │ INCIDENT COMMAND CELL  (T0 → T+10 min)                                         │
               │--------------------------------------------------------------------            │
               │ • Assign Incident Commander & Scribe                                           │
               │ • Open secure war room (Slack / Zoom)                                          │
               │ • Freeze deployments / notify stakeholders                                     │
               │ • Notify Legal / HR / Executives                                               │
               │ • Define log collection & metrics export interval                              │
               └──────────────────────┬─────────────────────────────────────────────────────────┘
                                      │
       ┌──────────────────────────────┼──────────────────────────────────────────────────────────┐
       │                              │                                                          │
       ▼                              ▼                                                          ▼
┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐
│ GLOBAL USER DEACTIVATION    │  │ ENDPOINT CONTAINMENT        │  │ IDENTITY CONTAINMENT        │  │ AWS BLAST RADIUS REVIEW     │
│ (“Kill Switch”) T0 → T+10m  │  │ (Response Eng T0 → T+20m)   │  │ (IAM Sec T0 → T+25m)        │  │ (CloudSec T10 → T40m)       │
│-----------------------------│  │-----------------------------│  │-----------------------------│  │------------------------------│
│ • Trigger Global Deactivation Runbook                        │  │ • Revoke STS sessions        │  │ • Query CloudTrail / Athena │
│ • Disable user via Okta / IdP                                │  │ • Disable access keys        │  │ • Review AWS Config drift   │
│ • Kill SSO & OAuth tokens org‑wide                           │  │ • Force MFA reset            │  │ • Evaluate GuardDuty alerts │
│ • Revoke STS sessions AWS‑org wide                           │  │ • Audit IAM trust policies   │  │ • Identify modified policies│
│ • Isolate endpoint (EDR quarantine)                          │  │                              │  │ • Map impacted resources    │
│ • Verify revocation across Okta / AWS / SaaS                 │  │                              │  │ • Establish blast‑radius    │
└──────────────┬───────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘
               │                                 │                                 │                                 │
               ├─────────────────────────────────┴─────────────────────────────────┼─────────────────────────────────┤
               │                                                                   │
               ▼                                                                   ▼
┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐
│ LOG & EVIDENCE CAPTURE      │  │ OBSERVABILITY / APP LOGS    │  │ THREAT HUNTING & DETECTION  │  │ COMMUNICATION & TRACKING    │
│ (SOC / Forensics T10 → T40m)│  │ (SRE / Logging T10 → T50m)  │  │ (SOC / Detection T20 → T50m)│  │ (Comms / IR Lead Cont.)     │
│------------------------------│  │----------------------------│  │------------------------------│ │------------------------------│
│ • Snapshot SIEM search sets  │  │ • Export Kibana queries     │  │ • SIEM anomaly sweeps       │  │ • Maintain incident log     │
│ • Archive S3 / VPC / ALB logs│  │ • Capture Grafana / Loki    │  │ • Role / asset correlation  │  │ • Compile exec summaries    │
│ • Hash + timestamp evidence  │  │ • Gather WebApp / API logs  │  │ • GuardDuty pattern checks  │  │ • Decision tracking         │
│ • Secure evidence S3 bucket  │  │ • Archive Prometheus data   │  │ • IOC sweeps / enrichment   │  │ • Stakeholder comms cadence │
│ • Create evidence manifest   │  │ • Ingest to Splunk pipeline │  │ • Validate signals vs app logs│ │ • Documentation continuity │
└──────────────┬───────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘  └──────────────┬──────────────┘
               │                                 │                                 │                                 │
               ├─────────────────────────────────┴─────────────────────────────────┴─────────────────────────────────┤
               │
               ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ OBSERVABILITY CORRELATION HUB  (SRE + SOC Continuous)                                                              │
│--------------------------------------------------------------------------------------------------------------------│
│ • Compare metrics vs events for confirmation and false‑positive reduction                                          │
│ • Detect anomaly spikes in system metrics (CPU / traffic / auth errors)                                            │
│ • Correlate app telemetry with CloudTrail and SIEM alerts                                                          │
│ • Confirm service health / impact scope                                                                            │
│ • Feed validated signals back to SOC and IR Lead                                                                   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                                         │
                                                         ▼
                                ┌──────────────────────────────────────────────────────────────┐
                                │ INITIAL CONTAINMENT VERIFIED  (≈ T+60 min)                   │
                                │--------------------------------------------------------------│
                                │ • Global Deactivation complete (Okta + AWS + SaaS verified)  │
                                │ • Endpoint & IAM access revoked org‑wide                     │
                                │ • CloudTrail & App logs secured and hashed                   │
                                │ • Observability layer confirms no further spread             │
                                │ • Proceed to Forensics / Blast‑Radius Deep‑Dive              │
                                └──────────────────────────────────────────────────────────────┘
```

##
##

```
GLOBAL USER / DEVICE DEACTIVATION — T0 → T+10 min
                     ==================================================

                                 ┌────────────────────────────────────────
                                 │ TRIGGER CONDITION
                                 │ • Confirmed device or identity compromise
                                 │ • AWS / Okta / SOC high‑confidence alert
                                 └──────────────────────┬─────────────────
                                                        │
                                                        ▼
                 ┌────────────────────────────────────────────────────────────
                 │ INCIDENT COMMAND CELL  (IR Lead / SecOps Manager)
                 │-------------------------------------------------------------
                 │ • Approve “Global Deactivation” (“Kill Switch”)
                 │ • Assign owners (IAM, CloudSec, Response, SOC)
                 │ • Open war room, notify HR / Legal / IT
                 └──────────────────────┬─────────────────────────────
                                        │
                                        ▼
┌──────────────────────────────────────────    ┌────────────────────────────────────────     ┌───────────────────────────────────────
│ IDENTITY PROVIDER / SSO  (Okta / Azure AD)   │ CLOUD (AWS Organization / IAM / STS)        │ ENDPOINT & NETWORK SYSTEMS (EDR / VPN)
│--------------------------------------------   │-------------------------------------------   │---------------------------------------
│ • Suspend user account                       │ • Revoke STS sessions                       │ • Isolate endpoint (EDR quarantine)
│ • Terminate sessions (web / mobile)          │ • Disable access keys                       │ • Disable VPN / remote access
│ • Revoke MFA / OAuth / refresh tokens        │ • Detach IAM policies                       │ • Revoke cert / token auth
│ • Enforce password and MFA reset             │ • Block AWS SSO / federated login           │ • Disable local / AD login
│ • Verify SCIM sync to SaaS targets           │ • Rotate shared keys if applicable          │ • Confirm device isolation event
└──────────────────────┬───────────────────     └──────────────────────┬────────────────      └──────────────────────┬────────────────
                       │                                        │                                     │
                       ├────────────────────────────────────────┴────────────────────────────────────┤
                       │
                       ▼
            ┌────────────────────────────────────────────────────────────────────────────
            │ BUSINESS / SAAS SYSTEMS (via SCIM or API Integration)
            │------------------------------------------------------------
            │ • Suspend email / calendar / office suite accounts
            │ • Deactivate collaboration apps (Slack / Teams / Jira)
            │ • Remove VCS access (GitHub / GitLab / Bitbucket)
            │ • Invalidate CI/CD tokens / PATs
            │ • Rotate secrets owned by compromised user
            └──────────────────────┬────────────────────────────
                                   │
                                   ▼
            ┌────────────────────────────────────────────────────────────────────────────
            │ VERIFICATION & COMMUNICATION
            │------------------------------------------------------------
            │ • SOC verifies no active sessions remain (Okta / AWS)
            │ • Confirm endpoint is isolated (EDR status = Quarantined)
            │ • IR Lead announces “Deactivation Complete” in war room
            │ • Upload revocation logs to incident evidence store
            │ • Update timeline + UTC completion timestamp
            └────────────────────────────────────────────────────────────
```

##
##

# Incident Response Deliverables and Artifact Collection (AWS Employee Device Compromise)

This section defines the specific **artifacts to collect**, **deliverables to produce**, and **responsible owners**
during each incident phase.  
All collections should follow evidence‑handling best practices (timestamps, integrity verification, secure storage).

---

## Phase 1 — Declaration and Coordination (T0 → T+10 min)

| Category | Artifact / Deliverable | Description | Owner | Storage Location |
|-----------|------------------------|-------------|--------|------------------|
| Incident Metadata | Incident Declaration Record | Incident ID, SEV level, timestamp, assigned roles | IR Lead | /incidents/metadata/ |
| Communications | War Room Log | Chat channel transcript link, decisions log | IR Lead / Scribe | /incidents/logs/ |
| Status Snapshot | Current AWS Account Context | List of active sessions, AWS Organizations map | CloudSec | /incidents/metadata/aws_context.json |

---

## Phase 2 — Containment (T+10 → T+25 min)

| Category | Artifact / Deliverable | Description | Owner | Purpose |
|-----------|------------------------|-------------|--------|----------|
| Endpoint Forensics | Memory capture, process list, open connections | Extracted from compromised endpoint | Response Engineer | Identify malware, active C2 |
| Endpoint Summary | Device metadata (OS, hostname, serial, IP, VPN IP) | Logged from EDR/MDM | Response Engineer | Trace network access |
| IAM Data | IAM user JSON dump (`aws iam get-user`) | Baseline of identity configuration | CloudSec | Reference before revocation |
| AWS Sessions | List of active sessions (`aws sts get-caller-identity`) | Determine active consoles/tokens | IAM Security | Revoke + verify lockout |
| Credential Audit | Access key list (`aws iam list-access-keys`) | Track key rotation | IAM Security | Audit / Rotation evidence |

Deliverables:
- Isolation confirmation log
- IAM/session revocation confirmation
- Initial endpoint image or memory dump
- Containment checklist (signed by IR Lead)

---

## Phase 3 — Blast Radius & Evidence Capture (T+20 → T+40 min)

| Category | Artifact / Deliverable | Description | Owner | Storage |
|-----------|------------------------|-------------|--------|----------|
| CloudTrail Snapshot | Exported logs (JSON/GZIP) for 14 days | CloudTrail & CloudWatch | CloudSec | s3://incident-evidence/cloudtrail/ |
| AWS Config Snapshot | JSON deltas of IAM, S3, VPC, Lambda configurations | CloudSec | s3://incident-evidence/config/ |
| GuardDuty Findings | All findings (JSON export) | SOC | s3://incident-evidence/guardduty/ |
| VPC Flow Logs | Network traffic related to user/device | CloudSec | s3://incident-evidence/vpcflow/ |
| S3 Access Logs | Requests or downloads during window | SOC | s3://incident-evidence/s3access/ |
| SIEM Query Results | Raw Splunk/Chronicle logs | Detection | /incidents/logs/siem_results.json |
| IP & IOC Table | Detected malicious IPs, hashes, domains | Threat Intel | /incidents/indicators/ioc_list.csv |
| IAM Role Usage | List of assumed roles + permissions | CloudSec | /incidents/aws/roles_usage.csv |

Deliverables:
- AWS artifact package (CloudTrail + Config + GuardDuty)
- IOC summary table
- IAM access report
- Log integrity hashes

---

## Phase 4 — Threat Hunting & Analysis (T+30 → T+50 min)

| Category | Artifact / Deliverable | Description | Owner | Purpose |
|-----------|------------------------|-------------|--------|----------|
| Correlated Event Timeline | Combined timeline: EDR + CloudTrail + SIEM | Detection / IR Lead | Build event chronology |
| IOC Pivot List | IPs, hashes, user‑agents, domains | Threat Intel | Feed detection tuning |
| Malicious Artifacts | Files downloaded, scripts, processes | Forensics | Reverse engineering / signature gen |
| AWS Service Footprint | EC2/Lambda/S3 created by actor | CloudSec | Identify persistence |
| Credential Propagation | Detect reused API keys / tokens | CloudSec | Scope lateral movement |

Deliverables:
- Unified incident timeline (CSV or Markdown)
- Threat‑intel IOCs ready for blocklists
- Initial impact statement

---

## Phase 5 — Verification & Stabilization (≈ T+60 min)

| Category | Artifact / Deliverable | Description | Owner | Purpose |
|-----------|------------------------|-------------|--------|----------|
| Verification Checklist | Confirm all credentials rotated, IAM disabled | IR Lead | Containment validation |
| Detection Validation | Confirm new SIEM / GuardDuty detections active | Detection Engineer | Continuous monitoring |
| Forensic Archive | Evidence package hash manifest | Forensics | Long‑term storage integrity |
| Communication Summary | Final update to leadership | Comms Officer | Status reporting |
| Lessons Log | Immediate observed gaps | IR Lead | Entry for post‑mortem |

Deliverables:
- Containment verification memo
- Final evidence hash log
- Executive summary update

---

## Common Artifacts Collected (Cross‑Phase Overview)

| Type | Collected From | Examples |
|------|----------------|-----------|
| **Cloud Logs** | CloudTrail, Config, GuardDuty, Security Hub | Auth events, configuration changes |
| **Identity Data** | IAM, AWS SSO, Okta, STS | Sessions, access keys, role assumptions |
| **Network Data** | VPC Flow, ELB, WAF, VPN | Source IPs, ports, traffic volume |
| **System Data** | Endpoint EDR, MDM, Sysmon | Running processes, binaries, connections |
| **Indicators of Compromise (IOCs)** | Threat Intel, Network, Files | IPs, hashes, URLs, domains |
| **Artifacts for Correlation** | SIEM Export, Athena Queries | Timeline data, alert correlation |
| **Evidence Integrity** | SHA256 Hash Log | Validation for post‑event audits |

---

## Artifact Storage and Retention Policy (Example)

| Location | Type | Access Control | Retention |
|-----------|------|----------------|-----------|
| `s3://incident-evidence/cloudtrail/` | CloudTrail, Athena, Config | Write‑once bucket, versioning enabled | 1 year minimum |
| `/incidents/forensics/<incident_id>/` | Endpoint images, logs | Restricted to Forensics group | Permanent |
| `/incidents/logs/` | Chat transcripts, SIEM exports | Secure share (read‑only) | 1 year |
| `/incidents/indicators/` | IOC lists, threat intel | SOC / Detection only | 6 months |
| `/docs/postmortems/` | Final reports | All Security leads | Permanent archive |

---

## Notes and Best Practices

- **All timestamp data must be in UTC**; record source offset if known.  
- Use **SHA256 hash + timestamp** for every log file or forensic image before upload.  
- Avoid opening collected samples on production systems — use isolated analysis.
- Always capture **pre\-revocation** IAM data before disabling users, to preserve an untouched reference.
- Integrate this list with your SOAR playbooks for automation:
  - CloudTrail → export to S3
  - IAM snapshot → JSON dump  
  - SIEM snapshot → auto‑export saved search

---

**File placement:**  
`/playbooks/incident-response/runbooks/aws_employee_device_artifact_matrix.md`

##
##

# Incident Correlation Schema — AWS Employee Device Compromise

**File Path:**  
`/playbooks/incident-response/schemas/aws_incident_correlation_schema.md`

**Purpose:**  
Map artifacts collected during the incident to corresponding detections, validation methods, and final lessons learned.  
Each record describes how evidence connects to investigation goals and where it feeds future detection logic.

---

## 1. Schema Overview

| Field | Description |
|--------|-------------|
| **Artifact_ID** | Unique identifier for the evidence item (cross‑referenced with artifact matrix) |
| **Artifact_Type** | Type of evidence collected (log, config, forensic image, alert, etc.) |
| **Detection_Source** | Where the signal originated (SIEM, GuardDuty, Athena, EDR, etc.) |
| **Detection_Gap_Found** | If this evidence revealed a gap in coverage |
| **Investigation_Link** | Related step, query, or hunt that used this data |
| **Impact_Insight** | What new understanding came from this artifact |
| **Improvement_Action** | Specific change to tooling, detection, or process |
| **Owner** | Who updates detections or processes based on this item |
| **Postmortem_Tag** | Tag used in the after‑action review (e.g. "DetectionCoverage", "PlaybookUpdate") |

---

## 2. Example Correlation Records

| Artifact_ID | Artifact_Type | Detection_Source | Detection_Gap_Found | Investigation_Link | Impact_Insight | Improvement_Action | Owner | Postmortem_Tag |
|--------------|----------------|------------------|---------------------|--------------------|----------------|--------------------|--------|----------------|
| A‑CT001 | CloudTrail Log Export (14 days) | GuardDuty / Athena Query | None | “Blast Radius” analysis (phase 3) | Identified creation of rogue IAM Role within 5 min of compromise | Add CloudTrail rule to alert on inline IAM role creation | CloudSec | DetectionCoverage |
| A‑IAM002 | IAM User Configuration Dump | Athena, Manual CLI | Partial | “Identity Containment” (phase 2) | Found active access key not rotated in >90 days | Add IAM key‑age policy; automate rotation alert | IAM Security | PolicyGap |
| A‑VPC003 | VPC Flow Logs | SIEM / Splunk query | True | “Blast Radius” – network path analysis | Revealed exfil via EC2 instance using same key | Add VPC Flow correlation to SIEM; build exfil detection rule | Detection Engineer | NetworkVisibility |
| A‑EDR004 | Memory Dump / Process Snapshot | Endpoint Agent | N/A | “Endpoint Forensics” (phase 2) | Uncovered running process using AWS CLI with cached tokens | Update EDR detections for CLI abuse; train staff | Forensics | EndpointCoverage |
| A‑SIEM005 | SIEM Query Export | Splunk – GuardDuty Bridge | True | “Threat Hunting” (phase 4) | Alerts fired 10 min late due to missing API log delay | Investigate log ingestion latency; improve pipeline monitoring | SOC Engineering | LoggingPipeline |
| A‑IOC006 | Indicator List (IPs, hashes) | Threat Intel + Manual Correl. | None | “Threat Hunting” (phase 4) | Linked malicious IP to external campaign | Feed IP to blocklists & threat feeds | Threat Intel | ThreatFeedUpdate |
| A‑POST007 | Unified Timeline Report | Consolidated Evidence | None | “Verification” (phase 5) | Demonstrated TTP pattern: token reuse + manual key create | Add analytic rule: *STS token re‑use after IAM create* | IR Lead / Detection Eng | DetectionEnhancement |

---

## 3. Schema Fields with Value Guidance

| Field | Expected Format | Example |
|--------|-----------------|----------|
| **Artifact_ID** | `A-<category><sequence>` | `A-CT001`, `A-IAM002` |
| **Artifact_Type** | Controlled vocabulary: `CloudTrail Log`, `VPC Flow`, `IAM Dump`, `Memory Image`, `SIEM Query`, `IOC List`, `Config Snapshot` |  |
| **Detection_Source** | AWS service or tool where the detection came from | `GuardDuty`, `Athena`, `Splunk`, `EDR` |
| **Detection_Gap_Found** | Boolean (`True/False`) | `True` |
| **Investigation_Link** | Incident phase or specific query reference | `"Blast Radius – step 3"` |
| **Impact_Insight** | Short sentence capturing what was learned | `"Exposed S3 bucket accessible via compromised key"` |
| **Improvement_Action** | Specific change to process or tool | `"Add automated S3 public-access auditing rule"` |
| **Owner** | Functional owner (e.g., SOC, Detection Engineer, CloudSec) | `"Detection Engineer"` |
| **Postmortem_Tag** | Tag used for grouping improvements | `"PlaybookUpdate"`, `"DetectionCoverage"`, `"Training"` |

---

## 4. Example Usage in Workflow

**a. During Investigation**
1. Each artifact logged in the artifact matrix receives an `Artifact_ID`.
2. When analysts find insight or detection gaps from that artifact, they create an entry in this schema.

**b. During Post‑Incident Review**
1. Group by `Postmortem_Tag` to generate lessons‑learned categories.
2. Each “Improvement Action” becomes a JIRA or GitHub issue for remediation tracking.

**c. After Review**
1. Security Engineering validates that new detection or policy has been implemented.
2. Close item with `Status = Verified` column (if you extend this as a CSV / YAML schema).

---

## 5. Suggested Storage and Automation

| System | Purpose | Notes |
|---------|----------|-------|
| `/incidents/schema/` folder | Raw Markdown / CSV record | Reference during ongoing incidents |
| GitHub Issues automation | Auto‑create remediation tasks from new records | Connect via GitHub Actions / webhook |
| Security Tool Wiki | Sync `Improvement_Action` + `Impact_Insight` for training | Continuous improvement docs |

---

## 6. Optional Extended Columns (for YAML or DB Integration)

For more automation or SOAR import, extend fields:

```yaml
Artifact_ID: A-CT001
Artifact_Type: CloudTrail Export
Detection_Source: GuardDuty
Detection_Gap_Found: false
Severity: High
Investigation_Link: Blast-Radius-Query
Impact_Insight: Rogue IAM role created via stolen token
Improvement_Action: Add analytic detection for CreateRole + unusual user
Owner: CloudSec
Postmortem_Tag: DetectionCoverage
Status: Open
Hash: 8c12b4e1...
Integrity_Checked: true
Timestamp_Recorded: 2025-10-03T20:15:00Z
```

---

##
##
