# Enhanced Production Readiness Checklist with SDLC & Supply Chain Focus (Beta)



## Secure SDLC & Supply Chain

| Item | Status | Guidance | Resources | Owner |
|------|--------|----------|-----------|-------|
| Secure Development Practices | ⬜ | Verify adherence to secure coding guidelines and training completion | [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/) | |
| Code Review Process | ⬜ | Document security-focused code review process with required approvers | [SAST Integration Guide](https://cheatsheetseries.owasp.org/cheatsheets/Static_Code_Analysis_Cheat_Sheet.html) | |
| Dependency Management | ⬜ | Implement policy for dependency scanning, approval, and updating | [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/), [Snyk](https://snyk.io/) | |
| Container Security | ⬜ | Scan container images and implement minimal base images with security hardening | [Docker Bench Security](https://github.com/docker/docker-bench-security), [Trivy](https://github.com/aquasecurity/trivy) | |
| Artifact Signing | ⬜ | Implement digital signing of all artifacts and verification before deployment | [Sigstore](https://www.sigstore.dev/), [Notary](https://github.com/notaryproject/notary) | |
| Software Bill of Materials | ⬜ | Generate and maintain SBOM for tracking components and dependencies | [CycloneDX](https://cyclonedx.org/), [SPDX](https://spdx.dev/) | |
| Infrastructure as Code Security | ⬜ | Scan IaC templates for security issues and enforce best practices | [Checkov](https://www.checkov.io/), [tfsec](https://github.com/aquasecurity/tfsec) | |
| Third-Party Vendor Assessment | ⬜ | Verify security assessment of all third-party integrations and vendors | [Vendor Security Assessment Questionnaire](https://www.cisecurity.org/insights/white-papers/vendor-security) | |

## Security Elements (Enhanced)

| Item | Status | Guidance | Resources | Owner |
|------|--------|----------|-----------|-------|
| Threat Modeling | ⬜ | Complete a threat modeling session with security team to identify attack vectors and mitigations | [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling), [STRIDE Model](https://en.wikipedia.org/wiki/STRIDE_(security)) | |
| Security Scanning | ⬜ | Run SAST/DAST tools against codebase and document remediation plan for findings | [OWASP Top 10](https://owasp.org/www-project-top-ten/), [SonarQube](https://www.sonarqube.org/) | |
| Vulnerability Management | ⬜ | Implement process for tracking and addressing CVEs in dependencies | [NIST NVD](https://nvd.nist.gov/), [Dependabot](https://github.com/dependabot) | |
| Secret Management | ⬜ | Verify all secrets are stored in approved vaults, not hardcoded | [HashiCorp Vault](https://www.vaultproject.io/), [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) | |
| IAM & Access Control | ⬜ | Verify RBAC implementation and least-privilege for service accounts | [NIST RBAC Guide](https://csrc.nist.gov/projects/role-based-access-control) | |
| Network Security | ⬜ | Review firewall rules, network segmentation, and TLS implementation | [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html) | |
| Data Protection | ⬜ | Verify encryption at rest and in transit for all sensitive data | [NIST Encryption Guidelines](https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final) | |
| API Security | ⬜ | Implement API security controls (rate limiting, input validation, authentication) | [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) | |
| Secure Configuration | ⬜ | Document and validate secure configuration baselines for all components | [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) | |
| Compliance | ⬜ | Document compliance with relevant regulations (SOC2, GDPR, etc.) | [SOC2 Guidelines](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome.html) | |

## Reliability & Resiliency (Enhanced for Availability)

| Item | Status | Guidance | Resources | Owner |
|------|--------|----------|-----------|-------|
| Load Testing | ⬜ | Conduct load tests demonstrating capacity meets expected traffic plus 2x buffer | [k6](https://k6.io/), [Locust](https://locust.io/) | |
| Failure Modes | ⬜ | Document potential failure scenarios and mitigation strategies | [Google SRE Book: Failure Modes](https://sre.google/sre-book/addressing-cascading-failures/) | |
| Chaos Testing | ⬜ | Execute chaos experiments to validate system resilience | [Chaos Monkey](https://netflix.github.io/chaosmonkey/), [Gremlin](https://www.gremlin.com/) | |
| Backup & Recovery | ⬜ | Implement and test regular backup procedures with RTO/RPO defined | [NIST Contingency Planning Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-34r1.pdf) | |
| SLOs/SLIs | ⬜ | Define and instrument service level objectives with appropriate indicators | [Google SRE Book: SLOs](https://sre.google/sre-book/service-level-objectives/) | |
| Graceful Degradation | ⬜ | Implement circuit breakers and document behavior during partial outages | [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html) | |
| Rate Limiting | ⬜ | Implement rate limiting to protect against traffic surges and DoS | [Rate Limiting Patterns](https://cloud.google.com/architecture/rate-limiting-strategies-techniques) | |
| Auto-scaling | ⬜ | Configure auto-scaling based on load metrics with appropriate thresholds | [Kubernetes HPA](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/) | |
| Multi-region Strategy | ⬜ | Document multi-region failover strategy if applicable | [AWS Multi-Region Architecture](https://aws.amazon.com/solutions/implementations/multi-region-application-architecture/) | |

## Observability (Enhanced)

| Item | Status | Guidance | Resources | Owner |
|------|--------|----------|-----------|-------|
| Logging | ⬜ | Configure structured logging with appropriate levels and PII filtering | [ELK Stack](https://www.elastic.co/elastic-stack), [Loki](https://grafana.com/oss/loki/) | |
| Metrics | ⬜ | Implement RED (Rate, Errors, Duration) metrics at minimum | [Prometheus](https://prometheus.io/), [Datadog](https://www.datadog.com/) | |
| Alerting | ⬜ | Configure actionable alerts with appropriate thresholds and runbooks | [PagerDuty](https://www.pagerduty.com/), [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) | |
| Tracing | ⬜ | Implement distributed tracing across service boundaries | [Jaeger](https://www.jaegertracing.io/), [OpenTelemetry](https://opentelemetry.io/) | |
| Runbook Links | ⬜ | Create runbooks for each alert and common troubleshooting scenarios | [Runbook Template](https://www.atlassian.com/incident-management/incident-response/runbooks) | |
| Security Monitoring | ⬜ | Implement security-specific monitoring, logging, and alerting | [SIEM Best Practices](https://www.crowdstrike.com/cybersecurity-101/siem/siem-security/) | |
| Audit Logging | ⬜ | Configure immutable audit logs for security-relevant activities | [NIST Audit Guidelines](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf) | |

## Operational Readiness (Enhanced)

| Item | Status | Guidance | Resources | Owner |
|------|--------|----------|-----------|-------|
| Deployment Pipeline | ⬜ | Implement CI/CD with security gates and automated testing | [Jenkins](https://www.jenkins.io/), [GitHub Actions](https://github.com/features/actions) | |
| Pipeline Security | ⬜ | Secure CI/CD pipeline with proper authentication, least privilege | [SLSA Framework](https://slsa.dev/), [Supply Chain Security](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf) | |
| Rollback Plan | ⬜ | Document and test procedure for emergency rollbacks | [GitOps Model](https://www.weave.works/technologies/gitops/) | |
| Incident Response | ⬜ | Define incident severity levels, response procedures, and escalation paths | [PagerDuty IR Framework](https://response.pagerduty.com/) | |
| Change Management | ⬜ | Implement process for tracking and approving production changes | [ITIL Change Management](https://www.axelos.com/certifications/itil-service-management) | |
| Documentation | ⬜ | Create/update architecture diagrams and system documentation | [C4 Model](https://c4model.com/), [Arc42](https://arc42.org/) | |
| On-call Readiness | ⬜ | Verify on-call rotation is configured with proper access and training | [Google SRE Book: On-Call](https://sre.google/sre-book/being-on-call/) | |
| Maintenance Plan | ⬜ | Document regular maintenance procedures and patching schedule | [Maintenance Planning Guide](https://www.splunk.com/en_us/blog/platform/maintenance-windows-why-when-and-how.html) | |

## Production Transition (Enhanced)

| Item | Status | Guidance | Resources | Owner |
|------|--------|----------|-----------|-------|
| Feature Flags | ⬜ | Implement feature flags to disable functionality without redeployment | [LaunchDarkly](https://launchdarkly.com/), [Flagsmith](https://flagsmith.com/) | |
| Gradual Rollout | ⬜ | Configure ability for canary or percentage-based deployments | [Spinnaker](https://spinnaker.io/), [Argo Rollouts](https://argoproj.github.io/argo-rollouts/) | |
| Post-Launch Monitoring | ⬜ | Define heightened monitoring plan for initial production period | [Datadog Dashboards](https://www.datadog.com/product/dashboards-notebooks) | |
| Security Validation | ⬜ | Perform final security validation in production environment | [OWASP Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) | |
| Launch Approval | ⬜ | Obtain formal sign-offs from Security, SRE, and Product stakeholders | [RACI Matrix Template](https://www.projectmanagement.com/contentPages/article.cfm?ID=209312) | |
| Post-Launch Review | ⬜ | Schedule post-launch security and reliability review (1-2 weeks after) | [Blameless Post-Mortem](https://www.atlassian.com/incident-management/postmortem) | |

## Process 

1. For each item, update the Status column with one of:
   - ⬜ Not Started
   - 🟡 In Progress
   - 🟢 Complete
   - 🔴 Blocked

2. Assign an Owner to each item who is responsible for completion

3. Add links to your organization's specific resources in the Resources column

4. Consider holding regular readiness reviews to track progress toward production

5. Schedule a risk assessment for any items that cannot be completed before launch

6. After launch, conduct a retrospective to improve the checklist for future deployments, (where applicable)

