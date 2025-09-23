
# 🛡️ Enterprise Incident Response Runbook
**Product Security Incident Response Team (PSIRT) Playbook**



# ⚡ Quick Reference: Incident Response Phases (..beta..)

---

## **Phase 1 — Detection & Initial Triage (0–30 minutes)**  
- ✅ Confirm authenticity (rule out false positives)  
- ✅ Classify severity (**SEV1–SEV4**)  
- ✅ Spin up **war room** & assign roles  
- ✅ Begin **containment** for SEV1 immediately  

---

## **Phase 2 — Containment & Blast Radius (30 minutes–4 hours)**  
- 🛑 Stop ongoing compromise and limit spread  
- 🗺️ Map blast radius (**infra, apps, data, pipelines**)  
- 📦 Preserve evidence (**chain-of-custody format**)  
- 🔑 Execute containment actions  
  - Rotate credentials  
  - Isolate systems  
  - Block C2 domains  
  - Disable compromised accounts  

---

## **Phase 3 — Investigation & Forensics (parallel with Phase 2)**  
- 🕵️ Reconstruct **attack timeline**  
- 🔍 Identify **root cause & persistence mechanisms**  
- 📂 Collect **volatile/system/network evidence**  
- 🤝 Coordinate with **external forensics** if needed  

---

## **Phase 4 — Remediation & Recovery (hours → weeks)**  
- 🔴 **Critical fixes (0–24h):** containment, hotfixes, customer impact mitigation  
- 🟠 **Short-term (1–7d):** patch rollout, secret rotation, notifications  
- 🟡 **Medium-term (1–4w):** infra hardening, process/policy updates, monitoring  
- 🟢 **Long-term (1–6m):** maturity improvements, vendor/partner security uplift  

---

## **Phase 5 — Post-Incident & Continuous Improvement**  
- 📝 Hot wash (<48h) & **After-Action Review** (<1w)  
- 📊 Document **timeline, impact, lessons learned**  
- 🔄 Update **runbooks, training, detection rules**  
- 📅 Track **action items** at 1w / 1m / 6m horizons  

---

##
##

```
# Incident Response Phases (ASCII Flow with Parallel Tracks)

+---------------------------------------------------------------+
|                        Phase 1: Detection                     |
|      Confirm Incident → Classify Severity → War Room Setup     |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|            Phase 2: Containment & Blast Radius                |
|   Stop Threat → Limit Spread → Preserve Evidence              |
+---------------------------------------------------------------+
                              |
              +----------------------------------+
              |                                  |
              v                                  v
+-----------------------------+     +-----------------------------+
|  Phase 2A: Containment      |     |  Phase 3: Investigation     |
|  Revoke Keys, Isolate Sys   |     |  Root Cause, Timeline,      |
|  Block C2, Rotate Secrets   |     |  Persistence, Forensics     |
+-----------------------------+     +-----------------------------+
              |                                  |
              |                                  |
              +----------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|          Phase 4: Remediation & Recovery                      |
|  🔴 Critical Now → 🟠 Short Term → 🟡 Medium Term → 🟢 Long Term|
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|            Phase 5: Post-Incident & Improvement               |
|  Hot Wash → AAR → Lessons Learned → Playbook Updates          |
+---------------------------------------------------------------+

```


---

## Table of Contents
1. [Overview & Principles](#overview--principles)
2. [Incident Classification](#incident-classification)
3. [War Room Establishment](#war-room-establishment)
4. [Phase-Based Response](#phase-based-response)
5. [Cross-Functional Coordination](#cross-functional-coordination)
6. [Communication Protocols](#communication-protocols)
7. [Evidence Preservation](#evidence-preservation)
8. [Escalation & Legal Considerations](#escalation--legal-considerations)
9. [Metrics & SLAs](#metrics--slas)
10. [Post-Incident Process](#post-incident-process)
11. [Appendices & Templates](#appendices--templates)

---

## Overview & Principles

### Core Philosophy
- **Safety First**: Contain active exploitation before comprehensive analysis
- **Customer Impact Above All**: Prioritize based on customer data exposure and service degradation
- **Parallel Execution**: Investigation, containment, and communication run simultaneously
- **Evidence Integrity**: Preserve forensic evidence while enabling rapid response
- **Sustainable Response**: Build in rotation to prevent team burnout during extended incidents

### Success Metrics
- **MTTD**: Mean Time to Detection < 15 minutes (automated), < 2 hours (manual)
- **MTTR**: Mean Time to Response < 30 minutes (SEV1), < 2 hours (SEV2)
- **MTTC**: Mean Time to Containment < 4 hours (SEV1), < 24 hours (SEV2)

---

## Incident Classification

### Severity Levels

| Level | Description | Response Time | Update Frequency | Escalation |
|-------|-------------|---------------|------------------|------------|
| **SEV1** | Active exploitation, customer impact, data breach, product outage | 15 minutes | 30 minutes | Immediate exec notification |
| **SEV2** | High-risk vulnerability, potential exploitation, limited impact | 2 hours | 2 hours | VP+ notification within 4h |
| **SEV3** | Medium risk, mitigations in place, no immediate threat | 4 hours | 8 hours | Manager notification |
| **SEV4** | Low risk, cosmetic issues, theoretical vulnerabilities | 24 hours | Daily | Team notification only |

### Impact Classification Matrix

| **Impact Type** | **SEV1 Indicators** | **SEV2 Indicators** | **SEV3 Indicators** |
|-----------------|---------------------|---------------------|---------------------|
| **Customer Data** | Active data exfiltration, exposed PII/PHI | Potential access to customer data | Internal data exposure only |
| **Product Integrity** | Security controls bypassed/disabled | Security product degraded performance | Non-security product issues |
| **Availability** | Complete service outage | Partial service degradation | Single component affected |
| **Compliance** | Immediate breach notification required | Potential regulatory implications | Internal policy violations |

---

## War Room Establishment

### Secure War Room Setup (< 10 minutes)
1. **Primary Channel**: Secure Slack channel `#incident-[timestamp]-[brief-desc]`
2. **Video Bridge**: Dedicated WebEx/Teams room with waiting room enabled
3. **Shared Documents**: 
   - Live incident timeline (Google Docs/Confluence)
   - Evidence collection spreadsheet
   - Communication log
4. **Access Control**: Principle of least privilege, documented access log

### War Room Roles & Responsibilities

#### **Incident Commander (IC)**
- Overall incident coordination and decision-making authority
- Declares severity level and phase transitions
- Manages cross-functional communication
- Authorizes containment actions that may impact availability

#### **Investigation Lead**
- Coordinates technical investigation team
- Manages evidence collection and preservation
- Provides technical briefings to IC
- Interfaces with external forensic teams if needed

#### **Communication Lead (Scribe)**
- Maintains incident timeline and documentation
- Manages stakeholder communications
- Coordinates with Legal/PR for external messaging
- Ensures compliance with notification requirements

#### **Technical Responders**
- Platform/Infrastructure teams
- Security Engineering
- Development teams (if code fixes required)
- DevOps/SRE for deployment and monitoring

---

## Phase-Based Response

### Phase 1: Detection & Initial Triage (0-30 minutes)

#### **Objectives**
- Confirm and validate the security incident
- Establish war room and assign roles
- Perform initial severity classification
- Begin containment for SEV1 incidents

#### **Actions**
```markdown
**Detection Sources:**
- [ ] SOC alert validation and enrichment
- [ ] Bug bounty report verification
- [ ] AWS GuardDuty/CloudTrail analysis
- [ ] CI/CD pipeline anomaly investigation
- [ ] Customer-reported security concerns

**Initial Response Checklist:**
- [ ] Establish war room within 10 minutes
- [ ] Assign IC, Investigation Lead, and Scribe
- [ ] Confirm incident authenticity (eliminate false positives)
- [ ] Classify initial severity level
- [ ] Begin evidence collection and preservation
- [ ] Initiate containment for SEV1/SEV2 incidents
- [ ] Notify key stakeholders per escalation matrix
```

#### **Containment Decision Tree**
```
High Confidence Threat? 
├── Yes → Immediate containment
└── No → Continue investigation (30 min max)
    ├── Confirmed Threat → Containment
    └── False Positive → Document and close
```

### Phase 2: Containment & Blast Radius Analysis (30 minutes - 4 hours)

#### **Objectives**
- Stop ongoing compromise or prevent expansion
- Determine full scope of potential impact
- Preserve evidence for forensic analysis
- Establish monitoring for additional indicators

#### **Blast Radius Analysis Worksheet**

```markdown
**Infrastructure Scope:**
- [ ] AWS Accounts affected: [list]
- [ ] Regions impacted: [list]
- [ ] VPCs/Subnets compromised: [list]
- [ ] EC2 instances accessed: [list]
- [ ] Database systems affected: [list]

**Application & Data Scope:**
- [ ] Products/services impacted: [list]
- [ ] Customer segments affected: [list]
- [ ] Data types potentially exposed: [list]
- [ ] Third-party integrations compromised: [list]

**Development & Deployment:**
- [ ] Source code repositories accessed: [list]
- [ ] CI/CD pipelines compromised: [list]
- [ ] Container registries affected: [list]
- [ ] Deployment artifacts compromised: [list]
- [ ] Secrets/credentials potentially exposed: [list]
```

#### **Containment Actions by Type**

| **Incident Type** | **Immediate Actions** | **Evidence Preservation** |
|-------------------|----------------------|--------------------------|
| **Credential Compromise** | Revoke keys, disable accounts, rotate secrets | Preserve access logs, API calls |
| **Malware/Intrusion** | Isolate affected systems, block C2 domains | Memory dumps, disk images |
| **Supply Chain** | Stop builds, quarantine artifacts, block dependencies | Preserve build logs, artifact hashes |
| **Data Breach** | Restrict data access, enable enhanced logging | Preserve access logs, query logs |
| **Insider Threat** | Disable accounts, preserve evidence | HR coordination, legal hold |

### Phase 3: Investigation & Forensics (Parallel with Containment)

#### **Objectives**
- Determine root cause and attack timeline
- Identify all affected systems and data
- Collect evidence for potential legal action
- Develop comprehensive remediation plan

#### **Investigation Framework**
```markdown
**Timeline Reconstruction:**
- [ ] Initial compromise vector identified
- [ ] Lateral movement paths mapped
- [ ] Data access/exfiltration confirmed
- [ ] Persistence mechanisms identified
- [ ] Full attack timeline documented

**Evidence Collection:**
- [ ] System logs preserved (90+ days)
- [ ] Network traffic captures
- [ ] Memory dumps from affected systems
- [ ] Malware samples isolated and analyzed
- [ ] Digital forensics chain of custody maintained
```

### Phase 4: Remediation & Recovery (Hours to Weeks)

#### **Remediation Buckets**

##### 🔴 **Critical Now (0-24 hours)**
- Active threat containment
- Customer impact mitigation
- Critical security controls restoration
- Emergency patches and hotfixes

##### 🟠 **Short-Term (1-7 days)**
- Comprehensive patching rollout
- Secrets rotation across all systems
- Security control tuning and enhancement
- Customer notifications (if required)

##### 🟡 **Medium-Term (1-4 weeks)**
- Infrastructure hardening
- Security architecture improvements
- Process and policy updates
- Long-term monitoring enhancements

##### 🟢 **Long-Term (1-6 months)**
- Strategic security initiatives
- Organizational security maturity improvements
- Vendor security program enhancements

#### **Recovery Validation Checklist**
```markdown
- [ ] All malicious artifacts removed
- [ ] Compromised credentials rotated
- [ ] Security controls functioning properly
- [ ] Monitoring enhanced for similar threats
- [ ] Business operations fully restored
- [ ] Customer impact mitigated
- [ ] Compliance requirements satisfied
```

---

## Cross-Functional Coordination

### **Stakeholder Matrix**

| **Stakeholder** | **SEV1 Notification** | **Update Frequency** | **Information Shared** |
|----------------|----------------------|---------------------|----------------------|
| **Executive Team** | Immediate | 2-4 hours | High-level impact, business risk, timeline |
| **Legal/Compliance** | Within 1 hour | 4 hours | Regulatory implications, breach assessment |
| **Engineering Teams** | Immediate | 30 minutes | Technical details, remediation actions |
| **Customer Success** | Within 2 hours | 4 hours | Customer impact, external messaging |
| **PR/Communications** | Within 4 hours | As needed | Public messaging, media handling |
| **HR** | As needed | As needed | Insider threats, employee communications |

### **Decision Authority Matrix**

| **Decision Type** | **Authority** | **Escalation Required** |
|------------------|---------------|------------------------|
| Technical containment | Investigation Lead | No |
| Service degradation | IC + Engineering Manager | No |
| Customer notifications | IC + Legal + Customer Success | SEV1: Yes, Others: No |
| Public disclosure | Legal + PR + Executive Team | Always |
| Law enforcement involvement | Legal + Executive Team | Always |

---

## Communication Protocols

### **Internal Communications**

#### **Update Templates**

##### SEV1 Executive Brief Template:
```markdown
**INCIDENT UPDATE - [TIMESTAMP]**
**Severity:** SEV1
**Status:** [Investigating/Contained/Resolved]

**Customer Impact:**
- [Number] customers affected
- [Services] experiencing [type of impact]
- ETA for resolution: [timeframe]

**Business Risk:**
- Data exposure: [Yes/No/Unknown]
- Compliance implications: [description]
- Financial impact: [estimate if available]

**Next Steps:**
- [Key actions in next 2 hours]
- Next update: [timestamp]

**IC Contact:** [name/contact]
```

#### **Communication Cadence**
- **Engineering Teams**: Every 30 minutes during active phases
- **Executive Updates**: Every 60 minutes (SEV1), Every 4 hours (SEV2)
- **Legal/Compliance**: Every 2 hours or as developments warrant
- **All-hands notifications**: At phase transitions and resolution

### **External Communications**

#### **Customer Notification Decision Tree**
```
Customer Data Involved?
├── Yes → Legal review required
│   ├── Confirmed exposure → Immediate notification
│   └── Potential exposure → 24-48h notification
└── No → Service impact only
    ├── Significant impact → Proactive notification
    └── Minor impact → Status page update
```

#### **Regulatory Notification Requirements**
- **GDPR**: 72 hours for data breaches affecting EU residents
- **CCPA**: Without unreasonable delay for California residents
- **SOX**: Immediate for material impact to financial reporting
- **Industry-specific**: Healthcare (HIPAA), Financial (PCI-DSS), etc.

---

## Evidence Preservation

### **Digital Forensics Protocols**

#### **Evidence Collection Priority**
1. **Volatile Memory**: RAM dumps, running processes
2. **System State**: Registry, system files, temporary files
3. **Storage Media**: Disk images, database dumps
4. **Network Evidence**: Traffic captures, firewall logs
5. **Application Logs**: Security logs, audit trails

#### **Chain of Custody Requirements**
```markdown
**For each piece of evidence:**
- [ ] Unique identifier assigned
- [ ] Hash values calculated (MD5, SHA-256)
- [ ] Collection timestamp recorded
- [ ] Collector identification documented
- [ ] Storage location secured and logged
- [ ] Access log maintained
```

### **Legal Hold Procedures**
- Immediate legal hold notification for SEV1/SEV2 incidents
- Preservation of all relevant communications (Slack, email, documents)
- Coordination with Legal team for external disclosure requirements
- Documentation of all investigative steps for potential litigation

---

## Escalation & Legal Considerations

### **Escalation Matrix**

#### **Internal Escalation Triggers**
- **30 minutes**: No containment progress on SEV1
- **2 hours**: Unable to determine blast radius
- **4 hours**: Customer impact continues without resolution path
- **24 hours**: Investigation reveals potential criminal activity

#### **External Escalation Triggers**
- **Law Enforcement**: Evidence of criminal activity, nation-state actors
- **Federal Agencies**: Critical infrastructure impact, national security implications
- **Industry Partners**: Supply chain compromise affecting multiple organizations
- **Customers**: Confirmed or likely data exposure

### **Legal Considerations Checklist**
```markdown
- [ ] Attorney-client privilege preserved for sensitive communications
- [ ] Regulatory notification requirements assessed
- [ ] Customer contractual notification obligations reviewed
- [ ] Insurance carrier notification (cyber insurance)
- [ ] Third-party vendor notification requirements
- [ ] Public disclosure requirements evaluated
```

---

## Metrics & SLAs

### **Response Time SLAs**

| **Metric** | **SEV1** | **SEV2** | **SEV3** | **SEV4** |
|------------|----------|----------|----------|----------|
| Initial Response | 15 min | 2 hours | 4 hours | 24 hours |
| War Room Established | 10 min | 30 min | 1 hour | N/A |
| Containment Started | 30 min | 4 hours | 8 hours | N/A |
| Executive Notification | 30 min | 4 hours | 24 hours | N/A |
| Customer Notification | 2 hours* | 24 hours* | N/A | N/A |

*If customer impact confirmed

### **Quality Metrics**
- **False Positive Rate**: < 15% for automated detections
- **Escalation Accuracy**: > 90% appropriate severity classification
- **Containment Effectiveness**: < 5% of incidents require re-containment
- **Documentation Completeness**: 100% of SEV1/SEV2 incidents have complete timeline

### **Post-Incident Metrics**
- **Mean Time to Detection (MTTD)**: From initial compromise to detection
- **Mean Time to Response (MTTR)**: From detection to response initiation  
- **Mean Time to Containment (MTTC)**: From detection to threat containment
- **Mean Time to Recovery (MTTR)**: From detection to full service restoration

---

## Post-Incident Process

### **After-Action Review (AAR) Process**

#### **Timeline Requirements**
- **Immediate (< 48 hours)**: Hot wash with core team
- **Short-term (< 1 week)**: Comprehensive AAR with all stakeholders
- **Medium-term (< 1 month)**: Follow-up on action items and process improvements

#### **AAR Structure**
```markdown
**Executive Summary**
- Incident overview and timeline
- Customer and business impact
- Root cause analysis
- Key lessons learned

**Technical Analysis**
- Attack vector and methodology
- Security control effectiveness
- Detection and response timeline
- Evidence and forensic findings

**Response Evaluation**
- What went well
- What could be improved
- Process and communication gaps
- Resource and training needs

**Action Items**
- Immediate fixes (< 1 week)
- Short-term improvements (< 1 month)
- Strategic initiatives (< 6 months)
- Assigned owners and due dates
```

### **Continuous Improvement Process**

#### **Knowledge Management**
- Incident response playbook updates
- Threat intelligence integration
- Detection rule improvements
- Training material updates

#### **Process Optimization**
- Communication workflow improvements
- Tool integration and automation
- Cross-functional coordination enhancements
- Escalation procedure refinements

---

## Appendices & Templates

### **Appendix A: Incident Declaration Template**

```markdown
**SECURITY INCIDENT DECLARATION**

**Basic Information:**
- Incident ID: INC-[YYYYMMDD]-[###]
- Declaration Time: [UTC timestamp]
- Declaring Person: [Name, Role]
- Initial Severity: [SEV1/SEV2/SEV3/SEV4]

**Incident Summary:**
[Brief description of what happened]

**Immediate Impact:**
- Systems affected: [list]
- Customer impact: [Yes/No/Unknown]
- Data exposure risk: [High/Medium/Low/Unknown]

**Initial Response Actions:**
- [ ] War room established
- [ ] IC assigned: [Name]
- [ ] Investigation Lead assigned: [Name]
- [ ] Scribe assigned: [Name]
- [ ] Key stakeholders notified
```

### **Appendix B: Evidence Collection Log**

```markdown
**DIGITAL EVIDENCE LOG**

| Evidence ID | Description | Collection Time | Collector | Hash (SHA-256) | Location | Chain of Custody |
|-------------|-------------|----------------|-----------|----------------|----------|------------------|
| EVD-001 | Server memory dump | [timestamp] | [name] | [hash] | [location] | [log] |
| EVD-002 | Network traffic capture | [timestamp] | [name] | [hash] | [location] | [log] |
```

### **Appendix C: Stakeholder Notification Templates**

#### **Executive Notification Template**
```markdown
Subject: SECURITY INCIDENT - SEV[X] - [Brief Description]

[Executive Name],

We are responding to a SEV[X] security incident that began at [time].

IMMEDIATE IMPACT:
- [Customer/business impact]
- [Data exposure assessment]
- [Service availability status]

CURRENT STATUS:
- [Containment status]
- [Investigation progress]
- [ETA for resolution]

NEXT STEPS:
- [Key actions in next 2-4 hours]
- [Your involvement needed, if any]

I will provide updates every [frequency] until resolved.

[IC Name and Contact]
```

#### **Customer Notification Template**
```markdown
Subject: Important Security Notice - [Service Name]

Dear [Customer Name],

We are writing to inform you of a security incident that may have affected your account with [Company Name].

WHAT HAPPENED:
[Brief, clear explanation of the incident]

WHAT INFORMATION WAS INVOLVED:
[Specific data types that may have been affected]

WHAT WE ARE DOING:
[Steps taken to address the incident and prevent future occurrences]

WHAT YOU CAN DO:
[Recommended actions for customers]

We sincerely apologize for this incident and any inconvenience it may cause.

For questions, please contact us at [contact information].

[Company Name] Security Team
```

### **Appendix D: Common Incident Playbooks**

#### **Data Breach Response Playbook**
```markdown
**IMMEDIATE ACTIONS (0-2 hours):**
- [ ] Identify data types and volume affected
- [ ] Determine customer vs. internal data exposure
- [ ] Begin legal hold and evidence preservation
- [ ] Notify Legal and Compliance teams
- [ ] Assess regulatory notification requirements

**SHORT-TERM ACTIONS (2-24 hours):**
- [ ] Complete blast radius analysis
- [ ] Prepare customer notifications (if required)
- [ ] Engage external forensics (if needed)
- [ ] Begin regulatory notifications (if required)
- [ ] Coordinate with insurance carrier

**ONGOING ACTIONS:**
- [ ] Monitor for misuse of exposed data
- [ ] Provide identity monitoring services (if applicable)
- [ ] Regular updates to affected customers
- [ ] Coordinate with law enforcement (if applicable)
```

#### **Supply Chain Compromise Playbook**
```markdown
**IMMEDIATE ACTIONS:**
- [ ] Identify compromised components/dependencies
- [ ] Stop all builds using affected components
- [ ] Quarantine potentially compromised artifacts
- [ ] Notify affected downstream customers
- [ ] Coordinate with upstream vendors

**INVESTIGATION ACTIONS:**
- [ ] Analyze build system logs
- [ ] Verify integrity of existing deployments
- [ ] Assess impact on customer deployments
- [ ] Coordinate industry-wide response (if needed)

**RECOVERY ACTIONS:**
- [ ] Rebuild all affected artifacts
- [ ] Implement enhanced supply chain security
- [ ] Update SBOM and dependency tracking
- [ ] Enhance vendor security requirements
```

---
```
**Document Version:** 2.1
**Last Updated:** [Current Date]
**Next Review:** [Date + 6 months]
**Owner:** [Your Name], PSIRT Manager
**Approved By:** [CISO/Security Leadership]
```


##
##
