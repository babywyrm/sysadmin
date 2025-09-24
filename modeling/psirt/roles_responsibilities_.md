## Roles & Responsibilities ..draft..

### 🎯 Incident Commander (IC)
- Owns the incident until formally handing off.  
- Ensures **priorities are defined, tracked, and executed**.  
- Tracks **time and cadence of updates** (exec, teams, customers).  
- Not responsible for fixing technical issues — **focuses on coordination**.  
- Declares severity level and phase transitions.  
- Authorizes containment actions that may affect availability.  

---

### 🛠️ Technical Leads
Each lead owns their domain and delegates tasks to responders. All report directly to the IC.

- **Product Security Engineer**  
  - Deep dive on vulnerabilities (CVEs, exploits).  
  - Validate severity and potential impact.  
  - Ensure patches/fixes align with secure coding practices.  

- **Cloud/Infra Engineer**  
  - AWS accounts, IAM, VPC, KMS.  
  - CloudTrail / GuardDuty monitoring and validation.  
  - Containment actions (security groups, account lockdown, key rotation).  

- **CI/CD Engineer**  
  - Pipelines, registries, SBOM validation, secret management.  
  - Contain compromised artifacts.  
  - Validate build system integrity.  

---

### 🔬 Researcher(s)
- Analyze exploit payloads, PoCs, and attack tools.  
- Interface with **threat intel feeds & external researchers**.  
- Provide **attack narrative & threat actor TTPs** for executive/board-level briefings.  
- Feed intel back into detection engineering.  

---

### ✍️ Scribe (Communication Lead – Internal)
- Maintains **real-time log** (timestamps, actions, decisions).  
- Captures **who / what / when** for the official timeline.  
- Posts **summarized updates** to the incident channel.  
- Ensures communication log is preserved for AAR & legal hold.  

---

### 📢 Communications (External)
- Coordinates with **executives, PR/Comms, Legal, and customer-facing teams**.  
- Drafts and ensures **consistent, approved messaging**.  
- Prepares **customer notifications**, status page updates, press statements.  
- Tracks regulatory notification deadlines (GDPR, CCPA, HIPAA, etc.).  

---

### 🤝 Support Liaison
- Interfaces with customer support teams (tickets, escalations, call centers).  
- Provides **sanitized & vetted updates** for customers.  
- Escalates urgent customer reports back to IC & Technical Leads.  

---

### 🔄 Rotation Policy
- **Incident Commander (IC):** 4–6h max per shift.  
- **Engineering Responders:** 8–10h max, with mandatory breaks.  
- **Scribe:** rotates daily.  
- **Hand-off checklist required** for every rotation to preserve continuity.  

---

### ✅ Hand-Off Checklist (All Roles)
- [ ] Current incident status & severity level.  
- [ ] Active containment actions and their owners.  
- [ ] Outstanding decisions & blockers.  
- [ ] Communication cadence & next update timestamp.  
- [ ] Evidence preservation status.  
- [ ] Escalations pending (execs, legal, regulatory, customers).  

