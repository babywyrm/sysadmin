# MCP Security Workshop

> A hands-on workshop teaching MCP security assessment, attack simulation,
> and defense validation. Designed for 4-hour delivery with flexible
> module selection for shorter sessions.

## Learning Objectives

By the end of this workshop, participants will:
1. Understand the OWASP MCP Top 10 attack categories
2. Run MCP-SLAYER assessments against a controlled target
3. Interpret findings and map them to remediation actions
4. Build and execute multi-stage attack campaigns
5. Validate detection coverage with purple team techniques

## Prerequisites

- Familiarity with APIs, HTTP, and JSON
- Basic understanding of LLMs and AI agents
- Python 3.11+ installed (for hands-on labs)
- Docker (for running lab targets)

## Workshop Structure

### Module 1: Threat Landscape (45 min)

**Lecture (25 min)**
- Why MCP changes the security model
- The fundamental problem: everything in context is instruction
- OWASP MCP Top 10 walkthrough with real-world examples
- Playbook taxonomy: MCP-T01 through MCP-T14

**Discussion (20 min)**
- Participants identify MCP tools in their own environments
- Threat modeling exercise: pick a tool, map attack surface

### Module 2: Hands-On Assessment (60 min)

**Setup (10 min)**
- Install MCP-SLAYER
- Deploy lab target (Docker container with intentionally vulnerable MCP server)
- Configure `slayer-config.yaml`

**Lab 1 — Individual Modules (30 min)**
```bash
# Run token validation
mcp-slayer --config lab.yaml --authorized --modules token-validation -v

# Run prompt injection
mcp-slayer --config lab.yaml --authorized --modules prompt-injection-canary -v

# Run full scan
mcp-slayer --config lab.yaml --authorized --modules all \
    --output-formats json,markdown
```

**Lab 2 — Interpreting Results (20 min)**
- Read the markdown report
- Identify CRITICAL vs HIGH vs MEDIUM findings
- Map findings to OWASP categories
- Discuss: which findings would block deployment?

### Module 3: Campaign Chains (60 min)

**Lecture (15 min)**
- Why single-module testing isn't enough
- Attack chains model real adversary behavior
- ABRS scoring for blast radius assessment

**Lab 3 — Running Campaigns (25 min)**
```bash
# List available campaigns
mcp-slayer campaign --list

# Run the semantic drift chain
mcp-slayer campaign --config lab.yaml \
    --chain chain-1-semantic-drift-exfil -v

# Run all campaigns
mcp-slayer campaign --config lab.yaml --chain all -v
```

**Lab 4 — Writing a Custom Campaign (20 min)**
- Participants define a 3-stage campaign YAML
- Exchange campaigns with a partner
- Run partner's campaign against the lab target
- Discuss: did it halt? Where? Why?

### Module 4: Purple Team Operations (60 min)

**Lecture (15 min)**
- Detection validation: MTTD/MTTR measurement
- Canary tokens for proving exfiltration
- Regression testing from confirmed findings
- The continuous validation loop

**Lab 5 — Detection Correlation (25 min)**
- Plant canary tokens in the lab environment
- Run an attack campaign
- Check: did the canary fire? What was the MTTD?
- Review the detection correlation report

**Lab 6 — Regression Suite (20 min)**
```bash
# Generate regression cases from findings
python3 -c "
from mcp_slayer.purple.regression import RegressionSuite
from mcp_slayer.models import Finding
import json

# Load findings from previous scan
findings = [...]  # from JSON report
suite = RegressionSuite(Path('regressions.json'))
suite.add_from_findings(findings)
print(suite.summary())
"
```
- Review generated regression JSON
- Discuss: how would this integrate into CI?

### Module 5: Remediation & Integration (45 min)

**Lecture (15 min)**
- Golden path: the minimum viable security posture
- CI integration with GitHub Actions
- Maturity levels: where are you today, where do you need to be?

**Lab 7 — CI Pipeline Setup (15 min)**
- Create a `.github/workflows/mcp-gate.yml`
- Configure fail-on-critical policy
- Simulate a PR with a vulnerable MCP server config
- Observe: PR blocked by MCP-SLAYER

**Wrap-up & Q&A (15 min)**
- Review: what did we learn?
- Take-home: assessment checklist for your environment
- Resources: scanner landscape, golden path template

---

## Delivery Variants

| Duration | Modules |
|---|---|
| 90 min (intro) | Module 1 + Module 2 |
| 2.5 hours (practitioner) | Module 1 + Module 2 + Module 3 |
| 4 hours (full) | All modules |
| 1 day (advanced) | All modules + custom lab targets + extended campaign writing |

## Lab Target

The workshop uses a containerized, intentionally vulnerable MCP server:

```bash
docker run -p 8080:8080 ghcr.io/your-org/mcp-slayer-lab:latest
```

The lab target exposes:
- Token validation endpoints (with `alg:none` and missing `aud`)
- Tool schemas with hidden instructions
- Injectable tool outputs
- Unprotected exfiltration paths
- No audit logging

## Materials Provided

- Slide deck (Mermaid diagrams from research)
- Lab config files (slayer-config.yaml pre-configured for lab target)
- Cheat sheet: OWASP MCP Top 10 → module mapping → remediation
- Assessment checklist (printable)
- Golden path template (take-home)
