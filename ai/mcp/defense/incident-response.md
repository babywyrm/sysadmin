# MCP Incident Response Playbooks

IR procedures for MCP-specific incident types. These supplement — not replace —
standard IR processes. Each playbook assumes the SOC has already triaged the
alert and confirmed it is not a false positive.

---

## Playbook Index

| ID | Incident Type | Threat ID | Severity | Containment SLA |
|---|---|---|---|---|
| IR-01 | Prompt Injection Exploitation | MCP-T01, T02 | High | 15 min |
| IR-02 | Cross-Tool Token Replay | MCP-T04 | Critical | 5 min |
| IR-03 | Data Exfiltration via MCP Chain | MCP-T12 | Critical | 10 min |
| IR-04 | Agent Config Tampering | MCP-T09 | Critical | 5 min |
| IR-05 | SSRF to Cloud Metadata | MCP-T06 | Critical | 5 min |

---

## IR-01: Prompt Injection Exploitation

**Trigger:** D07 alert (injection pattern in tool output) confirmed with
evidence of agent behavior change.

### Contain (target: 15 min)

1. Identify the affected session(s) via `session_id`
2. Terminate active sessions for affected user(s)
3. Disable the tool that returned the injected content
4. If injection came from a content source (wiki, repo, ticket):
   - Revert the content change if possible
   - Flag the content source as quarantined

### Investigate

- What content source contained the injection?
- Which user/account planted it? (may be compromised)
- What actions did the agent take after ingesting the injection?
- Were any destructive operations executed?
- Were any secrets exposed in agent output?
- Was the injection direct (user input) or indirect (content source)?

### Recover

- Rotate any credentials the agent may have exposed
- Revert any changes the agent made under injected instructions
- Re-enable the tool with tightened output scanning
- Add the observed injection pattern to Prompt Guard

### Post-Incident

- [ ] Add injection pattern to regression test suite
- [ ] Update content trust labeling for the affected source
- [ ] Review whether HITL gates would have prevented the action
- [ ] File CVE/internal advisory if the injection vector is novel

---

## IR-02: Cross-Tool Token Replay

**Trigger:** D01 (audience mismatch) or D09 (JTI replay) confirmed.

### Contain (target: 5 min)

1. Revoke the replayed token immediately
2. Invalidate all tokens for the affected `session_id`
3. If the source of the leaked token is unknown:
   - Rotate the signing key (JWK rotation)
   - This invalidates ALL active tokens — coordinate with ops

### Investigate

- How was the token captured? (log inspection, network tap, tool output?)
- Which tool was the token originally issued for? (`aud` claim)
- Which tool accepted it incorrectly? (missing `aud` validation = vuln)
- Was the replay from the same IP/workload or external?
- Was JTI validation actually enforced? (check JTI store)

### Recover

- Fix audience validation on the tool that accepted the replayed token
- Verify JTI store is operational and TTL matches token `exp`
- Re-issue tokens with stricter claims if needed
- Re-enable affected tools after fix is verified

### Post-Incident

- [ ] Add audience validation test to MCP-SLAYER confused-deputy module
- [ ] Verify every tool enforces `aud` + `jti` (not just the affected one)
- [ ] Review whether shared signing keys contributed to the issue
- [ ] Update the identity module controls documentation

---

## IR-03: Data Exfiltration via MCP Chain

**Trigger:** D03 (high-volume output) or D05 (canary hit) confirmed with
evidence of sensitive data in outbound channel.

### Contain (target: 10 min)

1. Disable the egress tool (Slack, email, webhook, etc.)
2. Terminate the affected session
3. If data went to an external destination:
   - Block the destination domain/webhook URL at network layer
   - If Slack: delete the messages via API if possible
4. Preserve all audit logs for the session

### Investigate

- What data was exfiltrated? (content hashes, DLP classification)
- How many messages/requests carried data out?
- Was this a single burst or slow drip over time? (Scenario 6 pattern)
- What was the original prompt or injection that triggered the exfil?
- Which tenants are affected?
- Was the exfil within rate limits? (indicates limit tuning needed)

### Recover

- Rotate any credentials that were exfiltrated
- Notify affected tenants per compliance requirements
- Re-enable egress tool with tighter rate limits and DLP rules
- Add the exfil pattern to canary monitoring

### Post-Incident

- [ ] Review rate limit thresholds — were they too generous?
- [ ] Add DLP patterns for the data types that escaped
- [ ] Consider per-session output volume caps
- [ ] Add exfil scenario to purple team regression suite
- [ ] Review whether cross-MCP action chains need checkpoint approval

---

## IR-04: Agent Config Tampering

**Trigger:** D10 (agent config mutation) confirmed.

### Contain (target: 5 min)

1. Revert the config change immediately (`git revert` or restore from backup)
2. Restart all agent instances to pick up reverted config
3. Suspend the agent service account that made the write
4. If a new MCP endpoint was added: block it at network layer immediately

### Investigate

- What was changed? (system prompt, tool list, permissions, MCP endpoints?)
- What injection vector caused the agent to modify its own config?
- Was the config repo writable by the agent? (it shouldn't be)
- How long was the tampered config active?
- How many sessions were affected during that window?
- Did the tampered config weaken security gates (e.g., remove HITL)?

### Recover

- Verify the restored config matches known-good state
- Audit all actions taken during the tampered window
- Revoke agent write access to config repository permanently
- If external MCP was added: investigate what data it received

### Post-Incident

- [ ] Enforce read-only access for agent service accounts to config repos
- [ ] Add branch protection / PR approval for config changes
- [ ] Add config drift detection (hash comparison on startup)
- [ ] Add self-modification scenario to regression suite
- [ ] Review whether the injection that triggered this is in the scanner

---

## IR-05: SSRF to Cloud Metadata

**Trigger:** D02 (metadata IP access) confirmed with evidence of credential
exposure in response.

### Contain (target: 5 min)

1. Rotate the exposed IAM credentials immediately
   - AWS: `aws iam delete-access-key` + create new
   - If IRSA: force pod restart to get fresh STS credentials
2. Block the egress path that reached metadata (should already be blocked)
3. Terminate the affected session
4. Check CloudTrail/audit logs for any actions taken with the leaked creds

### Investigate

- Which tool made the metadata request?
- Was it triggered by a prompt (injection) or a bug in the tool?
- What IP encoding bypass was used? (direct, decimal, hex, DNS rebinding?)
- Were credentials actually returned? (IMDSv2 requires token — was it bypassed?)
- What actions were taken with the leaked credentials? (CloudTrail)
- Were other pods in the same namespace also vulnerable?

### Recover

- Patch the egress controls (NetworkPolicy blocking 169.254.0.0/16)
- Implement resolved-IP validation in fetch proxy
- Verify IMDSv2 is enforced (requires token, short TTL)
- Re-enable the tool after egress fix is verified

### Post-Incident

- [ ] Verify NetworkPolicy blocks ALL metadata ranges (AWS, GCP, Azure)
- [ ] Verify fetch proxy validates resolved IP, not just input URL
- [ ] Add all IP encoding variants to SSRF regression tests
- [ ] Review if any other tools have URL-fetching capability without proxy
- [ ] Consider disabling IMDSv1 entirely at instance level

---

## General IR Principles for MCP Incidents

1. **Session ID is your primary correlation key.** Every MCP action in a
   session should be traceable via a single `session_id`.

2. **Preserve the full audit trail before containment.** MCP incidents often
   involve multi-tool chains — you need the complete sequence.

3. **Assume the agent's reports are unreliable.** If the agent was
   compromised, its own status messages ("recovery complete") cannot be
   trusted.

4. **Check for persistence.** MCP-T09 and MCP-T14 both create persistence
   mechanisms that survive session termination. Always check for:
   - Config changes
   - New webhook/callback registrations
   - Modified system prompts
   - New tool registrations

5. **Multi-tenant blast radius.** If a shared agent serves multiple tenants,
   assume all tenants in the affected session window may be impacted.

6. **Coordinate with the red team.** Every confirmed MCP incident should
   become a regression test in the purple team suite.
