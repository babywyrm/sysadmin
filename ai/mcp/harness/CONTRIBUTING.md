# Contributing to MCP-SLAYER

Thank you for contributing to MCP security research. This guide covers
how to submit new attack scenarios, modules, campaign chains, and detection rules.

## What We Accept

| Contribution | Description | Difficulty |
|---|---|---|
| Attack scenario | Documented attack path with reproduction steps | Low |
| Detection rule | SPL/KQL/Sigma rule for an existing attack class | Low |
| Campaign chain | YAML campaign definition exercising existing modules | Medium |
| Payload generator | New generator or mutation operator | Medium |
| Attack module | Full module implementation with tests | High |
| Taxonomy extension | New MCP-T## threat ID with OWASP mapping | High |

## Quick Start

```bash
git clone <repo>
cd harness
uv sync
uv run pytest  # verify clean baseline
```

## Submitting an Attack Scenario

The lowest-barrier contribution. Create a markdown file describing an attack:

```markdown
# Scenario: [Name]

## Threat Model
- **OWASP Category**: MCP## (e.g., MCP06)
- **Playbook Threat**: MCP-T## (e.g., MCP-T02)
- **Attack Surface**: [tool output / schema / delegation / etc.]

## Description
[What the attack does and why it works]

## Reproduction Steps
1. [Step 1]
2. [Step 2]
3. [Expected vulnerable behavior]

## Detection Signals
- [What blue team should alert on]

## Remediation
- [How to fix it]

## References
- [Links to research, CVEs, blog posts]
```

Place in `scenarios/` and submit a PR.

## Submitting a Campaign Chain

Create a YAML file in `mcp_slayer/campaign/chains/`:

```yaml
id: your-chain-id
name: "Human-Readable Name"
description: "What defense-in-depth property this validates"

stages:
  - id: stage-1
    module: existing-module-id  # Must be in MODULE_REGISTRY
    action: "What this stage does"
    taxonomy_ids: ["MCP-T##"]
    gate: stop_on_block

  - id: stage-2
    module: another-module-id
    action: "Builds on stage-1"
    depends_on: [stage-1]
    inject_from_prior: true
    gate: continue_always

success_conditions:
  - "What makes this campaign a concern"

blue_team_gates:
  - "What should catch this chain"
```

Requirements:
- All referenced modules must exist in `MODULE_REGISTRY`
- All `depends_on` references must be valid stage IDs within the campaign
- At least 2 stages (single-stage chains are just module runs)
- Include `success_conditions` and `blue_team_gates`

## Submitting an Attack Module

Modules live in `mcp_slayer/modules/`. Each module:

1. Extends `AttackModule` base class
2. Declares class variables: `id`, `name`, `owasp_category`, `playbook_threats`, `description`, `severity_range`
3. Implements `async def run(self) -> list[Finding]`
4. Uses `_execute_with_safeguards()` for rate limiting and kill switch
5. Returns `Finding` objects with proper taxonomy mapping

Template:

```python
class YourModule(AttackModule):
    id: ClassVar[str] = "your-module-id"
    name: ClassVar[str] = "Human-Readable Name"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.SOME_CATEGORY
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.SOME_THREAT,
    ]
    description: ClassVar[str] = "What this module tests"
    severity_range: ClassVar[tuple[Severity, Severity]] = (Severity.MEDIUM, Severity.CRITICAL)

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.ctx.config.tools:
            # Your logic here
            pass
        return findings
```

Requirements:
- Register in `modules/__init__.py` → `MODULE_REGISTRY`
- Add tests in `tests/` with the fake HTTP client pattern
- All tests must pass: `uv run pytest`

## Submitting a Payload Generator or Mutation

Generators live in `mcp_slayer/payloads/generators.py`.
Mutations live in `mcp_slayer/payloads/mutations.py`.

Generators must:
- Extend `PayloadGenerator`
- Set a unique `generator_id`
- Implement `generate(count: int) -> list[GeneratedPayload]`
- Embed a unique canary in every payload via `_make_canary()`

Mutations must:
- Be a pure function: `(str, random.Random) -> str`
- Be registered in the `MUTATIONS` list with a weight
- Not crash on empty or short inputs

## Code Standards

- Python 3.11+, type hints everywhere
- `ruff` for formatting/linting (config in `pyproject.toml`)
- Tests required for all new code
- No secrets, credentials, or PII in commits
- Ed25519 signing on findings (handled by the engine, no action needed)

## PR Process

1. Fork → branch → implement → test
2. Run full suite: `uv run pytest`
3. Run linter: `uv run ruff check .`
4. Submit PR with description covering: what, why, and how to verify
5. At least one approval required before merge

## Questions?

Open an issue with the `question` label.
