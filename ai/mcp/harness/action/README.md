# MCP-SLAYER GitHub Action

Run OWASP MCP Top 10 security assessments against your MCP infrastructure as part of CI/CD.

## Quick Start

```yaml
- uses: your-org/mcp-slayer-action@v1
  with:
    config: slayer-config.yaml
    fail-on-critical: "true"
```

## Full Example

```yaml
name: MCP Security Gate
on:
  pull_request:
    paths: ["mcp-server/**", "agent-config/**"]
  schedule:
    - cron: "0 6 * * 1"  # Weekly Monday 6AM UTC

jobs:
  mcp-security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # For SARIF upload

    steps:
      - uses: actions/checkout@v4

      - uses: your-org/mcp-slayer-action@v1
        id: slayer
        with:
          config: .security/slayer-config.yaml
          modules: "all"
          campaign: "all"
          output-formats: "json,sarif,markdown"
          fail-on-critical: "true"
          fail-on-high: "false"
          upload-sarif: "true"

      - name: Comment on PR
        if: github.event_name == 'pull_request' && steps.slayer.outputs.findings-total > 0
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `## MCP-SLAYER Results\n\n` +
                    `| Metric | Count |\n|---|---|\n` +
                    `| Total | ${{ steps.slayer.outputs.findings-total }} |\n` +
                    `| Critical | ${{ steps.slayer.outputs.findings-critical }} |\n` +
                    `| High | ${{ steps.slayer.outputs.findings-high }} |\n`
            })

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mcp-security-results
          path: slayer-results/
```

## Inputs

| Input | Description | Default |
|---|---|---|
| `config` | Path to slayer-config.yaml | `slayer-config.yaml` |
| `modules` | Modules to run (comma-separated or 'all') | `all` |
| `campaign` | Campaign chain to run (ID, 'all', or empty) | `` |
| `output-formats` | Report formats | `json,sarif` |
| `output-dir` | Results directory | `slayer-results` |
| `fail-on-critical` | Fail if CRITICAL findings exist | `true` |
| `fail-on-high` | Fail if HIGH+ findings exist | `false` |
| `upload-sarif` | Upload to GitHub Security tab | `true` |
| `python-version` | Python version | `3.12` |

## Outputs

| Output | Description |
|---|---|
| `findings-total` | Total findings discovered |
| `findings-critical` | CRITICAL severity count |
| `findings-high` | HIGH severity count |
| `report-path` | Path to results directory |
| `exit-code` | 0=clean, 1=policy violation |

## Policy Gates

Use `fail-on-critical` and `fail-on-high` to enforce security policy:

- **PR gate**: Block merges when critical MCP vulnerabilities exist
- **Deploy gate**: Prevent deployment with HIGH+ findings
- **Audit mode**: Set both to `false` for monitoring without blocking

## SARIF Integration

When `upload-sarif: true`, findings appear in the repository's Security tab
under Code Scanning. This provides:
- Persistent vulnerability tracking across commits
- Automatic dismissal when issues are fixed
- Integration with GitHub security advisories
