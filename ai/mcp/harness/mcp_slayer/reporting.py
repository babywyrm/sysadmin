"""Multi-format report generation engine."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from mcp_slayer.models import AttackOutcome, Finding, Severity

if TYPE_CHECKING:
    from mcp_slayer.engine import SlayerContext


class ReportGenerator:
    """Generates JSON, YAML, Markdown, and SARIF reports from findings."""

    def __init__(self, ctx: SlayerContext):
        self.ctx = ctx
        self.logger = logging.getLogger("slayer.reporter")

    async def generate_reports(self, findings: list[Finding]) -> None:
        sorted_findings = sorted(findings, key=lambda f: f.severity, reverse=True)
        self.ctx.config.output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in self.ctx.config.output_formats:
            output_file = self._get_output_path(fmt)
            self.logger.info(f"Generating {fmt.upper()} report: {output_file}")

            if fmt == "json":
                self._generate_json(sorted_findings, output_file)
            elif fmt == "yaml":
                self._generate_yaml(sorted_findings, output_file)
            elif fmt == "markdown":
                self._generate_markdown(sorted_findings, output_file)
            elif fmt == "sarif":
                self._generate_sarif(sorted_findings, output_file)

    def _get_output_path(self, fmt: str) -> Path:
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        return self.ctx.config.output_dir / f"slayer-report_{timestamp}.{fmt}"

    def _generate_json(self, findings: list[Finding], output_path: Path):
        report = {
            "metadata": {
                "version": self.ctx.config.version,
                "generated_at": datetime.now(UTC).isoformat(),
                "target_gateway": str(self.ctx.config.gateway.base_url),
                "tools_tested": [t.name for t in self.ctx.config.tools],
                "modules_executed": list(self.ctx.modules_executed),
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    s.value: sum(1 for f in findings if f.severity == s)
                    for s in Severity
                },
                "by_outcome": {
                    o.value: sum(1 for f in findings if f.outcome == o)
                    for o in AttackOutcome
                },
            },
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        output_path.write_text(json.dumps(report, indent=2, default=str))

    def _generate_yaml(self, findings: list[Finding], output_path: Path):
        findings_data = [f.model_dump(mode="json") for f in findings]
        output_path.write_text(
            yaml.dump({"findings": findings_data}, default_flow_style=False)
        )

    def _generate_markdown(self, findings: list[Finding], output_path: Path):
        lines = [
            "# MCP-SLAYER Security Assessment Report",
            "",
            f"**Generated**: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Target**: {self.ctx.config.gateway.base_url}",
            f"**Tools Tested**: {', '.join(t.name for t in self.ctx.config.tools)}",
            "",
            "---",
            "",
            f"## Summary: {len(findings)} findings",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for severity in reversed(list(Severity)):
            count = sum(1 for f in findings if f.severity == severity)
            lines.append(f"| {severity.value} | {count} |")

        lines.extend(["", "---", "", "## Findings", ""])

        for idx, finding in enumerate(findings, 1):
            threat_ids = ", ".join(finding.playbook_threat_ids) if finding.playbook_threat_ids else "—"
            lines.extend([
                f"### {idx}. {finding.title}",
                "",
                f"**Severity**: {finding.severity.value} | "
                f"**OWASP**: {finding.owasp_category.value} | "
                f"**Playbook Threats**: {threat_ids}",
                "",
                f"**Description**: {finding.description}",
                "",
                f"**Impact**: {finding.impact}",
                "",
                f"**Recommendation**: {finding.recommendation}",
                "",
                "---",
                "",
            ])

        output_path.write_text("\n".join(lines))

    def _generate_sarif(self, findings: list[Finding], output_path: Path):
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "MCP-SLAYER",
                        "version": self.ctx.config.version,
                        "informationUri": "https://github.com/owasp/mcp-top-10",
                    }
                },
                "results": [
                    {
                        "ruleId": f.owasp_category.value,
                        "level": self._sarif_level(f.severity),
                        "message": {"text": f"{f.title}: {f.description}"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(f.target_url)}
                            }
                        }],
                    }
                    for f in findings
                ],
            }],
        }
        output_path.write_text(json.dumps(sarif, indent=2))

    def _sarif_level(self, severity: Severity) -> str:
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }[severity]
