"""Campaign runner — orchestrates multi-stage attack chains.

Executes campaign stages sequentially, applying gate logic between stages.
When a stage is blocked, the runner can halt (validating defense-in-depth)
or continue (measuring detection coverage across the full chain).

Findings from earlier stages propagate forward as context, simulating how
real attackers leverage prior footholds to advance.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from mcp_slayer.campaign.models import (
    ABRSScore,
    CampaignDefinition,
    CampaignResult,
    StageDefinition,
    StageGate,
    StageResult,
)
from mcp_slayer.exceptions import SlayerKillSwitchError
from mcp_slayer.models import AttackOutcome, Finding
from mcp_slayer.modules import MODULE_REGISTRY

if TYPE_CHECKING:
    from mcp_slayer.engine import SlayerContext


class CampaignRunner:
    """Executes a campaign definition against a live target.

    Usage:
        async with SlayerContext(config) as ctx:
            runner = CampaignRunner(ctx)
            result = await runner.execute(campaign_def)
    """

    def __init__(self, ctx: SlayerContext):
        self.ctx = ctx
        self.logger = logging.getLogger("slayer.campaign")

    async def execute(self, campaign: CampaignDefinition) -> CampaignResult:
        """Run all stages of a campaign, respecting gates and dependencies."""
        self.logger.info(
            f"Campaign '{campaign.name}' starting — {len(campaign.stages)} stages"
        )

        result = CampaignResult(
            campaign_id=campaign.id,
            campaign_name=campaign.name,
        )

        stage_outcomes: dict[str, StageResult] = {}
        prior_findings: list[Finding] = []
        start_time = time.monotonic()

        for stage in campaign.stages:
            if self.ctx.kill_switch_active:
                self.logger.critical("Kill switch active — aborting campaign")
                result.halted_at_stage = stage.id
                result.halt_reason = "kill_switch"
                break

            # Check dependency gates
            if not self._dependencies_met(stage, stage_outcomes):
                sr = StageResult(
                    stage_id=stage.id,
                    module_id=stage.module,
                    outcome=AttackOutcome.SKIPPED,
                    skipped=True,
                    skip_reason=f"dependency not met: {stage.depends_on}",
                )
                stage_outcomes[stage.id] = sr
                result.stage_results.append(sr)
                self.logger.info(f"  [{stage.id}] SKIPPED — dependency unmet")
                continue

            # Execute stage
            sr = await self._execute_stage(stage, prior_findings)
            stage_outcomes[stage.id] = sr
            result.stage_results.append(sr)

            # Propagate findings forward
            if sr.findings:
                prior_findings.extend(sr.findings)

            # Apply gate logic
            if self._should_halt(stage, sr):
                result.halted_at_stage = stage.id
                result.halt_reason = f"gate={stage.gate.value}, outcome={sr.outcome.value}"
                self.logger.info(
                    f"  [{stage.id}] Campaign halted — {result.halt_reason}"
                )
                break

        # Finalize
        result.completed_at = datetime.now(UTC)
        result.duration_ms = int((time.monotonic() - start_time) * 1000)
        result.compute_summary()

        # Compute ABRS if parameters provided
        result.abrs = ABRSScore(
            reachable_agents=campaign.abrs_reachable_agents,
            avg_tool_scope=campaign.abrs_avg_tool_scope,
            memory_persistence_days=campaign.abrs_memory_persistence_days,
            isolation_boundaries=campaign.abrs_isolation_boundaries,
        ).compute()

        self.logger.info(
            f"Campaign '{campaign.name}' complete: "
            f"{result.stages_vulnerable}/{result.stages_executed} vulnerable, "
            f"detection_rate={result.detection_rate:.0%}, "
            f"ABRS={result.abrs.score:.1f} ({result.abrs.risk_level})"
        )

        return result

    async def _execute_stage(
        self, stage: StageDefinition, prior_findings: list[Finding]
    ) -> StageResult:
        """Execute a single campaign stage using its mapped attack module."""
        self.logger.info(
            f"  [{stage.id}] Running module '{stage.module}' — {stage.action}"
        )

        if stage.module not in MODULE_REGISTRY:
            self.logger.error(f"  [{stage.id}] Unknown module: {stage.module}")
            return StageResult(
                stage_id=stage.id,
                module_id=stage.module,
                outcome=AttackOutcome.ERROR,
                error=f"Module '{stage.module}' not in registry",
            )

        module_class = MODULE_REGISTRY[stage.module]
        start = time.monotonic()

        try:
            # Apply per-stage overrides to context if specified
            original_timeout = self.ctx.config.timeout_seconds
            if stage.timeout_seconds:
                self.ctx.config.timeout_seconds = stage.timeout_seconds

            module = module_class(self.ctx)

            # Inject prior stage context if requested
            if stage.inject_from_prior and prior_findings:
                self._inject_context(module, prior_findings)

            findings = await module.run()
            duration_ms = int((time.monotonic() - start) * 1000)

            # Restore original timeout
            self.ctx.config.timeout_seconds = original_timeout

            # Classify stage outcome from findings
            outcome = self._classify_outcome(findings)

            sr = StageResult(
                stage_id=stage.id,
                module_id=stage.module,
                outcome=outcome,
                findings=findings,
                duration_ms=duration_ms,
                alert_fired=any(f.alert_fired for f in findings),
                detection_time_ms=self._min_detection_time(findings),
                blocking_control=self._blocking_control(findings),
            )

            status_icon = "🚨" if outcome == AttackOutcome.VULNERABLE else "✅"
            self.logger.info(
                f"  [{stage.id}] {status_icon} {outcome.value} "
                f"({len(findings)} findings, {duration_ms}ms)"
            )
            return sr

        except SlayerKillSwitchError:
            raise
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            self.logger.exception(f"  [{stage.id}] ERROR: {e}")
            return StageResult(
                stage_id=stage.id,
                module_id=stage.module,
                outcome=AttackOutcome.ERROR,
                error=str(e),
                duration_ms=duration_ms,
            )

    def _dependencies_met(
        self, stage: StageDefinition, outcomes: dict[str, StageResult]
    ) -> bool:
        """Check if all dependency stages succeeded (were VULNERABLE)."""
        if not stage.depends_on:
            return True
        for dep_id in stage.depends_on:
            dep = outcomes.get(dep_id)
            if dep is None or dep.skipped:
                return False
            if dep.outcome not in (
                AttackOutcome.VULNERABLE,
                AttackOutcome.PARTIALLY_VULNERABLE,
            ):
                return False
        return True

    def _should_halt(self, stage: StageDefinition, result: StageResult) -> bool:
        """Determine if the campaign should stop at this stage."""
        if stage.gate == StageGate.CONTINUE_ALWAYS:
            return False
        if stage.gate == StageGate.STOP_ON_BLOCK:
            return result.outcome in (AttackOutcome.BLOCKED, AttackOutcome.DETECTED)
        if stage.gate == StageGate.STOP_ON_VULN:
            return result.outcome in (
                AttackOutcome.VULNERABLE,
                AttackOutcome.PARTIALLY_VULNERABLE,
            )
        return False

    def _classify_outcome(self, findings: list[Finding]) -> AttackOutcome:
        """Derive aggregate stage outcome from its findings."""
        if not findings:
            return AttackOutcome.BLOCKED

        outcomes = [f.outcome for f in findings]
        if AttackOutcome.VULNERABLE in outcomes:
            return AttackOutcome.VULNERABLE
        if AttackOutcome.PARTIALLY_VULNERABLE in outcomes:
            return AttackOutcome.PARTIALLY_VULNERABLE
        if AttackOutcome.DETECTED in outcomes:
            return AttackOutcome.DETECTED
        if AttackOutcome.BLOCKED in outcomes:
            return AttackOutcome.BLOCKED
        return AttackOutcome.ERROR

    def _inject_context(self, module, prior_findings: list[Finding]) -> None:
        """Pass prior-stage findings into the module as injectable context.

        Modules that support context injection expose an `injected_context`
        attribute. This enables realistic chained attacks where output from
        stage N feeds stage N+1.
        """
        if hasattr(module, "injected_context"):
            module.injected_context = [
                {
                    "module": f.attack_module,
                    "target_tool": f.target_tool,
                    "outcome": f.outcome.value,
                    "evidence": f.evidence,
                }
                for f in prior_findings
                if f.outcome
                in (AttackOutcome.VULNERABLE, AttackOutcome.PARTIALLY_VULNERABLE)
            ]

    def _min_detection_time(self, findings: list[Finding]) -> int | None:
        """Earliest detection time across findings."""
        times = [f.time_to_detect_ms for f in findings if f.time_to_detect_ms]
        return min(times) if times else None

    def _blocking_control(self, findings: list[Finding]) -> str | None:
        """Identify which control blocked the attack."""
        for f in findings:
            if f.outcome in (AttackOutcome.BLOCKED, AttackOutcome.DETECTED):
                if f.blue_team_signal:
                    return f.blue_team_signal
        return None


def load_campaign(path: Path) -> CampaignDefinition:
    """Load a campaign definition from a YAML file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Campaign file must be a YAML mapping: {path}")
    return CampaignDefinition(**raw)


def load_builtin_campaigns() -> list[CampaignDefinition]:
    """Load all built-in campaign chain definitions."""
    chains_dir = Path(__file__).parent / "chains"
    campaigns = []
    if chains_dir.exists():
        for chain_file in sorted(chains_dir.glob("*.yaml")):
            campaigns.append(load_campaign(chain_file))
    return campaigns
