"""Data models for multi-stage campaign orchestration.

A campaign is a sequence of stages. Each stage maps to an existing attack
module with optional parameter overrides and gate conditions that determine
whether subsequent stages execute.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from mcp_slayer.models import AttackOutcome, Finding, Severity
from mcp_slayer.taxonomy import PlaybookThreatID


class StageGate(StrEnum):
    """Determines how a stage result controls campaign flow."""

    STOP_ON_BLOCK = "stop_on_block"
    CONTINUE_ALWAYS = "continue_always"
    STOP_ON_VULN = "stop_on_vuln"


class StageDefinition(BaseModel):
    """One step in a campaign chain.

    Each stage references an attack module by ID and optionally overrides
    its settings. The gate controls whether the campaign continues if this
    stage's attack is blocked.
    """

    id: str = Field(..., description="Unique stage identifier within the campaign")
    module: str = Field(..., description="Attack module ID from MODULE_REGISTRY")
    action: str = Field(..., description="Human-readable description of what this stage does")
    taxonomy_ids: list[PlaybookThreatID] = Field(default_factory=list)
    gate: StageGate = StageGate.STOP_ON_BLOCK
    depends_on: list[str] = Field(
        default_factory=list,
        description="Stage IDs that must succeed (VULNERABLE) for this stage to run",
    )
    module_overrides: dict[str, Any] = Field(
        default_factory=dict,
        description="Override module_settings for this stage's module execution",
    )
    inject_from_prior: bool = Field(
        False,
        description="If True, pass prior stage findings as context for this stage",
    )
    timeout_seconds: int | None = Field(
        None, description="Per-stage timeout override"
    )


class CampaignDefinition(BaseModel):
    """A complete campaign definition — loaded from YAML or constructed in code."""

    id: str = Field(..., description="Unique campaign identifier")
    name: str = Field(..., description="Human-readable campaign name")
    description: str = Field(..., description="What this campaign validates")
    stages: list[StageDefinition] = Field(..., min_length=2)
    success_conditions: list[str] = Field(
        default_factory=list,
        description="Narrative criteria for campaign success",
    )
    blue_team_gates: list[str] = Field(
        default_factory=list,
        description="What defenses should catch this chain",
    )
    tags: dict[str, str] = Field(default_factory=dict)

    # ABRS parameters (optional — used if supplied)
    abrs_reachable_agents: int = Field(1, ge=1)
    abrs_avg_tool_scope: float = Field(1.0, ge=1.0, le=5.0)
    abrs_memory_persistence_days: float = Field(0.0, ge=0.0)
    abrs_isolation_boundaries: int = Field(1, ge=1)


class StageResult(BaseModel):
    """Result from executing a single campaign stage."""

    stage_id: str
    module_id: str
    outcome: AttackOutcome
    findings: list[Finding] = Field(default_factory=list)
    blocking_control: str | None = None
    alert_fired: bool = False
    detection_time_ms: int | None = None
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0
    skipped: bool = False
    skip_reason: str | None = None


class ABRSScore(BaseModel):
    """Agentic Blast Radius Score — measures propagation potential."""

    reachable_agents: int
    avg_tool_scope: float
    memory_persistence_days: float
    isolation_boundaries: int
    score: float = 0.0
    risk_level: str = "Contained"

    def compute(self) -> ABRSScore:
        self.score = (
            self.reachable_agents
            * self.avg_tool_scope
            * max(self.memory_persistence_days, 1.0)
        ) / self.isolation_boundaries

        if self.score < 5:
            self.risk_level = "Contained"
        elif self.score < 20:
            self.risk_level = "Elevated"
        elif self.score < 100:
            self.risk_level = "Critical"
        else:
            self.risk_level = "Systemic"

        return self


class CampaignResult(BaseModel):
    """Aggregated result of a full campaign execution."""

    campaign_id: str
    campaign_name: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    stages_total: int = 0
    stages_executed: int = 0
    stages_vulnerable: int = 0
    stages_blocked: int = 0
    stages_skipped: int = 0
    halted_at_stage: str | None = None
    halt_reason: str | None = None
    stage_results: list[StageResult] = Field(default_factory=list)
    all_findings: list[Finding] = Field(default_factory=list)
    max_severity: Severity = Severity.INFO
    abrs: ABRSScore | None = None
    detection_rate: float = 0.0
    duration_ms: int = 0

    def compute_summary(self) -> None:
        """Recompute summary statistics from stage_results."""
        self.stages_total = len(self.stage_results)
        self.stages_executed = sum(1 for s in self.stage_results if not s.skipped)
        self.stages_vulnerable = sum(
            1 for s in self.stage_results
            if s.outcome in (AttackOutcome.VULNERABLE, AttackOutcome.PARTIALLY_VULNERABLE)
        )
        self.stages_blocked = sum(
            1 for s in self.stage_results
            if s.outcome in (AttackOutcome.BLOCKED, AttackOutcome.DETECTED)
        )
        self.stages_skipped = sum(1 for s in self.stage_results if s.skipped)

        all_findings = []
        for sr in self.stage_results:
            all_findings.extend(sr.findings)
        self.all_findings = all_findings

        if all_findings:
            self.max_severity = max(f.severity for f in all_findings)

        detected = sum(1 for s in self.stage_results if s.alert_fired)
        if self.stages_executed > 0:
            self.detection_rate = detected / self.stages_executed
