"""Core domain models, enums, and evidence containers."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator

from mcp_slayer.taxonomy import PlaybookThreatID


class Severity(StrEnum):
    """CVSS-aligned severity classification."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: Severity) -> bool:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value) < order.index(other.value)

    @property
    def cvss_range(self) -> tuple[float, float]:
        ranges = {
            "INFO": (0.0, 0.0),
            "LOW": (0.1, 3.9),
            "MEDIUM": (4.0, 6.9),
            "HIGH": (7.0, 8.9),
            "CRITICAL": (9.0, 10.0),
        }
        return ranges[self.value]


class AttackCategory(StrEnum):
    """OWASP MCP Top 10 risk categories."""

    TOKEN_MISMANAGEMENT = "MCP01"
    PRIVILEGE_ESCALATION = "MCP02"
    TOOL_POISONING = "MCP03"
    SUPPLY_CHAIN = "MCP04"
    COMMAND_INJECTION = "MCP05"
    PROMPT_INJECTION = "MCP06"
    INSUFFICIENT_AUTH = "MCP07"
    LACK_OF_AUDIT = "MCP08"
    SHADOW_SERVERS = "MCP09"
    CONTEXT_LEAKAGE = "MCP10"


class AttackOutcome(StrEnum):
    """Structured attack result classification."""

    VULNERABLE = "VULNERABLE"
    PARTIALLY_VULNERABLE = "PARTIALLY_VULNERABLE"
    BLOCKED = "BLOCKED"
    DETECTED = "DETECTED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class Evidence:
    """Immutable evidence container with integrity hash."""

    raw_data: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = field(default="unknown")
    _hash: str = field(init=False, repr=False)

    def __post_init__(self):
        data_bytes = json.dumps(self.raw_data, sort_keys=True).encode()
        object.__setattr__(self, "_hash", hashlib.sha256(data_bytes).hexdigest())

    @property
    def hash(self) -> str:
        return self._hash

    def sanitize(self, redact_patterns: list[str]) -> dict[str, Any]:
        from mcp_slayer.utils import deep_redact

        return deep_redact(self.raw_data, redact_patterns)


class Finding(BaseModel):
    """Structured security finding with OWASP MCP and playbook taxonomy mapping."""

    id: str = Field(default_factory=lambda: f"MCP-{uuid.uuid4().hex[:8]}")
    owasp_category: AttackCategory
    playbook_threat_ids: list[PlaybookThreatID] = Field(default_factory=list)
    title: str = Field(..., min_length=10, max_length=200)
    severity: Severity

    target_url: HttpUrl
    target_tool: str | None = None
    target_agent: str | None = None

    attack_module: str
    attack_variant: str = ""
    outcome: AttackOutcome
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)

    evidence: dict[str, Any] = Field(default_factory=dict)
    request_sample: str | None = None
    response_sample: str | None = None

    description: str = Field(..., min_length=50)
    impact: str = Field(..., min_length=20)
    recommendation: str = Field(..., min_length=30)
    reproduction_steps: list[str] = Field(default_factory=list)

    blue_team_signal: str | None = None
    detection_rule_id: str | None = None
    alert_fired: bool = False
    time_to_detect_ms: int | None = None

    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    tags: dict[str, str] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)

    signature: str | None = Field(None, exclude=True)

    @field_validator("cvss_score")
    @classmethod
    def validate_cvss_matches_severity(
        cls, v: float | None, info
    ) -> float | None:
        if v is None:
            return None
        severity = info.data.get("severity")
        if severity:
            min_score, max_score = severity.cvss_range
            if not (min_score <= v <= max_score):
                raise ValueError(
                    f"CVSS {v} outside range {min_score}-{max_score} for {severity}"
                )
        return v

    def sign(self, private_key) -> None:
        """Sign finding with Ed25519 private key for chain-of-custody."""
        canonical = json.dumps(
            self.model_dump(exclude={"signature"}), sort_keys=True, default=str
        ).encode()
        sig = private_key.sign(canonical)
        self.signature = base64.b64encode(sig).decode()

    def verify(self, public_key) -> bool:
        """Verify finding signature."""
        if not self.signature:
            return False
        canonical = json.dumps(
            self.model_dump(exclude={"signature"}), sort_keys=True, default=str
        ).encode()
        sig_bytes = base64.b64decode(self.signature)
        try:
            public_key.verify(sig_bytes, canonical)
            return True
        except Exception:
            return False
