"""Canary deployment and monitoring for MCP environments.

Plants unique, trackable tokens into MCP tool contexts (RAG corpora,
agent memories, tool schemas, config files) and monitors for their
appearance in unexpected locations — proving exfiltration, leakage,
or cross-boundary violation occurred.

Canaries are the purple team's tripwire: when a canary surfaces where
it shouldn't, something has gone wrong regardless of whether the SIEM
caught it.

Usage:
    deployer = CanaryDeployer(ctx)
    canary = deployer.plant(target="rag-corpus", location="/docs/internal-policy.md")
    # ... time passes ...
    monitor = CanaryMonitor(ctx, deployed_canaries=[canary])
    alerts = await monitor.check()
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Callable


class CanaryType(StrEnum):
    """Where a canary is planted."""

    RAG_CORPUS = "rag_corpus"
    AGENT_MEMORY = "agent_memory"
    TOOL_SCHEMA = "tool_schema"
    CONFIG_FILE = "config_file"
    CREDENTIAL = "credential"
    DOCUMENT = "document"


class CanaryStatus(StrEnum):
    """Current state of a deployed canary."""

    ACTIVE = "active"
    TRIGGERED = "triggered"
    EXPIRED = "expired"
    DISABLED = "disabled"


@dataclass
class DeployedCanary:
    """A canary token planted in the environment."""

    id: str
    token: str
    canary_type: CanaryType
    location: str
    planted_at: datetime
    expires_at: datetime | None = None
    status: CanaryStatus = CanaryStatus.ACTIVE
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        if self.status != CanaryStatus.ACTIVE:
            return False
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return False
        return True

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.token.encode()).hexdigest()[:16]


@dataclass
class CanaryAlert:
    """Alert generated when a canary is detected in an unexpected location."""

    canary_id: str
    canary_token: str
    detected_at: datetime
    detected_in: str
    context: str = ""
    severity: str = "HIGH"
    violation_type: str = ""

    @property
    def time_to_trigger_s(self) -> float | None:
        return None  # Computed externally from canary.planted_at


class CanaryDeployer:
    """Plants canary tokens into MCP environment surfaces.

    Each canary is a unique, non-guessable string designed to be
    detectable if it appears outside its intended scope.
    """

    TOKEN_PREFIX = "MCPCANARY"

    def __init__(self, namespace: str = "default"):
        self.namespace = namespace
        self.logger = logging.getLogger("slayer.canary.deployer")
        self._deployed: list[DeployedCanary] = []

    def generate_token(self) -> str:
        """Generate a unique canary token."""
        rand = secrets.token_hex(8)
        return f"{self.TOKEN_PREFIX}-{self.namespace}-{rand}"

    def plant(
        self,
        canary_type: CanaryType,
        location: str,
        description: str = "",
        ttl_hours: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DeployedCanary:
        """Create and register a new canary deployment."""
        token = self.generate_token()
        now = datetime.now(UTC)

        canary = DeployedCanary(
            id=f"canary-{secrets.token_hex(4)}",
            token=token,
            canary_type=canary_type,
            location=location,
            planted_at=now,
            expires_at=datetime.fromtimestamp(
                now.timestamp() + (ttl_hours * 3600), tz=UTC
            ) if ttl_hours else None,
            description=description or f"{canary_type.value} canary at {location}",
            metadata=metadata or {},
        )

        self._deployed.append(canary)
        self.logger.info(
            f"Planted canary [{canary.id}] type={canary_type.value} "
            f"location={location} token={token[:20]}..."
        )
        return canary

    def plant_suite(self) -> list[DeployedCanary]:
        """Plant a standard suite of canaries across common surfaces."""
        canaries = [
            self.plant(
                CanaryType.RAG_CORPUS,
                "/internal/policies/access-control.md",
                "Embedded in internal policy document body",
            ),
            self.plant(
                CanaryType.AGENT_MEMORY,
                "session_context.system_prompt",
                "Injected into agent system prompt as compliance marker",
            ),
            self.plant(
                CanaryType.CREDENTIAL,
                "vault://mcp-service/api-key",
                "Fake API key in credential store",
            ),
            self.plant(
                CanaryType.TOOL_SCHEMA,
                "tools/internal-admin/description",
                "Hidden in tool description metadata field",
            ),
            self.plant(
                CanaryType.DOCUMENT,
                "/shared/engineering/runbooks/oncall.md",
                "Invisible marker in engineering runbook",
            ),
            self.plant(
                CanaryType.CONFIG_FILE,
                ".env.production",
                "Fake credential in production env file",
            ),
        ]
        return canaries

    @property
    def deployed(self) -> list[DeployedCanary]:
        return self._deployed

    @property
    def active_canaries(self) -> list[DeployedCanary]:
        return [c for c in self._deployed if c.is_active]


class CanaryMonitor:
    """Monitors for canary token appearances in unexpected locations.

    Uses a pluggable check_function to scan target surfaces for canary
    tokens. When found, generates alerts with full context.
    """

    def __init__(
        self,
        canaries: list[DeployedCanary],
        check_functions: list[Callable[[str], list[dict[str, str]]]] | None = None,
    ):
        self.canaries = canaries
        self.check_functions = check_functions or []
        self.logger = logging.getLogger("slayer.canary.monitor")
        self._alerts: list[CanaryAlert] = []

    async def check(self) -> list[CanaryAlert]:
        """Run all check functions against active canaries."""
        new_alerts = []

        for canary in self.canaries:
            if not canary.is_active:
                continue

            for check_fn in self.check_functions:
                try:
                    hits = check_fn(canary.token)
                except Exception as e:
                    self.logger.error(f"Check function error for {canary.id}: {e}")
                    continue

                for hit in hits:
                    alert = CanaryAlert(
                        canary_id=canary.id,
                        canary_token=canary.token,
                        detected_at=datetime.now(UTC),
                        detected_in=hit.get("location", "unknown"),
                        context=hit.get("context", ""),
                        severity=hit.get("severity", "HIGH"),
                        violation_type=hit.get("type", "exfiltration"),
                    )
                    new_alerts.append(alert)
                    canary.status = CanaryStatus.TRIGGERED
                    self.logger.warning(
                        f"CANARY TRIGGERED [{canary.id}] detected in "
                        f"{alert.detected_in} — {alert.violation_type}"
                    )

        self._alerts.extend(new_alerts)
        return new_alerts

    @property
    def alerts(self) -> list[CanaryAlert]:
        return self._alerts

    def summary(self) -> dict[str, Any]:
        """Summarize canary monitoring state."""
        active = sum(1 for c in self.canaries if c.is_active)
        triggered = sum(1 for c in self.canaries if c.status == CanaryStatus.TRIGGERED)
        return {
            "total_canaries": len(self.canaries),
            "active": active,
            "triggered": triggered,
            "total_alerts": len(self._alerts),
            "by_type": {
                ct.value: sum(1 for c in self.canaries if c.canary_type == ct and c.status == CanaryStatus.TRIGGERED)
                for ct in CanaryType
            },
        }
