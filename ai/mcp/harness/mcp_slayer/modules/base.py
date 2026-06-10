"""Abstract base class for attack modules."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ClassVar

from mcp_slayer.exceptions import SlayerKillSwitchError
from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.taxonomy import PlaybookThreatID
from mcp_slayer.utils import deep_redact

if TYPE_CHECKING:
    from mcp_slayer.engine import SlayerContext


class AttackModule(ABC):
    """Base class for all attack modules.

    Subclasses declare their identity via class variables and implement
    `run()` to execute attack scenarios.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    owasp_category: ClassVar[AttackCategory]
    playbook_threats: ClassVar[list[PlaybookThreatID]]
    description: ClassVar[str]
    severity_range: ClassVar[tuple[Severity, Severity]]

    def __init__(self, ctx: SlayerContext):
        self.ctx = ctx
        self.logger = logging.getLogger(f"slayer.{self.id}")
        self._rate_limiter = asyncio.Semaphore(ctx.config.max_concurrent_attacks)

    @abstractmethod
    async def run(self) -> list[Finding]:
        """Execute attack scenarios and return findings."""
        ...

    async def _execute_with_safeguards(
        self, attack_func: Callable, *args: Any, **kwargs: Any
    ) -> Any:
        """Execute attack function with rate limiting, timeout, and kill switch."""
        async with self._rate_limiter:
            if self.ctx.kill_switch_active:
                raise SlayerKillSwitchError(
                    f"Safe word '{self.ctx.config.safe_word}' detected"
                )
            try:
                return await asyncio.wait_for(
                    attack_func(*args, **kwargs),
                    timeout=self.ctx.config.timeout_seconds,
                )
            except TimeoutError:
                self.logger.error(
                    f"Attack timed out after {self.ctx.config.timeout_seconds}s"
                )
                raise

    def _create_finding(
        self,
        title: str,
        severity: Severity,
        target_url: str,
        outcome: AttackOutcome,
        **kwargs: Any,
    ) -> Finding:
        """Helper to create a finding with module defaults pre-filled."""
        evidence = kwargs.pop("evidence", {})
        sanitized_evidence = deep_redact(
            evidence, self.ctx.config.redaction.json_keys
        )

        return Finding(
            owasp_category=self.owasp_category,
            playbook_threat_ids=list(self.playbook_threats),
            title=title,
            severity=severity,
            target_url=target_url,
            attack_module=self.id,
            outcome=outcome,
            evidence=sanitized_evidence,
            **kwargs,
        )
