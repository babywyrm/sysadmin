"""Property test engine — composes generators and mutations into test runs.

The engine generates payloads, applies mutations, executes them against
a target function, and tracks which combinations bypass defenses. When a
bypass is found, the engine attempts to shrink the payload to its minimal
effective form for actionable reporting.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from mcp_slayer.payloads.generators import GeneratedPayload, PayloadGenerator
from mcp_slayer.payloads.mutations import (
    MutationStrategy,
    apply_mutations,
)


@dataclass
class PropertyTestResult:
    """Result of a single payload test."""

    payload: GeneratedPayload
    mutated_value: str
    mutations_applied: list[str]
    bypassed: bool
    response_snippet: str = ""
    canary_found: bool = False
    shrunk_payload: str | None = None


@dataclass
class PropertyTestReport:
    """Aggregate report from a property test run."""

    generator_id: str
    strategy: MutationStrategy
    total_payloads: int = 0
    total_bypasses: int = 0
    bypass_rate: float = 0.0
    results: list[PropertyTestResult] = field(default_factory=list)
    duration_ms: int = 0
    unique_mutation_bypasses: dict[str, int] = field(default_factory=dict)

    def compute(self) -> None:
        self.total_payloads = len(self.results)
        self.total_bypasses = sum(1 for r in self.results if r.bypassed)
        if self.total_payloads > 0:
            self.bypass_rate = self.total_bypasses / self.total_payloads

        # Track which mutations appear most in successful bypasses
        mutation_counts: dict[str, int] = {}
        for r in self.results:
            if r.bypassed:
                for m in r.mutations_applied:
                    mutation_counts[m] = mutation_counts.get(m, 0) + 1
        self.unique_mutation_bypasses = dict(
            sorted(mutation_counts.items(), key=lambda x: x[1], reverse=True)
        )


class PropertyTestEngine:
    """Orchestrates property-based payload testing.

    Usage:
        engine = PropertyTestEngine(
            generator=InjectionPayloadGenerator(seed=42),
            oracle=my_test_function,
            strategy=MutationStrategy.MODERATE,
        )
        report = engine.run(count=200)

    The oracle function receives a payload string and returns True if
    the payload bypassed defenses (vulnerability found), False otherwise.
    """

    def __init__(
        self,
        generator: PayloadGenerator,
        oracle: Callable[[str], bool],
        strategy: MutationStrategy = MutationStrategy.MODERATE,
        canary_checker: Callable[[str, str], bool] | None = None,
        seed: int | None = None,
        max_shrink_rounds: int = 10,
    ):
        self.generator = generator
        self.oracle = oracle
        self.strategy = strategy
        self.canary_checker = canary_checker
        self.seed = seed
        self.max_shrink_rounds = max_shrink_rounds
        self.logger = logging.getLogger("slayer.property_test")

    def run(self, count: int = 100) -> PropertyTestReport:
        """Generate and test `count` payloads, returning the report."""
        start = time.monotonic()
        report = PropertyTestReport(
            generator_id=self.generator.generator_id,
            strategy=self.strategy,
        )

        payloads = self.generator.generate(count=count)

        for i, payload in enumerate(payloads):
            # Apply mutations
            seed_for_mutation = (self.seed or 0) + i
            mutated, mutations = apply_mutations(
                payload.value, self.strategy, seed=seed_for_mutation
            )

            # Test against oracle
            try:
                bypassed = self.oracle(mutated)
            except Exception as e:
                self.logger.debug(f"Oracle error on payload {i}: {e}")
                bypassed = False

            # Check canary if checker provided
            canary_found = False
            if self.canary_checker and bypassed:
                canary_found = self.canary_checker(mutated, payload.canary)

            # Shrink if bypass found
            shrunk = None
            if bypassed and len(mutated) > 10:
                shrunk = self._shrink(mutated)

            result = PropertyTestResult(
                payload=payload,
                mutated_value=mutated,
                mutations_applied=mutations,
                bypassed=bypassed,
                canary_found=canary_found,
                shrunk_payload=shrunk,
            )
            report.results.append(result)

        report.duration_ms = int((time.monotonic() - start) * 1000)
        report.compute()

        self.logger.info(
            f"PropertyTest[{self.generator.generator_id}]: "
            f"{report.total_bypasses}/{report.total_payloads} bypasses "
            f"({report.bypass_rate:.1%}) in {report.duration_ms}ms"
        )

        return report

    def _shrink(self, payload: str) -> str | None:
        """Attempt to reduce a bypassing payload to its minimal form.

        Uses binary reduction: repeatedly halve the payload and test
        whether the shorter version still bypasses. Returns the smallest
        version that still triggers the oracle.
        """
        minimal = payload
        for _ in range(self.max_shrink_rounds):
            if len(minimal) <= 5:
                break

            # Try removing the first half
            mid = len(minimal) // 2
            candidate = minimal[mid:]
            if self._safe_oracle(candidate):
                minimal = candidate
                continue

            # Try removing the second half
            candidate = minimal[:mid]
            if self._safe_oracle(candidate):
                minimal = candidate
                continue

            # Try removing middle quarter
            q1 = len(minimal) // 4
            q3 = 3 * len(minimal) // 4
            candidate = minimal[:q1] + minimal[q3:]
            if self._safe_oracle(candidate):
                minimal = candidate
                continue

            break

        if minimal != payload and len(minimal) < len(payload):
            return minimal
        return None

    def _safe_oracle(self, payload: str) -> bool:
        try:
            return self.oracle(payload)
        except Exception:
            return False


def run_property_suite(
    generators: list[PayloadGenerator],
    oracle: Callable[[str], bool],
    count_per_generator: int = 100,
    strategy: MutationStrategy = MutationStrategy.MODERATE,
    seed: int | None = None,
) -> list[PropertyTestReport]:
    """Convenience function to run property tests across multiple generators."""
    reports = []
    for gen in generators:
        engine = PropertyTestEngine(
            generator=gen,
            oracle=oracle,
            strategy=strategy,
            seed=seed,
        )
        report = engine.run(count=count_per_generator)
        reports.append(report)
    return reports
