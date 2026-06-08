from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Policy:
    severity_threshold: str = "medium"
    max_file_bytes: int = 1048576
    max_findings: int = 25


def _policy_from_dict(data: dict[str, Any]) -> Policy:
    return Policy(
        severity_threshold=str(data.get("severity_threshold", "medium")),
        max_file_bytes=int(data.get("max_file_bytes", 1048576)),
        max_findings=int(data.get("max_findings", 25)),
    )


def load_policy(path: str | None = None) -> Policy:
    if path is None:
        return Policy()
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("policy must be a JSON object")
    return _policy_from_dict(payload)
