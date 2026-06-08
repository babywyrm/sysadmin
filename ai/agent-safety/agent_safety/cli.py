from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_safety.adapters.codex import codex_preflight
from agent_safety.adapters.cursor import (
    cursor_before_agent,
    cursor_before_read,
    cursor_before_tool,
)
from agent_safety.models import Finding, ScanResult
from agent_safety.policies import load_policy
from agent_safety.scanners.control_files import is_control_file, scan_control_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-safety")
    parser.add_argument("--policy", help="Path to a JSON policy file.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_file_parser = subparsers.add_parser("scan-file")
    scan_file_parser.add_argument("path")
    scan_file_parser.add_argument("--format", choices=("text", "json", "jsonl"), default="text")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path")
    scan_parser.add_argument("--format", choices=("text", "json", "jsonl"), default="text")

    hook_parser = subparsers.add_parser("hook")
    hook_parser.add_argument(
        "hook_name",
        choices=(
            "cursor-before-read",
            "cursor-before-tool",
            "cursor-before-agent",
            "codex-preflight",
        ),
    )

    args = parser.parse_args(argv)
    policy = load_policy(args.policy)

    if args.command == "scan-file":
        result = _scan_file_path(Path(args.path))
    elif args.command == "scan":
        result = _scan_tree(Path(args.path))
    elif args.command == "hook":
        payload = _load_stdin_json()
        response = _run_hook(args.hook_name, payload)
        print(json.dumps(response, sort_keys=True))
        return 0
    else:
        parser.error(f"unsupported command: {args.command}")

    _emit_result(result, args.format)
    return 1 if result.has_findings_at_or_above(policy.severity_threshold) else 0


def _scan_file_path(path: Path) -> ScanResult:
    if not is_control_file(path):
        return ScanResult()
    return scan_control_file(path)


def _scan_tree(path: Path) -> ScanResult:
    if path.is_file():
        return _scan_file_path(path)

    findings: list[Finding] = []
    errors: list[str] = []
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file() or not is_control_file(candidate):
            continue
        result = scan_control_file(candidate)
        findings.extend(result.findings)
        errors.extend(result.errors)
    return ScanResult(findings=findings, errors=errors)


def _emit_result(result: ScanResult, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result.to_dict(), sort_keys=True))
        return
    if output_format == "jsonl":
        for finding in result.findings:
            print(json.dumps(finding.to_dict(), sort_keys=True))
        return
    for finding in result.findings:
        payload = finding.to_dict()
        path = payload.get("path") or "<stdin>"
        line = payload.get("line") or 1
        print(
            f"{payload['severity'].upper()} {payload['rule_id']} "
            f"{path}:{line} {payload['snippet']}",
            file=sys.stdout,
        )


def _load_stdin_json() -> dict[str, object]:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _run_hook(hook_name: str, payload: dict[str, object]) -> dict[str, object]:
    if hook_name == "cursor-before-read":
        return cursor_before_read(payload)
    if hook_name == "cursor-before-tool":
        return cursor_before_tool(payload)
    if hook_name == "cursor-before-agent":
        return cursor_before_agent(payload)
    if hook_name == "codex-preflight":
        return codex_preflight(payload)
    raise ValueError(f"unsupported hook: {hook_name}")
