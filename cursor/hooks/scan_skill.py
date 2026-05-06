#!/usr/bin/env python3
"""
scan-skill.sh (runs as python3)
Scans SKILL.md and other skill/plugin markdown files for suspicious
patterns before the agent reads them.

Fires on: beforeReadFile
Returns:  ask  if red flags found (shows user what was flagged)
          allow if clean
"""

import sys
import json
import re
import os


def load_input():
    try:
        return json.load(sys.stdin)
    except Exception:
        return {}


def strip_code_blocks(content):
    """Remove fenced code blocks — patterns inside them are teaching examples, not instructions."""
    content = re.sub(r'```[\s\S]*?```', '[CODE_BLOCK]', content)
    content = re.sub(r'`[^`\n]+`', '[INLINE_CODE]', content)
    return content


def scan_file(path):
    try:
        with open(path, "r", errors="replace") as f:
            raw = f.read()
    except Exception as e:
        return [], f"could not read file: {e}"

    prose = strip_code_blocks(raw)
    flags = []

    net_patterns = [
        (prose, r'\b(run|execute|call|invoke)\b.{0,60}\b(curl|wget|requests\.get)\b',
         "instruction to run network fetch"),
        (prose, r'https?://(?!modelcontextprotocol\.io|spec\.modelcontextprotocol|github\.com/babywyrm|shields\.io|img\.shields|TARGET|localhost|127\.0\.0\.1|<)',
         "external URL in prose (non-trusted, non-placeholder)"),
    ]

    stealth_patterns = [
        (prose, r"don['\u2019]?t\s+(tell|inform|mention|show|reveal|disclose)\s+the\s+user",
         "instruction to hide from user"),
        (prose, r"\b(silently|covertly|secretly|without\s+notif\w+|without\s+telling\s+the\s+user)\b",
         "instruction to act covertly"),
        (prose, r"\b(exfiltrat\w+|steal\s+\w+|harvest\s+(token|cred|secret|key|password))\b",
         "exfiltration instruction in prose"),
    ]

    injection_patterns = [
        (prose, r"(?i)ignore\s+(previous|prior|above|all)\s+instructions",
         "prompt injection: ignore instructions"),
        (prose, r"(?i)you\s+are\s+now\s+(?!a\s+(?:skill|hook|rule|tool)\b)",
         "prompt injection: persona override"),
        (prose, r"(?i)(system\s*:\s*(you\s+are|override|act\s+as))",
         "prompt injection: system role claim"),
        (prose, r"(?i)\bnew\s+(system\s+)?instruction\b(?!\s+example|\s+format|\s+set|\s+type)",
         "prompt injection: new instruction directive"),
    ]

    obfuscation_patterns = [
        (raw, r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])',
         "long base64-like blob (possible obfuscation)"),
    ]

    all_groups = net_patterns + stealth_patterns + injection_patterns + obfuscation_patterns

    for text, pattern, label in all_groups:
        matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
        if matches:
            unique = list(dict.fromkeys(str(m)[:80] for m in matches))[:3]
            flags.append(f"  [{label}]: {', '.join(repr(u) for u in unique)}")

    return flags, raw


def is_skill_file(path):
    if not path:
        return False
    skill_dirs = [
        ".cursor/skills",
        ".cursor/plugins",
        ".cursor/hooks",
        ".cursor/rules",
    ]
    normalized = path.replace("\\", "/")
    for d in skill_dirs:
        if d in normalized:
            return True
    basename = os.path.basename(normalized)
    if basename.upper() in ("SKILL.MD", "RULE.MD", "AGENTS.MD"):
        return True
    return False


def main():
    data = load_input()
    path = (data.get("path") or data.get("file_path") or
            data.get("filePath") or "")

    if not is_skill_file(path):
        print(json.dumps({"permission": "allow"}))
        return

    flags, _ = scan_file(path)

    if not flags:
        print(json.dumps({"permission": "allow"}))
        return

    flag_text = "\n".join(flags)
    parts = path.replace("\\", "/").split("/")
    short_path = "/".join(parts[-2:]) if len(parts) >= 2 else path

    user_msg = (
        f"⚠️  Security scan flagged `{short_path}` before the agent reads it.\n\n"
        f"**Flags found ({len(flags)}):**\n{flag_text}\n\n"
        "Review the raw file before proceeding. "
        "Allow only if you trust the source and have read it yourself."
    )
    agent_msg = (
        f"scan-skill hook flagged {short_path} with {len(flags)} pattern(s). "
        "Paused for user review."
    )

    print(json.dumps({
        "permission": "ask",
        "user_message": user_msg,
        "agent_message": agent_msg,
    }))


if __name__ == "__main__":
    main()
