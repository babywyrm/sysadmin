"""Shared utility functions for sanitization, redaction, and formatting."""

from __future__ import annotations

from typing import Any


def deep_redact(data: dict[str, Any], patterns: list[str]) -> dict[str, Any]:
    """Recursively redact sensitive keys from nested dicts.

    Args:
        data: Dictionary to sanitize.
        patterns: List of key substrings to redact (case-insensitive).

    Returns:
        Deep copy with redacted values.
    """
    if not isinstance(data, dict):
        return data

    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if any(pattern.lower() in key.lower() for pattern in patterns):
            redacted[key] = "[REDACTED]"
        elif isinstance(value, dict):
            redacted[key] = deep_redact(value, patterns)
        elif isinstance(value, list):
            redacted[key] = [
                deep_redact(item, patterns) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            redacted[key] = value
    return redacted
