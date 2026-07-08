"""Mutation operators for payload transformation.

Each mutation transforms a payload string in a way that may bypass
input validation while preserving semantic intent. Mutations are
composable — the engine chains multiple mutations to explore the
space of possible evasion techniques.

These model real-world WAF/blocklist bypass techniques observed in
production MCP deployments and traditional web application security.
"""

from __future__ import annotations

import base64
import random
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable


class MutationStrategy(StrEnum):
    """Mutation intensity presets."""

    LIGHT = "light"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"


@dataclass(frozen=True)
class Mutation:
    """A single mutation applied to a payload."""

    name: str
    description: str
    transform: Callable[[str, random.Random], str]
    weight: float = 1.0


# ── Unicode Mutations ─────────────────────────────────────────────────────────

_HOMOGLYPHS = {
    "a": "\u0430",  # Cyrillic а
    "e": "\u0435",  # Cyrillic е
    "o": "\u043E",  # Cyrillic о
    "p": "\u0440",  # Cyrillic р
    "c": "\u0441",  # Cyrillic с
    "x": "\u0445",  # Cyrillic х
    "i": "\u0456",  # Ukrainian і
    "s": "\u0455",  # Cyrillic ѕ
}


def _unicode_homoglyph(payload: str, rng: random.Random) -> str:
    """Replace 1-3 characters with visually identical unicode homoglyphs."""
    chars = list(payload)
    eligible = [(i, c) for i, c in enumerate(chars) if c.lower() in _HOMOGLYPHS]
    if not eligible:
        return payload
    count = min(rng.randint(1, 3), len(eligible))
    for i, c in rng.sample(eligible, count):
        chars[i] = _HOMOGLYPHS[c.lower()]
    return "".join(chars)


def _zero_width_insert(payload: str, rng: random.Random) -> str:
    """Insert zero-width characters at random positions."""
    zwchars = ["\u200B", "\u200C", "\u200D", "\uFEFF"]
    chars = list(payload)
    count = rng.randint(1, 4)
    for _ in range(count):
        pos = rng.randint(0, len(chars))
        chars.insert(pos, rng.choice(zwchars))
    return "".join(chars)


def _unicode_normalize_bypass(payload: str, rng: random.Random) -> str:
    """Use fullwidth or other Unicode forms that normalize to ASCII."""
    fullwidth_offset = 0xFF01 - 0x21  # Fullwidth ! starts at FF01
    result = []
    for c in payload:
        if 0x21 <= ord(c) <= 0x7E and rng.random() < 0.3:
            result.append(chr(ord(c) + fullwidth_offset))
        else:
            result.append(c)
    return "".join(result)


# ── Encoding Mutations ────────────────────────────────────────────────────────


def _base64_wrap(payload: str, rng: random.Random) -> str:
    """Base64 encode the payload (simulates decoded-at-runtime patterns)."""
    return base64.b64encode(payload.encode()).decode()


def _url_encode(payload: str, rng: random.Random) -> str:
    """URL-encode characters that might trigger pattern matching."""
    return urllib.parse.quote(payload, safe="")


def _double_url_encode(payload: str, rng: random.Random) -> str:
    """Double URL-encode to bypass single-decode filters."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _hex_encode_partial(payload: str, rng: random.Random) -> str:
    """Replace some characters with \\xNN hex escapes."""
    result = []
    for c in payload:
        if rng.random() < 0.25 and c.isalpha():
            result.append(f"\\x{ord(c):02x}")
        else:
            result.append(c)
    return "".join(result)


# ── Case Mutations ────────────────────────────────────────────────────────────


def _case_toggle(payload: str, rng: random.Random) -> str:
    """Randomly toggle case of alphabetic characters."""
    return "".join(
        c.upper() if rng.random() < 0.4 else c.lower() if rng.random() < 0.5 else c
        for c in payload
    )


def _alternating_case(payload: str, rng: random.Random) -> str:
    """Apply aLtErNaTiNg case pattern."""
    return "".join(
        c.upper() if i % 2 == 0 else c.lower()
        for i, c in enumerate(payload)
    )


# ── Whitespace Mutations ──────────────────────────────────────────────────────


def _whitespace_pad(payload: str, rng: random.Random) -> str:
    """Insert extra whitespace around keywords."""
    import re
    keywords = ["ignore", "system", "override", "admin", "output", "print", "echo"]
    for kw in keywords:
        if kw in payload.lower():
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            replacement = f" {kw} "
            payload = pattern.sub(replacement, payload, count=1)
            break
    return payload


def _tab_substitution(payload: str, rng: random.Random) -> str:
    """Replace spaces with tabs or mixed whitespace."""
    alternatives = ["\t", "\t ", " \t", "\x0b", "\x0c"]
    result = []
    for c in payload:
        if c == " " and rng.random() < 0.3:
            result.append(rng.choice(alternatives))
        else:
            result.append(c)
    return "".join(result)


def _newline_inject(payload: str, rng: random.Random) -> str:
    """Insert newlines to split payload across lines."""
    words = payload.split(" ")
    if len(words) < 3:
        return payload
    pos = rng.randint(1, len(words) - 1)
    words.insert(pos, "\n")
    return " ".join(words)


# ── Structural Mutations ──────────────────────────────────────────────────────


def _null_byte_inject(payload: str, rng: random.Random) -> str:
    """Insert null bytes that may truncate processing."""
    pos = rng.randint(0, len(payload))
    return payload[:pos] + "\x00" + payload[pos:]


def _comment_wrap(payload: str, rng: random.Random) -> str:
    """Wrap payload in comment syntax for the target format."""
    wrappers = [
        (f"<!-- {payload} -->", "html"),
        (f"/* {payload} */", "css/js"),
        (f"// {payload}", "line_comment"),
        (f"# {payload}", "hash_comment"),
        (f"{{/* {payload} */}}", "go_template"),
    ]
    wrapped, _ = rng.choice(wrappers)
    return wrapped


def _string_split(payload: str, rng: random.Random) -> str:
    """Split payload into concatenated string fragments."""
    if len(payload) < 6:
        return payload
    pos = rng.randint(2, len(payload) - 2)
    return f'"{payload[:pos]}" + "{payload[pos:]}"'


def _crlf_inject(payload: str, rng: random.Random) -> str:
    """Inject CRLF sequences for header/log injection."""
    pos = rng.randint(0, len(payload))
    return payload[:pos] + "\r\n" + payload[pos:]


# ── Registry ──────────────────────────────────────────────────────────────────

MUTATIONS: list[Mutation] = [
    Mutation("unicode_homoglyph", "Replace chars with visually identical homoglyphs", _unicode_homoglyph, weight=1.5),
    Mutation("zero_width_insert", "Insert invisible zero-width characters", _zero_width_insert, weight=1.2),
    Mutation("unicode_fullwidth", "Use fullwidth Unicode forms", _unicode_normalize_bypass, weight=1.0),
    Mutation("base64_wrap", "Base64 encode the payload", _base64_wrap, weight=0.8),
    Mutation("url_encode", "URL-encode special characters", _url_encode, weight=1.0),
    Mutation("double_url_encode", "Double URL-encode for filter bypass", _double_url_encode, weight=0.7),
    Mutation("hex_partial", "Hex-encode selected characters", _hex_encode_partial, weight=0.9),
    Mutation("case_toggle", "Random case toggling", _case_toggle, weight=1.3),
    Mutation("alternating_case", "aLtErNaTiNg case pattern", _alternating_case, weight=0.8),
    Mutation("whitespace_pad", "Extra whitespace around keywords", _whitespace_pad, weight=1.1),
    Mutation("tab_substitution", "Replace spaces with tabs/mixed", _tab_substitution, weight=1.0),
    Mutation("newline_inject", "Insert newlines to split payload", _newline_inject, weight=0.9),
    Mutation("null_byte", "Insert null byte for truncation", _null_byte_inject, weight=1.4),
    Mutation("comment_wrap", "Wrap in comment syntax", _comment_wrap, weight=0.8),
    Mutation("string_split", "Split into concatenated fragments", _string_split, weight=0.7),
    Mutation("crlf_inject", "Inject CRLF for header/log injection", _crlf_inject, weight=1.2),
]

_STRATEGY_COUNTS = {
    MutationStrategy.LIGHT: (1, 1),
    MutationStrategy.MODERATE: (1, 3),
    MutationStrategy.AGGRESSIVE: (2, 5),
}


def apply_mutations(
    payload: str,
    strategy: MutationStrategy = MutationStrategy.MODERATE,
    seed: int | None = None,
) -> tuple[str, list[str]]:
    """Apply mutations to a payload according to the given strategy.

    Returns the mutated payload and the list of mutation names applied.
    """
    rng = random.Random(seed)
    min_count, max_count = _STRATEGY_COUNTS[strategy]
    count = rng.randint(min_count, max_count)

    # Weighted selection
    weights = [m.weight for m in MUTATIONS]
    selected = rng.choices(MUTATIONS, weights=weights, k=count)

    applied_names = []
    result = payload
    for mutation in selected:
        result = mutation.transform(result, rng)
        applied_names.append(mutation.name)

    return result, applied_names
