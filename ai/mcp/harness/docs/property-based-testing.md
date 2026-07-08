# Property-Based Payload Generation

> Static payload lists find known bypasses. Property-based generation finds
> unknown ones by exploring the combinatorial space of evasion techniques.

## Overview

Instead of maintaining handcrafted lists of attack strings, the property-based
testing system **generates payloads dynamically** through grammar-based
construction and mutation operators. This approach:

- Finds encoding tricks that static lists miss
- Discovers Unicode normalization gaps
- Identifies whitespace and structural bypasses
- Produces minimal reproduction cases via shrinking
- Tracks which mutation strategies are most effective

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Generators                             │
│  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐          │
│  │  Injection   │ │  Command    │ │   Exfil      │          │
│  │  (authority, │ │  (perl,ruby,│ │   (dns,http, │          │
│  │  override,   │ │  lua,awk,   │ │   stego)     │          │
│  │  hijack)     │ │  encoding)  │ │              │          │
│  └─────────────┘ └─────────────┘ └──────────────┘          │
│  ┌─────────────┐ ┌─────────────┐                            │
│  │   Token      │ │   Schema    │                            │
│  │  (alg:none,  │ │  (desc,hint,│                            │
│  │  audience,   │ │  default,   │                            │
│  │  claim)      │ │  examples)  │                            │
│  └─────────────┘ └─────────────┘                            │
└─────────────────────────────────────────────────────────────┘
         │ GeneratedPayload (value + canary + metadata)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Mutation Operators (16)                     │
│                                                               │
│  Unicode: homoglyph · zero-width · fullwidth                 │
│  Encoding: base64 · url · double-url · hex                   │
│  Case: toggle · alternating                                   │
│  Whitespace: padding · tabs · newlines                       │
│  Structural: null-byte · comment-wrap · string-split · crlf │
│                                                               │
│  Strategy: LIGHT (1) · MODERATE (1-3) · AGGRESSIVE (2-5)     │
└─────────────────────────────────────────────────────────────┘
         │ mutated payload
         ▼
┌─────────────────────────────────────────────────────────────┐
│                   PropertyTestEngine                          │
│  • Compose generator → mutations → oracle                    │
│  • Track bypass rate and effective mutations                  │
│  • Shrink bypassing payloads to minimal form                 │
│  • Deterministic with seed for reproducibility               │
└─────────────────────────────────────────────────────────────┘
         │ PropertyTestReport
         ▼
┌─────────────────────────────────────────────────────────────┐
│  • bypass_rate: what % of generated payloads evaded          │
│  • unique_mutation_bypasses: which mutations work best       │
│  • shrunk_payload: minimal reproduction for each bypass      │
│  • duration_ms: performance tracking                         │
└─────────────────────────────────────────────────────────────┘
```

## Usage

### Basic: Test a WAF/filter function

```python
from mcp_slayer.payloads import (
    InjectionPayloadGenerator,
    MutationStrategy,
    PropertyTestEngine,
)

def my_filter(payload: str) -> bool:
    \"\"\"Returns True if payload bypasses the filter.\"\"\"
    blocked_keywords = ["ignore", "override", "system"]
    return not any(kw in payload.lower() for kw in blocked_keywords)

engine = PropertyTestEngine(
    generator=InjectionPayloadGenerator(seed=42),
    oracle=my_filter,
    strategy=MutationStrategy.AGGRESSIVE,
    seed=1,
)

report = engine.run(count=500)
print(f"Bypass rate: {report.bypass_rate:.1%}")
print(f"Most effective mutations: {report.unique_mutation_bypasses}")
```

### Multi-generator suite

```python
from mcp_slayer.payloads import run_property_suite
from mcp_slayer.payloads.generators import (
    InjectionPayloadGenerator,
    CommandPayloadGenerator,
    SchemaPayloadGenerator,
)

reports = run_property_suite(
    generators=[
        InjectionPayloadGenerator(seed=1),
        CommandPayloadGenerator(seed=2),
        SchemaPayloadGenerator(seed=3),
    ],
    oracle=my_target_function,
    count_per_generator=200,
    strategy=MutationStrategy.MODERATE,
)

for r in reports:
    print(f"{r.generator_id}: {r.bypass_rate:.1%} bypass rate")
```

### Deterministic reproduction

All generators and mutations accept a `seed` parameter. When a bypass is
found, record the seed to reproduce the exact same payload generation
sequence for debugging and regression testing.

## Generators

| Generator | Attack Class | Templates | Output |
|---|---|---|---|
| `InjectionPayloadGenerator` | Prompt injection | Authority frames, instruction overrides, output directives, wrappers | Injection strings with embedded canary |
| `CommandPayloadGenerator` | Command injection | 10 interpreters, 9 shell chains, 4 encoding wrappers | Exec payloads with canary output |
| `ExfilPayloadGenerator` | Data exfiltration | DNS subdomain, HTTP callback | Exfil URLs with encoded canary |
| `TokenPayloadGenerator` | Token manipulation | alg:none, audience bypass, claim injection, empty sig | Malformed JWTs with canary in claims |
| `SchemaPayloadGenerator` | Schema poisoning | description, title, examples, x-agent-hint, default | Hidden instructions in schema fields |

## Mutation Operators

| Category | Mutation | What it does |
|---|---|---|
| Unicode | `unicode_homoglyph` | Replace chars with visually identical Cyrillic/Ukrainian homoglyphs |
| Unicode | `zero_width_insert` | Insert invisible ZWJ/ZWNJ/ZWSP characters |
| Unicode | `unicode_fullwidth` | Use fullwidth forms (Ｉｇｎｏｒｅ) |
| Encoding | `base64_wrap` | Base64 encode the payload |
| Encoding | `url_encode` | URL-encode special characters |
| Encoding | `double_url_encode` | Double encode for single-decode filters |
| Encoding | `hex_partial` | Replace chars with \xNN sequences |
| Case | `case_toggle` | Random case variation |
| Case | `alternating_case` | aLtErNaTiNg pattern |
| Whitespace | `whitespace_pad` | Extra spaces around keywords |
| Whitespace | `tab_substitution` | Replace spaces with tabs/mixed |
| Whitespace | `newline_inject` | Split payload across lines |
| Structural | `null_byte` | Insert \x00 for truncation |
| Structural | `comment_wrap` | Wrap in HTML/JS/hash comments |
| Structural | `string_split` | Split into concatenated fragments |
| Structural | `crlf_inject` | Header/log injection via CRLF |

## Shrinking

When a bypass is found, the engine automatically attempts to **shrink** the
payload to its minimal effective form. This produces actionable findings:
instead of reporting a 200-character payload, you get the 15-character
core that actually triggers the bypass.

Shrinking uses binary reduction — repeatedly halving the payload and testing
whether the shorter version still bypasses. The result is a minimal
reproduction case suitable for unit tests and detection rule development.

## Integration with Modules

Existing modules use static `INJECTION_PAYLOADS` and `_BYPASS_PROBES` lists.
The property-based system complements these:

1. **Static payloads**: Known-good, fast, deterministic regression tests
2. **Property-based**: Exploratory, finds novel bypasses, runs on demand

Modules can optionally accept payloads from a generator by checking for an
`injected_payloads` attribute (similar to `injected_context` in campaigns).

## Performance

The system is designed for speed:
- 500 payloads generated + mutated + tested in < 50ms (typical)
- Deterministic with seed — no flaky CI failures
- Shrinking adds < 10 oracle calls per bypass found
