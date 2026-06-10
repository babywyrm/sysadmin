"""Taxonomy bridge between playbook threat IDs (MCP-T01–T14) and OWASP categories.

The red team playbook defines threats MCP-T01 through MCP-T14.
The harness uses OWASP MCP Top 10 categories MCP01 through MCP10.
This module provides the canonical bidirectional mapping and metadata.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class PlaybookThreatID(StrEnum):
    """Red team playbook threat taxonomy (MCP-T01 through MCP-T14)."""

    PROMPT_INJECTION_DIRECT = "MCP-T01"
    PROMPT_INJECTION_INDIRECT = "MCP-T02"
    CONFUSED_DEPUTY = "MCP-T03"
    TOKEN_AUDIENCE_BYPASS = "MCP-T04"
    CROSS_TOOL_CONTEXT_POISONING = "MCP-T05"
    SSRF_VIA_TOOL = "MCP-T06"
    SECRETS_IN_TOOL_OUTPUT = "MCP-T07"
    SUPPLY_CHAIN_VIA_CONTENT = "MCP-T08"
    AGENT_CONFIG_TAMPERING = "MCP-T09"
    HALLUCINATION_DRIVEN_DESTRUCTION = "MCP-T10"
    CROSS_TENANT_MEMORY_LEAK = "MCP-T11"
    EXFILTRATION_VIA_CHAINING = "MCP-T12"
    AUDIT_LOG_EVASION = "MCP-T13"
    PERSISTENCE_VIA_CALLBACK = "MCP-T14"


class OWASPCategory(StrEnum):
    """OWASP MCP Top 10 risk categories (MCP01 through MCP10)."""

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


THREAT_TO_OWASP: dict[PlaybookThreatID, list[OWASPCategory]] = {
    PlaybookThreatID.PROMPT_INJECTION_DIRECT: [
        OWASPCategory.PROMPT_INJECTION,
    ],
    PlaybookThreatID.PROMPT_INJECTION_INDIRECT: [
        OWASPCategory.PROMPT_INJECTION,
    ],
    PlaybookThreatID.CONFUSED_DEPUTY: [
        OWASPCategory.PRIVILEGE_ESCALATION,
        OWASPCategory.INSUFFICIENT_AUTH,
    ],
    PlaybookThreatID.TOKEN_AUDIENCE_BYPASS: [
        OWASPCategory.TOKEN_MISMANAGEMENT,
        OWASPCategory.PRIVILEGE_ESCALATION,
    ],
    PlaybookThreatID.CROSS_TOOL_CONTEXT_POISONING: [
        OWASPCategory.PROMPT_INJECTION,
        OWASPCategory.CONTEXT_LEAKAGE,
    ],
    PlaybookThreatID.SSRF_VIA_TOOL: [
        OWASPCategory.COMMAND_INJECTION,
    ],
    PlaybookThreatID.SECRETS_IN_TOOL_OUTPUT: [
        OWASPCategory.TOKEN_MISMANAGEMENT,
        OWASPCategory.CONTEXT_LEAKAGE,
    ],
    PlaybookThreatID.SUPPLY_CHAIN_VIA_CONTENT: [
        OWASPCategory.SUPPLY_CHAIN,
        OWASPCategory.TOOL_POISONING,
    ],
    PlaybookThreatID.AGENT_CONFIG_TAMPERING: [
        OWASPCategory.SUPPLY_CHAIN,
        OWASPCategory.PRIVILEGE_ESCALATION,
    ],
    PlaybookThreatID.HALLUCINATION_DRIVEN_DESTRUCTION: [
        OWASPCategory.COMMAND_INJECTION,
    ],
    PlaybookThreatID.CROSS_TENANT_MEMORY_LEAK: [
        OWASPCategory.CONTEXT_LEAKAGE,
    ],
    PlaybookThreatID.EXFILTRATION_VIA_CHAINING: [
        OWASPCategory.CONTEXT_LEAKAGE,
        OWASPCategory.LACK_OF_AUDIT,
    ],
    PlaybookThreatID.AUDIT_LOG_EVASION: [
        OWASPCategory.LACK_OF_AUDIT,
        OWASPCategory.INSUFFICIENT_AUTH,
    ],
    PlaybookThreatID.PERSISTENCE_VIA_CALLBACK: [
        OWASPCategory.SHADOW_SERVERS,
        OWASPCategory.SUPPLY_CHAIN,
    ],
}

OWASP_TO_THREATS: dict[OWASPCategory, list[PlaybookThreatID]] = {}
for threat_id, owasp_cats in THREAT_TO_OWASP.items():
    for cat in owasp_cats:
        OWASP_TO_THREATS.setdefault(cat, []).append(threat_id)


THREAT_METADATA: dict[PlaybookThreatID, dict[str, str]] = {
    PlaybookThreatID.PROMPT_INJECTION_DIRECT: {
        "name": "Prompt Injection (Direct)",
        "description": "User directly injects instructions into agent input.",
        "exploitable_when": "Input validation absent.",
        "red_team_lane": "RT-02",
        "owasp_llm": "LLM01",
    },
    PlaybookThreatID.PROMPT_INJECTION_INDIRECT: {
        "name": "Prompt Injection (Indirect)",
        "description": "Instructions injected via content agent reads.",
        "exploitable_when": "Content not labeled as untrusted.",
        "red_team_lane": "RT-02",
        "owasp_llm": "LLM01",
    },
    PlaybookThreatID.CONFUSED_DEPUTY: {
        "name": "Confused Deputy",
        "description": "Agent acts with elevated permissions on behalf of low-privilege user.",
        "exploitable_when": "No per-user identity propagation.",
        "red_team_lane": "RT-01",
        "owasp_llm": "LLM06",
    },
    PlaybookThreatID.TOKEN_AUDIENCE_BYPASS: {
        "name": "Token Audience Bypass",
        "description": "Token for tool A accepted by tool B.",
        "exploitable_when": "JWT aud claim not validated.",
        "red_team_lane": "RT-01",
        "owasp_llm": "LLM02",
    },
    PlaybookThreatID.CROSS_TOOL_CONTEXT_POISONING: {
        "name": "Cross-Tool Context Poisoning",
        "description": "Malicious content from one MCP influences actions in another.",
        "exploitable_when": "No context isolation between tools.",
        "red_team_lane": "RT-07",
        "owasp_llm": "LLM01+LLM06",
    },
    PlaybookThreatID.SSRF_VIA_TOOL: {
        "name": "SSRF via Tool",
        "description": "Agent tool fetches attacker-controlled or internal URLs.",
        "exploitable_when": "Egress not restricted; IP resolution not post-validated.",
        "red_team_lane": "RT-04",
        "owasp_llm": "LLM07",
    },
    PlaybookThreatID.SECRETS_IN_TOOL_OUTPUT: {
        "name": "Secrets in Tool Output",
        "description": "Tool returns secrets that agent includes in logged/posted output.",
        "exploitable_when": "No output filtering; DLP absent.",
        "red_team_lane": "RT-06",
        "owasp_llm": "LLM02",
    },
    PlaybookThreatID.SUPPLY_CHAIN_VIA_CONTENT: {
        "name": "Supply Chain via Content",
        "description": "Attacker influences code/config via content injection.",
        "exploitable_when": "No human review gate on agent-written artifacts.",
        "red_team_lane": "RT-03",
        "owasp_llm": "LLM03",
    },
    PlaybookThreatID.AGENT_CONFIG_TAMPERING: {
        "name": "Agent Config Tampering",
        "description": "Agent's own configuration modified via accessible MCP.",
        "exploitable_when": "Config repo writable by agent service account.",
        "red_team_lane": "RT-08",
        "owasp_llm": "LLM06",
    },
    PlaybookThreatID.HALLUCINATION_DRIVEN_DESTRUCTION: {
        "name": "Hallucination-Driven Destruction",
        "description": "LLM confidently executes wrong action with no confirmation gate.",
        "exploitable_when": "No dry-run; no HITL for destructive ops.",
        "red_team_lane": "RT-05",
        "owasp_llm": "LLM06",
    },
    PlaybookThreatID.CROSS_TENANT_MEMORY_LEAK: {
        "name": "Cross-Tenant Memory Leak",
        "description": "One tenant's data retrieved by another via shared vector DB.",
        "exploitable_when": "No mandatory tenant filter on retrieval.",
        "red_team_lane": "RT-06",
        "owasp_llm": "LLM04",
    },
    PlaybookThreatID.EXFILTRATION_VIA_CHAINING: {
        "name": "Exfiltration via Chaining",
        "description": "Data extracted by routing through a communication MCP.",
        "exploitable_when": "No DLP on MCP outputs; rate limits absent.",
        "red_team_lane": "RT-06",
        "owasp_llm": "LLM02",
    },
    PlaybookThreatID.AUDIT_LOG_EVASION: {
        "name": "Audit Log Evasion",
        "description": "Malicious actions not attributed to originating user.",
        "exploitable_when": "Agent identity used instead of delegated user identity.",
        "red_team_lane": "RT-01",
        "owasp_llm": "LLM08",
    },
    PlaybookThreatID.PERSISTENCE_VIA_CALLBACK: {
        "name": "Persistence via Webhook/Callback",
        "description": "Attacker plants persistent callback that re-injects on each session.",
        "exploitable_when": "No validation of registered callbacks or webhooks.",
        "red_team_lane": "RT-08",
        "owasp_llm": "LLM09",
    },
}


def threats_for_owasp(category: OWASPCategory) -> list[PlaybookThreatID]:
    """Return all playbook threat IDs that map to a given OWASP category."""
    return OWASP_TO_THREATS.get(category, [])


def owasp_for_threat(threat_id: PlaybookThreatID) -> list[OWASPCategory]:
    """Return OWASP categories that a playbook threat maps to."""
    return THREAT_TO_OWASP.get(threat_id, [])


def get_threat_metadata(threat_id: PlaybookThreatID) -> dict[str, str]:
    """Return metadata dict for a playbook threat ID."""
    return THREAT_METADATA.get(threat_id, {})
