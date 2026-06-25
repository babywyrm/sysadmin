"""Taxonomy bridge between playbook threat IDs and OWASP categories.

The original red team playbook defines MCP-T01–T14 (core threats).
The extended agentic-sec / mcpnuke taxonomy adds MCP-T37–T49 covering
advanced transport, RAG pipeline, blocklist bypass, and multi-agent
identity-dilution attack classes.

MCP-T15–T36 are defined in the mcpnuke extended taxonomy (lanes.yaml)
and are not surfaced here — import from mcpnuke directly if needed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class PlaybookThreatID(StrEnum):
    """Red team playbook threat taxonomy (MCP-T01–T14 core + T37–T49 extended)."""

    # ── Core threats (T01–T14) ────────────────────────────────────────────────
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

    # ── Extended threats (T37–T49, agentic-sec / mcpnuke taxonomy) ──────────
    # Transport B — direct API (REST/gRPC); identity laundering
    AGENT_HTTP_BYPASS = "MCP-T37"
    # Transport C — in-process SDK; RAG content pipeline
    RAG_PIPELINE_INJECTION = "MCP-T39"
    # Transport A — governance gate bypass via trusted redirect
    AI_GOVERNANCE_GATE_BYPASS = "MCP-T41"
    # Transport A — blocklist bypass via alternative interpreter runtimes
    BLOCKLIST_BYPASS_INTERPRETER = "MCP-T44"
    # Lane 4 × Transport B — direct API credential forwarding, identity dilution
    AGENT_CHAIN_TRANSPORT_B_IDENTITY = "MCP-T45"
    # Lane 2 × Transport C — in-process SDK credential cache exposure
    SDK_CREDENTIAL_CACHE_EXPOSURE = "MCP-T46"
    # Lane 4 × Transport C — in-process SDK chain identity dilution
    AGENT_CHAIN_TRANSPORT_C_IDENTITY = "MCP-T47"
    # Lane 4 × Transport D — subprocess credential injection
    AGENT_CHAIN_SUBPROCESS_CRED = "MCP-T48"
    # Lane 4 × Transport E — LLM function-calling context/credential leak
    AGENT_CHAIN_FUNCTION_CALL_LEAK = "MCP-T49"


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
    # Extended T37–T49
    PlaybookThreatID.AGENT_HTTP_BYPASS: [
        OWASPCategory.INSUFFICIENT_AUTH,
        OWASPCategory.LACK_OF_AUDIT,
    ],
    PlaybookThreatID.RAG_PIPELINE_INJECTION: [
        OWASPCategory.PROMPT_INJECTION,
        OWASPCategory.SUPPLY_CHAIN,
    ],
    PlaybookThreatID.AI_GOVERNANCE_GATE_BYPASS: [
        OWASPCategory.PRIVILEGE_ESCALATION,
        OWASPCategory.INSUFFICIENT_AUTH,
    ],
    PlaybookThreatID.BLOCKLIST_BYPASS_INTERPRETER: [
        OWASPCategory.COMMAND_INJECTION,
    ],
    PlaybookThreatID.AGENT_CHAIN_TRANSPORT_B_IDENTITY: [
        OWASPCategory.TOKEN_MISMANAGEMENT,
        OWASPCategory.LACK_OF_AUDIT,
    ],
    PlaybookThreatID.SDK_CREDENTIAL_CACHE_EXPOSURE: [
        OWASPCategory.TOKEN_MISMANAGEMENT,
    ],
    PlaybookThreatID.AGENT_CHAIN_TRANSPORT_C_IDENTITY: [
        OWASPCategory.TOKEN_MISMANAGEMENT,
        OWASPCategory.PRIVILEGE_ESCALATION,
    ],
    PlaybookThreatID.AGENT_CHAIN_SUBPROCESS_CRED: [
        OWASPCategory.TOKEN_MISMANAGEMENT,
        OWASPCategory.PRIVILEGE_ESCALATION,
    ],
    PlaybookThreatID.AGENT_CHAIN_FUNCTION_CALL_LEAK: [
        OWASPCategory.CONTEXT_LEAKAGE,
        OWASPCategory.TOKEN_MISMANAGEMENT,
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
    # ── Extended metadata (T37–T49) ───────────────────────────────────────────
    PlaybookThreatID.AGENT_HTTP_BYPASS: {
        "name": "Agent HTTP Bypass — Direct Transport B Access",
        "description": "Machine agent skips MCP/gateway, calls downstream API directly with cached service token. OBO attribution collapses.",
        "exploitable_when": "Downstream API reachable from agent pod; mTLS or audience binding absent.",
        "red_team_lane": "RT-01",
        "transport": "B",
        "owasp_llm": "LLM06",
    },
    PlaybookThreatID.RAG_PIPELINE_INJECTION: {
        "name": "RAG Pipeline Injection — Poisoned Document Hijacks Synthesizer",
        "description": "Authority-framed chunk injected into shared corpus dominates retrieval and carries embedded instructions to the synthesizer agent.",
        "exploitable_when": "No per-chunk trust labels; retrieval not isolated by tenant or pipeline stage.",
        "red_team_lane": "RT-09",
        "transport": "C",
        "owasp_llm": "LLM01",
    },
    PlaybookThreatID.AI_GOVERNANCE_GATE_BYPASS: {
        "name": "AI Governance Gate Bypass via Trusted Redirect",
        "description": "Governance gate allowlists a trusted domain; attacker serves payload from attacker-controlled redirect target of that domain.",
        "exploitable_when": "Gate validates initial URL, not final redirect target; redirect resolution not sandboxed.",
        "red_team_lane": "RT-05",
        "transport": "A",
        "owasp_llm": "LLM06",
    },
    PlaybookThreatID.BLOCKLIST_BYPASS_INTERPRETER: {
        "name": "Blocklist Bypass via Incomplete Input Filter",
        "description": "Exec tool blocks bash/python but not perl, ruby, lua, awk, node, or php — alternative interpreters execute the same payload.",
        "exploitable_when": "Blocklist checks names, not invocation patterns; no interpreter allowlist.",
        "red_team_lane": "RT-03",
        "transport": "A",
        "owasp_llm": "LLM05",
    },
    PlaybookThreatID.AGENT_CHAIN_TRANSPORT_B_IDENTITY: {
        "name": "Agent-to-Agent Identity Dilution via Direct API Credential Forwarding",
        "description": "Orchestrator forwards its bearer token to sub-agent over direct REST. Audit chain shows service identity only — original user lost.",
        "exploitable_when": "No per-hop OBO exchange; audience not narrowed per agent.",
        "red_team_lane": "RT-01",
        "transport": "B",
        "lane": "4",
        "owasp_llm": "LLM02",
    },
    PlaybookThreatID.SDK_CREDENTIAL_CACHE_EXPOSURE: {
        "name": "In-Process SDK Credential Cache Exposure",
        "description": "Delegated human-to-agent token cached in SDK memory without re-validation. Forged write + privileged invoke extracts or replays cached credential.",
        "exploitable_when": "SDK cache not bound to session; no eviction on principal change.",
        "red_team_lane": "RT-01",
        "transport": "C",
        "lane": "2",
        "owasp_llm": "LLM02",
    },
    PlaybookThreatID.AGENT_CHAIN_TRANSPORT_C_IDENTITY: {
        "name": "Agent Chain In-Process SDK Identity Dilution",
        "description": "Multi-hop in-process delegation via SDK library calls. No network boundary between hops; no OBO per hop; authority accumulates without attenuation.",
        "exploitable_when": "No depth cap on delegation chain; in-process hops not audited as separate identities.",
        "red_team_lane": "RT-01",
        "transport": "C",
        "lane": "4",
        "owasp_llm": "LLM02",
    },
    PlaybookThreatID.AGENT_CHAIN_SUBPROCESS_CRED: {
        "name": "Agent Chain Subprocess Credential Injection",
        "description": "Parent agent injects token via env var or stdin to child subprocess. Child can act with parent credentials; audit attributes actions to child, not original user.",
        "exploitable_when": "Subprocess launch not sandboxed; env not scrubbed before fork; no SA pinning per subprocess.",
        "red_team_lane": "RT-01",
        "transport": "D",
        "lane": "4",
        "owasp_llm": "LLM06",
    },
    PlaybookThreatID.AGENT_CHAIN_FUNCTION_CALL_LEAK: {
        "name": "Agent Chain LLM Function-Calling Context Leak",
        "description": "Full conversation context — including credentials, PII, or injected instructions — propagated to each function call dispatch. Provider sees all; no identity per hop.",
        "exploitable_when": "No context scrubbing between function dispatches; provider key is only credential; user identity erased.",
        "red_team_lane": "RT-06",
        "transport": "E",
        "lane": "4",
        "owasp_llm": "LLM02",
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
