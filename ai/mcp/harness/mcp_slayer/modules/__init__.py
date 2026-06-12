"""Attack module registry and base class."""

from __future__ import annotations

from mcp_slayer.modules.base import AttackModule
from mcp_slayer.modules.confused_deputy import ConfusedDeputyModule
from mcp_slayer.modules.context_leakage import ContextLeakageModule
from mcp_slayer.modules.exfiltration import ExfiltrationModule
from mcp_slayer.modules.prompt_injection import PromptInjectionModule
from mcp_slayer.modules.shadow_server import ShadowServerModule
from mcp_slayer.modules.ssrf_metadata import SsrfMetadataModule
from mcp_slayer.modules.token_validation import TokenValidationModule

MODULE_REGISTRY: dict[str, type[AttackModule]] = {
    "confused-deputy": ConfusedDeputyModule,
    "ssrf-metadata": SsrfMetadataModule,
    "shadow-server": ShadowServerModule,
    "prompt-injection-canary": PromptInjectionModule,
    "token-validation": TokenValidationModule,
    "exfiltration-routing": ExfiltrationModule,
    "context-leakage": ContextLeakageModule,
}

__all__ = [
    "AttackModule",
    "ConfusedDeputyModule",
    "ContextLeakageModule",
    "ExfiltrationModule",
    "PromptInjectionModule",
    "ShadowServerModule",
    "SsrfMetadataModule",
    "TokenValidationModule",
    "MODULE_REGISTRY",
]
