"""Attack module registry and base class."""

from __future__ import annotations

from mcp_slayer.modules.base import AttackModule
from mcp_slayer.modules.confused_deputy import ConfusedDeputyModule
from mcp_slayer.modules.shadow_server import ShadowServerModule
from mcp_slayer.modules.ssrf_metadata import SsrfMetadataModule

MODULE_REGISTRY: dict[str, type[AttackModule]] = {
    "confused-deputy": ConfusedDeputyModule,
    "ssrf-metadata": SsrfMetadataModule,
    "shadow-server": ShadowServerModule,
}

__all__ = [
    "AttackModule",
    "ConfusedDeputyModule",
    "ShadowServerModule",
    "SsrfMetadataModule",
    "MODULE_REGISTRY",
]
