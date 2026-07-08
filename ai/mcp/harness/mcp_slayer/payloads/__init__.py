"""Property-based payload generation for MCP security testing.

Instead of static payload lists, this module generates attack strings
dynamically through grammar-based construction and mutation operators.
This finds bypasses that hardcoded payloads miss — encoding tricks,
unicode normalization gaps, whitespace exploits, and novel combinations.
"""

from mcp_slayer.payloads.generators import (
    CommandPayloadGenerator,
    ExfilPayloadGenerator,
    InjectionPayloadGenerator,
    SchemaPayloadGenerator,
    TokenPayloadGenerator,
)
from mcp_slayer.payloads.mutations import (
    Mutation,
    MutationStrategy,
    apply_mutations,
)
from mcp_slayer.payloads.engine import PropertyTestEngine

__all__ = [
    "CommandPayloadGenerator",
    "ExfilPayloadGenerator",
    "InjectionPayloadGenerator",
    "Mutation",
    "MutationStrategy",
    "PropertyTestEngine",
    "SchemaPayloadGenerator",
    "TokenPayloadGenerator",
    "apply_mutations",
]
