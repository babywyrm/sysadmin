"""Exception types for MCP-SLAYER."""


class SlayerException(Exception):
    """Base exception for MCP-SLAYER."""


class SlayerConfigError(SlayerException):
    """Configuration validation error."""


class SlayerKillSwitchError(SlayerException):
    """Kill switch activated — all operations must halt."""
