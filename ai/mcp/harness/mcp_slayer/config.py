"""Unified configuration schema for MCP-SLAYER v3.1.

This merges the two prior config formats (config.yaml and slayer-config.yaml)
into one canonical, versioned schema. Both old formats are loadable via
`load_config()` which normalizes them into `SlayerConfig`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    model_validator,
)


class RedactionConfig(BaseModel):
    """PII and secret redaction rules for evidence sanitization."""

    headers: list[str] = Field(
        default=[
            "authorization",
            "x-api-key",
            "cookie",
            "x-auth-token",
            "proxy-authorization",
            "x-amz-security-token",
        ]
    )
    json_keys: list[str] = Field(
        default=["password", "secret", "token", "key", "credential", "api_key"]
    )
    patterns: list[str] = Field(
        default=[
            r"(?i)bearer\s+[a-z0-9\-\._~\+\/]+=*",
            r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-z0-9]{20,}",
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        ]
    )


class ToolTarget(BaseModel):
    """MCP tool target definition."""

    name: str
    base_url: str
    execute_path: str = "/execute"
    health_path: str = "/health"
    auth_profile: str = "default"
    labels: dict[str, str] = Field(default_factory=dict)
    rate_limit_rps: int = Field(10, gt=0)
    allow_actions: list[str] = Field(default_factory=list)
    deny_actions: list[str] = Field(default_factory=list)
    # Endpoints whose responses flow back into agent context (prompt-injection-canary).
    injection_endpoints: list[str] = Field(default_factory=list)
    # Egress actions the tool can perform, used by the exfiltration-routing module.
    egress_actions: list[str] = Field(default_factory=list)
    # Retrieval/query endpoints that return stored context (context-leakage module).
    retrieval_endpoints: list[str] = Field(default_factory=list)
    # Endpoints that return the tool's advertised descriptions/schemas, e.g. a
    # JSON-RPC tools/list surface (tool-poisoning module).
    schema_endpoints: list[str] = Field(default_factory=list)


class GatewayTarget(BaseModel):
    """MCP gateway/controller target."""

    base_url: str
    invoke_path: str = "/invoke"
    tools_path: str = "/tools"
    health_path: str = "/healthz"
    auth_required: bool = True


class AuthProfile(BaseModel):
    """Authentication credential profile."""

    name: str
    type: Literal["bearer", "basic", "mtls", "oauth2_client_credentials", "none"]
    token: SecretStr | None = None
    username: str | None = None
    password: SecretStr | None = None
    cert_path: Path | None = None
    key_path: Path | None = None
    token_url: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    scope: str | None = None
    audience: str | None = None


class SIEMIntegration(BaseModel):
    """SIEM/observability integration for purple team coordination."""

    enabled: bool = False
    type: Literal["splunk", "elastic", "datadog", "custom"] = "splunk"
    endpoint: str | None = None
    api_key: SecretStr | None = None
    index_name: str | None = None


class PayloadEntry(BaseModel):
    """A single test payload definition."""

    id: str
    name: str
    prompt: str | None = None
    token: str | None = None
    canary: str | None = None
    expected: dict[str, Any] = Field(default_factory=dict)
    mapping: dict[str, str] = Field(default_factory=dict)


class ModuleSettings(BaseModel):
    """Per-module configuration overrides."""

    endpoint: str | None = None
    actions: list[str] = Field(default_factory=list)
    success_statuses: list[int] = Field(default=[200, 201, 202])
    strict_2xx_is_finding: bool = False
    require_canary: bool = False
    max_duration_s: float | None = None
    prompt: str | None = None
    tests_from_pack: str | None = None


class SlayerConfig(BaseModel):
    """Master configuration for MCP-SLAYER v3.1.

    Canonical schema that unifies both legacy config formats.
    Load with `load_config()` for automatic normalization.
    """

    version: str = "3.1"

    # Ethical safety
    authorized: bool = False
    safe_word: str = "REDSTOP"
    max_concurrent_attacks: int = Field(5, ge=1, le=50)
    respect_robots_txt: bool = True
    timeout_seconds: int = Field(10, ge=1, le=120)
    verify_tls: bool = True

    # Targets
    gateway: GatewayTarget
    tools: list[ToolTarget] = Field(default_factory=list)

    # Auth
    auth_profiles: list[AuthProfile] = Field(
        default=[AuthProfile(name="default", type="none")]
    )

    # Security
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)

    # Output
    output_dir: Path = Field(Path("./slayer-results"))
    output_formats: list[Literal["json", "yaml", "markdown", "sarif"]] = Field(
        default=["json"]
    )

    # Integration
    siem: SIEMIntegration = Field(default_factory=SIEMIntegration)

    # Modules
    enabled_modules: list[str] = Field(default=["all"])
    skip_modules: list[str] = Field(default_factory=list)
    module_settings: dict[str, ModuleSettings] = Field(default_factory=dict)

    # Payloads
    payloads: dict[str, list[PayloadEntry]] = Field(default_factory=dict)

    # Policy expectations (blue team requirements)
    policy_expectations: dict[str, Any] = Field(default_factory=dict)

    # Macros for payload interpolation
    macros: dict[str, str] = Field(default_factory=dict)

    # Metadata
    run_name: str | None = None
    environment: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_authorized(self) -> SlayerConfig:
        if not self.authorized:
            raise ValueError(
                "Config must set 'authorized: true' to perform active security testing."
            )
        return self


_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} and ${VAR:-default} with env values."""

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        default = match.group(2) or ""
        return os.environ.get(var_name, default)

    return _ENV_VAR_RE.sub(_replace, value)


def _interpolate_recursive(obj: Any) -> Any:
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, dict):
        return {k: _interpolate_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_interpolate_recursive(item) for item in obj]
    return obj


def _normalize_v1_config(data: dict) -> dict:
    """Normalize the payload-focused config format (version: 1) to v3.1 schema."""
    normalized: dict[str, Any] = {
        "version": "3.1",
        "authorized": data.get("run", {}).get("authorized", False),
        "safe_word": data.get("run", {}).get("safe_word", "REDSTOP"),
        "max_concurrent_attacks": data.get("run", {}).get("concurrency", 5),
        "timeout_seconds": data.get("run", {}).get("timeout_s", 10),
        "verify_tls": data.get("run", {}).get("verify_tls", True),
        "run_name": data.get("run", {}).get("name"),
        "environment": data.get("env", {}).get("name"),
        "tags": data.get("env", {}).get("tags", {}),
    }

    targets = data.get("targets", {})
    if "gateway" in targets:
        normalized["gateway"] = targets["gateway"]
    if "tools" in targets:
        normalized["tools"] = targets["tools"]

    profiles_section = data.get("auth_profiles", {})
    profiles_list = []
    for name, profile in profiles_section.get("profiles", {}).items():
        profile["name"] = name
        if profile.get("type") == "jwt_static":
            profile["type"] = "bearer"
        profiles_list.append(profile)
    if profiles_list:
        normalized["auth_profiles"] = profiles_list

    if "reporting" in data:
        reporting = data["reporting"]
        formats = []
        output_path = None
        for output in reporting.get("outputs", []):
            fmt = output.get("format")
            if fmt:
                formats.append(fmt)
            if output.get("path") and not output_path:
                output_path = str(Path(output["path"]).parent)
        if formats:
            normalized["output_formats"] = formats
        if output_path:
            normalized["output_dir"] = output_path
        if "redact" in reporting:
            normalized["redaction"] = {
                "headers": reporting["redact"].get("headers", []),
                "json_keys": [
                    k.removeprefix("$..")
                    for k in reporting["redact"].get("json_fields", [])
                ],
            }

    modules = data.get("modules", {})
    if "enabled" in modules:
        normalized["enabled_modules"] = modules["enabled"]
    if "settings" in modules:
        normalized["module_settings"] = modules["settings"]

    if "payloads" in data:
        normalized["payloads"] = data["payloads"]

    if "policy_expectations" in data:
        normalized["policy_expectations"] = data["policy_expectations"]

    if "macros" in data:
        normalized["macros"] = data["macros"]

    return normalized


def load_config(path: Path) -> SlayerConfig:
    """Load and normalize a config file from either format.

    Supports:
    - v3.x format (direct SlayerConfig mapping)
    - v1 format (payload-focused, normalized automatically)
    - Environment variable interpolation in all string values
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Config must be a YAML mapping")

    interpolated = _interpolate_recursive(raw)

    version = str(interpolated.get("version", ""))
    if version.startswith("1"):
        interpolated = _normalize_v1_config(interpolated)

    return SlayerConfig(**interpolated)
