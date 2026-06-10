"""Tests for config loading and normalization."""

import tempfile
from pathlib import Path

import pytest
import yaml

from mcp_slayer.config import load_config

MINIMAL_V3_CONFIG = {
    "version": "3.1",
    "authorized": True,
    "gateway": {
        "base_url": "https://gw.example.com",
        "invoke_path": "/invoke",
    },
    "tools": [
        {"name": "test-tool", "base_url": "http://tool.local:8080"},
    ],
}


MINIMAL_V1_CONFIG = {
    "version": 1,
    "run": {
        "name": "test-run",
        "authorized": True,
        "concurrency": 4,
        "timeout_s": 15,
        "verify_tls": True,
    },
    "targets": {
        "gateway": {
            "base_url": "https://gw.example.com",
            "invoke_path": "/invoke",
        },
        "tools": [
            {"name": "search", "base_url": "http://search.local:9000"},
        ],
    },
    "auth_profiles": {
        "default": "none-profile",
        "profiles": {
            "none-profile": {"type": "none"},
        },
    },
}


def _write_yaml(data: dict) -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
    return Path(f.name)


def test_load_v3_config():
    path = _write_yaml(MINIMAL_V3_CONFIG)
    try:
        config = load_config(path)
        assert config.version == "3.1"
        assert config.gateway.base_url == "https://gw.example.com"
        assert len(config.tools) == 1
        assert config.tools[0].name == "test-tool"
    finally:
        path.unlink()


def test_load_v1_config_normalizes():
    path = _write_yaml(MINIMAL_V1_CONFIG)
    try:
        config = load_config(path)
        assert config.version == "3.1"
        assert config.max_concurrent_attacks == 4
        assert config.timeout_seconds == 15
        assert config.gateway.base_url == "https://gw.example.com"
        assert config.run_name == "test-run"
    finally:
        path.unlink()


def test_unauthorized_config_raises():
    data = {**MINIMAL_V3_CONFIG, "authorized": False}
    path = _write_yaml(data)
    try:
        with pytest.raises(Exception, match="authorized"):
            load_config(path)
    finally:
        path.unlink()


def test_env_var_interpolation(monkeypatch):
    monkeypatch.setenv("TEST_GW_URL", "https://from-env.example.com")
    data = {
        **MINIMAL_V3_CONFIG,
        "gateway": {
            "base_url": "${TEST_GW_URL}",
            "invoke_path": "/invoke",
        },
    }
    path = _write_yaml(data)
    try:
        config = load_config(path)
        assert config.gateway.base_url == "https://from-env.example.com"
    finally:
        path.unlink()


def test_env_var_default():
    data = {
        **MINIMAL_V3_CONFIG,
        "gateway": {
            "base_url": "${NONEXISTENT_VAR:-https://default.example.com}",
            "invoke_path": "/invoke",
        },
    }
    path = _write_yaml(data)
    try:
        config = load_config(path)
        assert config.gateway.base_url == "https://default.example.com"
    finally:
        path.unlink()
