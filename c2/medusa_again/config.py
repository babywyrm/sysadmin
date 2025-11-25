"""Configuration management using Pydantic."""

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MEDUSA_",
        case_sensitive=False,
    )

    # Device settings
    adb_device: str = Field(default="", description="ADB device ID")
    frida_timeout: int = Field(default=30, description="Frida operation timeout")

    # API keys
    vt_api_key: Optional[str] = Field(
        default=None, description="VirusTotal API key"
    )

    # Paths
    base_dir: Path = Field(
        default_factory=lambda: Path.cwd(),
        description="Base directory for Medusa",
    )
    modules_dir: Path = Field(
        default_factory=lambda: Path.cwd() / "modules",
        description="Modules directory",
    )
    snippets_dir: Path = Field(
        default_factory=lambda: Path.cwd() / "snippets",
        description="Snippets directory",
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Ensure directories exist
        self.modules_dir.mkdir(parents=True, exist_ok=True)
        self.snippets_dir.mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings()
