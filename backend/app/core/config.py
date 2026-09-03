from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {
        "env_prefix": "SECOPS_",
        "env_file": ".env",
        "extra": "ignore",
        "populate_by_name": True,
    }

    # App
    app_name: str = "SecOps Orchestrator"
    debug: bool = False

    # Database
    database_url: str = "postgresql+asyncpg://secops:secops@localhost:5432/secops"
    database_url_sync: str = "postgresql://secops:secops@localhost:5432/secops"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Scanner execution
    scanner_timeout: int = 300  # seconds
    scanner_max_output_bytes: int = 50 * 1024 * 1024  # 50 MB
    workspace_base: Path = Path("/tmp/secops-workspaces")

    # Security
    allowed_workspace_root: Path = Path("/tmp/secops-workspaces")
    max_workspace_size_mb: int = 500

    # AI AppSec Reviewer
    ai_appsec_enabled: bool = Field(default=False, validation_alias="AI_APPSEC_ENABLED")
    ai_appsec_base_url: str | None = Field(default=None, validation_alias="AI_APPSEC_BASE_URL")
    ai_appsec_api_key: str | None = Field(default=None, validation_alias="AI_APPSEC_API_KEY")
    ai_appsec_model: str = Field(default="gpt-4o", validation_alias="AI_APPSEC_MODEL")
    ai_appsec_timeout_seconds: int = Field(default=60, validation_alias="AI_APPSEC_TIMEOUT_SECONDS")
    ai_appsec_max_file_bytes: int = Field(
        default=50 * 1024, validation_alias="AI_APPSEC_MAX_FILE_BYTES"
    )
    ai_appsec_max_total_bytes: int = Field(
        default=500 * 1024, validation_alias="AI_APPSEC_MAX_TOTAL_BYTES"
    )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def override_settings(settings: Settings) -> None:
    """For testing."""
    global _settings
    _settings = settings
