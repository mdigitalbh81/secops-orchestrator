from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "SECOPS_", "env_file": ".env", "extra": "ignore"}

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
