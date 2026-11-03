from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RS_", env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./data/reposentinel.db"
    api_token: SecretStr = SecretStr("")
    data_dir: Path = Path("data")
    sample_dir: Path = Path("sample_projects/vulnerable")
    frontend_dir: Path = Path("frontend/dist")
    demo_mode: bool = False
    allowed_repos: str = ""
    max_archive_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 20 * 1024 * 1024
    max_file_bytes: int = 512 * 1024
    max_files: int = 500
    scan_timeout: int = 180
    engine_timeout: int = 30
    max_pending: int = 8
    rate_limit_per_minute: int = 10
    osv_enabled: bool = True
    osv_cache_hours: int = 24
    engines: str = "bandit,detect-secrets,semgrep,pip-audit"
    ai_provider: str = "none"
    ai_model: str = ""
    ai_api_key: SecretStr = SecretStr("")
    ai_base_url: str = "https://api.openai.com/v1"
    ollama_url: str = "http://127.0.0.1:11434"
    exposure: Literal["internal", "internet"] = "internal"
    critical_asset: bool = False
    exclusions: list[str] = Field(default_factory=list)

    @field_validator("ai_provider")
    @classmethod
    def valid_provider(cls, value: str) -> str:
        if value not in {"none", "openai-compatible", "ollama"}:
            raise ValueError("Unsupported AI provider")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
