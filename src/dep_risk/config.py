import functools
import logging

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .logging import configure_logging

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    anthropic_api_key: SecretStr = Field(min_length=1)
    github_token: SecretStr | None = None
    llm_model: str = "claude-haiku-4-5-20251001"

    http_timeout_seconds: float = Field(default=10.0, gt=0)
    http_max_attempts: int = Field(default=3, ge=1, le=10)
    max_agent_iterations: int = Field(default=6, ge=1, le=20)

    log_level: str = "INFO"
    log_json: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("github_token")
    @classmethod
    def _blank_token_is_none(cls, v: SecretStr | None) -> SecretStr | None:
        return v if v is not None and v.get_secret_value().strip() else None


@functools.lru_cache
def get_settings() -> Settings:
    settings = Settings()
    configure_logging(settings.log_level, settings.log_json)
    if settings.github_token is None:
        logger.warning("GitHub token is not set.")
    return settings
