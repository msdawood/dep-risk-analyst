import functools
import logging
from typing import Any

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    anthropic_api_key: SecretStr
    github_token: SecretStr | None = None
    llm_model: str = "claude-haiku-4-5-20251001"

    http_timeout_seconds: float = Field(default=10.0, gt=0)
    http_max_retries: int = 3
    max_agent_iterations: int = Field(default=6, gt=1, le=20)

    log_level: str = "INFO"
    log_json: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if not self.github_token:
            logger.warning("GitHub token is not set.")


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()
