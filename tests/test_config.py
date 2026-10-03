import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from dep_risk.config import Settings as AppSettings
from dep_risk.config import get_settings


@pytest.fixture
def isolated_settings_logging() -> Iterator[None]:
    get_settings.cache_clear()
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level
    yield
    get_settings.cache_clear()
    for handler in root_logger.handlers[:]:
        if handler not in original_handlers:
            root_logger.removeHandler(handler)
    for handler in original_handlers:
        if handler not in root_logger.handlers:
            root_logger.addHandler(handler)
    root_logger.setLevel(original_level)


def test_missing_api_key_raises_validation_error(monkeypatch):
    """Ensure missing the required anthropic_api_key fails construction."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(ValidationError) as exc_info:
        # Pass _env_file=None to prevent reading from local disk
        AppSettings(_env_file=None)

    assert "anthropic_api_key" in str(exc_info.value)
    assert "Field required" in str(exc_info.value)


def test_repr_does_not_leak_secret_key(monkeypatch):
    """Ensure printing or getting the __repr__ of settings obfuscates secrets."""
    secret_value = "super-secret-anthropic-key-value"
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret_value)

    settings = AppSettings(_env_file=None)
    settings_repr = repr(settings)

    # The actual secret string should never appear in the representation
    assert secret_value not in settings_repr
    assert "**********" in settings_repr


def test_invalid_timeout_is_rejected(monkeypatch):
    """Ensure http_timeout_seconds must be strictly greater than zero."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy_key")

    with pytest.raises(ValidationError) as exc_info:
        AppSettings(_env_file=None, http_timeout_seconds=0)

    assert "http_timeout_seconds" in str(exc_info.value)
    assert "Input should be greater than 0" in str(exc_info.value)


def test_valid_construction_with_defaults(monkeypatch):
    """Verify standard operational defaults resolve cleanly when valid keys exist."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy_key")

    settings = AppSettings(_env_file=None)

    assert settings.llm_model == "claude-haiku-4-5-20251001"
    assert settings.http_timeout_seconds == 10.0
    assert settings.max_agent_iterations == 6


def test_settings_construction_does_not_warn_about_missing_github_token(monkeypatch, caplog):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy_key")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    with caplog.at_level(logging.WARNING, logger="dep_risk.config"):
        AppSettings(_env_file=None)

    assert not [record for record in caplog.records if record.name == "dep_risk.config"]

@pytest.fixture
def isolated_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)  # Settings reads ".env" from the cwd; keep the real one out
    get_settings.cache_clear()  # get_settings is lru_cached; start from a clean slate
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    get_settings.cache_clear()
    root.handlers[:] = handlers  # undo configure_logging's global changes
    root.setLevel(level)


@pytest.mark.usefixtures("isolated_settings")
def test_get_settings_configures_json_logging_before_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy_key")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("LOG_JSON", "true")

    settings = get_settings()

    captured = capsys.readouterr()
    warning = json.loads(captured.err)
    assert settings.github_token is None
    assert warning["level"] == "WARNING"
    assert warning["logger"] == "dep_risk.config"
    assert warning["message"] == "GitHub token is not set."
    assert "time" in warning
    assert captured.out == ""