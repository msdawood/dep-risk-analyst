import pytest
from pydantic import ValidationError

from dep_risk.config import Settings as AppSettings


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
