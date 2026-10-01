from dep_risk.errors import RateLimitedError, SourceError, SourceUnavailableError


def test_source_error_formats_message_and_stores_source() -> None:
	error = SourceError("github", "boom")

	assert str(error) == "[github] boom"
	assert error.source == "github"


def test_rate_limited_error_is_source_unavailable() -> None:
	error = RateLimitedError("github", "rate limited")

	assert isinstance(error, SourceUnavailableError)
