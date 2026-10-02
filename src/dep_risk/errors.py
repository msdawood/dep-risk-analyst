class DepRiskError(Exception): ...


class ConfigurationError(DepRiskError): ...


class InvalidInputError(DepRiskError): ...  # For bad package names


class SourceError(DepRiskError):
    def __init__(self, source: str, message: str) -> None:
        super().__init__(f"[{source}] {message}")
        self.source = source


class SourceNotFoundError(SourceError): ...  # HTTP 404


class SourceUnavailableError(SourceError): ...  # timeout, 5xx, network, after retries


class RateLimitedError(SourceUnavailableError): ...  # GitHub 403/429


class InvalidResponseError(SourceError): ...  # JSON isn't the shape we expect
