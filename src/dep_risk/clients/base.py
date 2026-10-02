import logging
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)
from tenacity.wait import wait_base

from dep_risk.errors import (
    InvalidResponseError,
    RateLimitedError,
    SourceError,
    SourceNotFoundError,
    SourceUnavailableError,
)
from dep_risk.models import Source

logger = logging.getLogger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    # RateLimitedError subclasses SourceUnavailableError, so exclude it explicitly.
    return isinstance(exc, SourceUnavailableError) and not isinstance(exc, RateLimitedError)


class BaseClient:
    source: Source  # set by each subclass

    def __init__(
        self, http: httpx.AsyncClient, *, max_attempts: int = 3, wait: wait_base | None = None
    ) -> None:
        self._http = http
        self._max_attempts = max_attempts
        self._wait = wait or wait_exponential_jitter(initial=0.5, max=8)

    async def _request_json(self, method: str, url: str, **kwargs: Any) -> Any:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._max_attempts),
            wait=self._wait,
            retry=retry_if_exception(_is_retryable),
            before_sleep=self._log_retry,
            reraise=True,  # raise our SourceUnavailableError, not tenacity's RetryError
        ):
            with attempt:
                return await self._request_once(method, url, **kwargs)
        raise AssertionError("unreachable")  # keeps mypy --strict happy

    async def _request_once(self, method: str, url: str, **kwargs: Any) -> Any:
        try:
            response = await self._http.request(method, url, **kwargs)
        except httpx.TransportError as exc:  # includes every httpx timeout
            raise SourceUnavailableError(self.source, type(exc).__name__) from exc
        self._raise_for_status(response)
        try:
            return response.json()
        except ValueError as exc:
            raise InvalidResponseError(self.source, "response was not valid JSON") from exc

    def _raise_for_status(self, response: httpx.Response) -> None:
        status_code = response.status_code
        if status_code == 404:
            raise SourceNotFoundError(self.source, f"HTTP {status_code}")
        if status_code == 429:
            raise RateLimitedError(self.source, f"HTTP {status_code}")
        if status_code >= 500:
            raise SourceUnavailableError(self.source, f"HTTP {status_code}")
        if status_code >= 400:
            raise SourceError(self.source, f"HTTP {status_code}")

    def _log_retry(self, state: RetryCallState) -> None:
        if state.outcome is None:
            return
        exception = state.outcome.exception()
        if exception is None:
            return

        logger.warning(
            "Retrying %s request after %s (attempt %d)",
            self.source.value,
            type(exception).__name__,
            state.attempt_number,
        )
