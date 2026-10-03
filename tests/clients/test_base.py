from collections.abc import AsyncIterator

import httpx
import pytest
import respx
from httpx import Response
from tenacity import wait_none

from dep_risk.clients.base import BaseClient, _is_retryable, as_object
from dep_risk.errors import (
    InvalidResponseError,
    RateLimitedError,
    SourceError,
    SourceNotFoundError,
    SourceUnavailableError,
)
from dep_risk.models import Source

URL = "https://example.test/package"


class _DummyClient(BaseClient):
    source = Source.PYPI


@pytest.fixture
async def client() -> AsyncIterator[_DummyClient]:
    async with httpx.AsyncClient() as http:
        yield _DummyClient(http, max_attempts=3, wait=wait_none())


async def test_200_response_returns_parsed_json(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:
    expected = {"package": "requests", "version": "2.31.0"}
    route = respx_mock.get(URL).mock(return_value=Response(200, json=expected))

    result = await client._request_json("GET", URL)

    assert result == expected
    assert route.call_count == 1


async def test_200_response_returns_invalid_data(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(
        return_value=Response(200, content=b"<html>Bad gateway</html>")
    )

    with pytest.raises(InvalidResponseError):
        await client._request_json("GET", URL)

    assert route.call_count == 1


async def test_404_response_raises_source_not_found_error(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(return_value=Response(404))

    with pytest.raises(SourceNotFoundError):
        await client._request_json("GET", URL)

    assert route.call_count == 1


async def test_429_response_raises_rate_limited_error(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(return_value=Response(429))

    with pytest.raises(RateLimitedError):
        await client._request_json("GET", URL)

    assert route.call_count == 1


async def test_500_response_twice_then_succeeds(
    client: _DummyClient, respx_mock: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    expected = {"package": "requests", "version": "2.31.0"}
    route = respx_mock.get(URL).mock(
        side_effect=[Response(500), Response(500), Response(200, json=expected)]
    )
    result = await client._request_json("GET", URL)

    assert route.call_count == 3
    assert result == expected
    retry_records = [record for record in caplog.records if record.name == "dep_risk.clients.base"]
    assert [record.getMessage() for record in retry_records] == [
        "Retrying pypi request after SourceUnavailableError (attempt 1)",
        "Retrying pypi request after SourceUnavailableError (attempt 2)",
    ]
    assert all(URL not in record.getMessage() for record in retry_records)


async def test_500_response_always_fails(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:

    route = respx_mock.get(URL).mock(side_effect=[Response(500), Response(500), Response(500)])

    with pytest.raises(SourceUnavailableError):
        await client._request_json("GET", URL)

    assert route.call_count == 3


async def test_timeout_raises_source_unavailable_error(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(side_effect=httpx.ReadTimeout("Timeout occurred"))

    with pytest.raises(SourceUnavailableError):
        await client._request_json("GET", URL)

    assert route.call_count == 3


async def test_401_response_raise_source_error(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(return_value=Response(401))

    with pytest.raises(SourceError):
        await client._request_json("GET", URL)

    assert route.call_count == 1


@pytest.mark.parametrize("bad", [None, [], [1, 2], "text", 42])
def test_as_object_rejects_non_objects(bad: object) -> None:
    with pytest.raises(InvalidResponseError):
        as_object(Source.PYPI, bad)


def test_as_object_returns_dict_unchanged() -> None:
    assert as_object(Source.PYPI, {"a": 1}) == {"a": 1}


def test_is_retryable() -> None:

    # Should retry on SourceUnavailableError
    assert _is_retryable(SourceUnavailableError("pypi", "error"))

    # Should not retry on RateLimitedError
    assert not _is_retryable(RateLimitedError("pypi", "error"))


async def test_unfollowed_redirect_is_an_error_not_parsed_as_data(
    client: _DummyClient, respx_mock: respx.MockRouter
) -> None:
    body = {"message": "Moved Permanently"}
    route = respx_mock.get(URL).mock(
        return_value=Response(301, json=body, headers={"Location": "https://example.test/new"})
    )

    with pytest.raises(SourceError) as excinfo:
        await client._request_json("GET", URL)

    assert "redirect" in str(excinfo.value)
    assert route.call_count == 1
