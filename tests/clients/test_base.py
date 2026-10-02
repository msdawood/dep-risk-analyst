from collections.abc import AsyncIterator

import httpx
import pytest
import respx
from httpx import Response

from dep_risk.clients.base import BaseClient
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
        yield _DummyClient(http)


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
    route = respx_mock.get(URL).mock(return_value=Response(200, json=None))

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
