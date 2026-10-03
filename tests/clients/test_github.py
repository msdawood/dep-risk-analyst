from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx
from httpx import Response
from pydantic import SecretStr
from tenacity import wait_none

from dep_risk.clients.github import GitHubClient, parse_github_facts, parse_repository_url
from dep_risk.errors import (
    InvalidInputError,
    InvalidResponseError,
    RateLimitedError,
    SourceError,
    SourceNotFoundError,
)

REPO_URL = "https://github.com/psf/requests"
API_URL = "https://api.github.com/repos/psf/requests"


def _repo(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "full_name": "psf/requests",
        "archived": False,
        "stargazers_count": 52000,
        "open_issues_count": 120,
        "pushed_at": "2026-09-30T10:15:00Z",
    }
    return base | overrides


@pytest.fixture
async def client() -> AsyncIterator[GitHubClient]:
    async with httpx.AsyncClient(follow_redirects=True) as http:
        yield GitHubClient(http, max_attempts=3, wait=wait_none())


# --- repository URL parsing -------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/psf/requests", ("psf", "requests")),
        ("https://github.com/psf/requests/", ("psf", "requests")),
        ("https://github.com/python/typing_extensions", ("python", "typing_extensions")),
        ("https://github.com/Owner/repo.js", ("Owner", "repo.js")),
    ],
)
def test_parse_repository_url_accepts_valid_urls(url: str, expected: tuple[str, str]) -> None:
    assert parse_repository_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://github.com/psf",
        "https://github.com/../requests",
        "https://github.com/psf/..",
        "https://github.com/psf/.",
        "https://github.com/psf/requests/issues",
        "https://gitlab.com/psf/requests",
        "http://github.com/psf/requests",
        "https://github.com/-bad/requests",
        "https://github.com/psf/requests?x=1",
        "https://github.com/psf/re quests",
        "https://github.com/" + "a" * 40 + "/repo",
    ],
)
def test_parse_repository_url_rejects_everything_else(url: str) -> None:
    with pytest.raises(InvalidInputError):
        parse_repository_url(url)


# --- parsing the response ---------------------------------------------------


def test_parse_maps_fields() -> None:
    facts = parse_github_facts(_repo())

    assert facts.full_name == "psf/requests"
    assert facts.archived is False
    assert facts.stars == 52000
    assert facts.open_issues == 120
    assert facts.last_commit_at is not None and facts.last_commit_at.year == 2026
    assert facts.contributor_count is None


def test_missing_optional_fields_are_unknown_not_zero() -> None:
    data = _repo()
    for key in ("stargazers_count", "open_issues_count", "pushed_at"):
        del data[key]

    facts = parse_github_facts(data)

    assert (facts.stars, facts.open_issues, facts.last_commit_at) == (None, None, None)


@pytest.mark.parametrize("missing", ["full_name", "archived"])
def test_missing_required_fields_raise(missing: str) -> None:
    data = _repo()
    del data[missing]

    with pytest.raises(InvalidResponseError):
        parse_github_facts(data)


def test_wrong_types_raise() -> None:
    with pytest.raises(InvalidResponseError):
        parse_github_facts(_repo(stargazers_count="lots"))


# --- the client: headers, rate limits, redirects ---------------------------------


async def test_fetch_sends_required_headers_and_no_auth_without_token(
    client: GitHubClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(API_URL).mock(return_value=Response(200, json=_repo()))

    await client.fetch(REPO_URL)

    headers = route.calls.last.request.headers
    assert headers["accept"] == "application/vnd.github+json"
    assert headers["user-agent"].startswith("dep-risk")
    assert "authorization" not in headers


async def test_fetch_sends_the_token_when_configured(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.get(API_URL).mock(return_value=Response(200, json=_repo()))
    async with httpx.AsyncClient() as http:
        authed = GitHubClient(http, token=SecretStr("s3cret"))
        await authed.fetch(REPO_URL)

    assert route.calls.last.request.headers["authorization"] == "Bearer s3cret"


@pytest.mark.parametrize("status", [403, 429])
async def test_primary_rate_limit_is_reported_and_not_retried(
    client: GitHubClient, respx_mock: respx.MockRouter, status: int
) -> None:
    headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1790000000"}
    route = respx_mock.get(API_URL).mock(return_value=Response(status, headers=headers))

    with pytest.raises(RateLimitedError) as excinfo:
        await client.fetch(REPO_URL)

    assert route.call_count == 1
    assert "resets at" in str(excinfo.value)
    assert "GITHUB_TOKEN" in str(excinfo.value)


async def test_secondary_rate_limit_is_detected_by_retry_after(
    client: GitHubClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(API_URL).mock(return_value=Response(403, headers={"retry-after": "60"}))

    with pytest.raises(RateLimitedError):
        await client.fetch(REPO_URL)

    assert route.call_count == 1


async def test_plain_403_is_not_a_rate_limit(
    client: GitHubClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(API_URL).mock(
        return_value=Response(403, headers={"x-ratelimit-remaining": "42"})
    )

    with pytest.raises(SourceError) as excinfo:
        await client.fetch(REPO_URL)

    assert not isinstance(excinfo.value, RateLimitedError)
    assert route.call_count == 1


async def test_404_is_not_found(client: GitHubClient, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(API_URL).mock(return_value=Response(404))

    with pytest.raises(SourceNotFoundError):
        await client.fetch(REPO_URL)


async def test_renamed_repository_redirect_is_followed(
    client: GitHubClient, respx_mock: respx.MockRouter
) -> None:
    old = "https://api.github.com/repos/kennethreitz/requests"
    new = "https://api.github.com/repositories/1234"
    respx_mock.get(old).mock(return_value=Response(301, headers={"Location": new}))
    respx_mock.get(new).mock(return_value=Response(200, json=_repo()))

    facts = await client.fetch("https://github.com/kennethreitz/requests")

    assert facts.full_name == "psf/requests"  # the new name is what GitHub reports


async def test_redirect_is_an_error_when_the_http_client_does_not_follow(
    respx_mock: respx.MockRouter,
) -> None:
    old = "https://api.github.com/repos/kennethreitz/requests"
    route = respx_mock.get(old).mock(
        return_value=Response(301, headers={"Location": "https://api.github.com/repositories/1"})
    )
    async with httpx.AsyncClient(follow_redirects=False) as http:
        with pytest.raises(SourceError):
            await GitHubClient(http).fetch("https://github.com/kennethreitz/requests")

    assert route.call_count == 1


async def test_invalid_url_makes_no_request(
    client: GitHubClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.route()

    with pytest.raises(InvalidInputError):
        await client.fetch("https://github.com/../etc")

    assert route.call_count == 0
