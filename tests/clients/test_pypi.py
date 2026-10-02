import copy
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import respx
from httpx import Response
from tenacity import wait_none

from dep_risk.clients.pypi import PyPIClient, extract_github_repo, parse_pypi_facts
from dep_risk.errors import InvalidInputError, InvalidResponseError, SourceNotFoundError

FIXTURE = json.loads((Path(__file__).parent.parent / "fixtures" / "pypi_requests.json").read_text())
URL = "https://pypi.org/pypi/requests/json"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://github.com/Owner/Repo.git/tree/main",
            "https://github.com/Owner/Repo",
        ),
        (
            "http://www.github.com/Owner/Repo/issues",
            "https://github.com/Owner/Repo",
        ),
        (
            "git+https://github.com/Owner/Repo.git/",
            "https://github.com/Owner/Repo",
        ),
    ],
)
def test_extract_github_repo_normalizes_url(url: str, expected: str) -> None:
    assert extract_github_repo({"Repository": url}, None) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com.evil.io/owner/repo",
        "https://gist.github.com/owner/repo",
        "https://owner.github.io/repo",
        "https://github.com/sponsors/project",
        "https://github.com/orgs/project",
        "https://github.com/apps/project",
        "https://github.com/owner",
        "https://github.com//repo",
        "ftp://github.com/owner/repo",
    ],
)
def test_extract_github_repo_rejects_invalid_urls(url: str) -> None:
    assert extract_github_repo({"Source": url}, None) is None


def test_extract_github_repo_prefers_project_url_keys_case_insensitively() -> None:
    project_urls = {
        "hOmEpAgE": "https://github.com/homepage/repo",
        "gItHuB": "https://github.com/github/repo",
        "sOuRcE cOdE": "https://github.com/source-code/repo",
        "sOuRcE": "https://github.com/source/repo",
    }

    assert (
        extract_github_repo(project_urls, "https://github.com/home-page/repo")
        == "https://github.com/source/repo"
    )


def test_extract_github_repo_falls_back_to_other_urls_then_home_page() -> None:
    assert (
        extract_github_repo(
            {
                "Source": "https://example.com/not-github",
                "Documentation": "https://github.com/docs/repo/issues",
            },
            "https://github.com/home/repo",
        )
        == "https://github.com/docs/repo"
    )
    assert extract_github_repo({}, "http://github.com/home/repo/") == (
        "https://github.com/home/repo"
    )


@pytest.fixture
async def client() -> AsyncIterator[PyPIClient]:
    async with httpx.AsyncClient() as http:
        yield PyPIClient(http, max_attempts=3, wait=wait_none())


def test_parse_fixture() -> None:
    facts = parse_pypi_facts(FIXTURE)
    assert facts.name == "requests"
    assert facts.repository_url == "https://github.com/psf/requests"
    assert facts.release_count == 3  # the trimmed fixture keeps 3 releases
    assert facts.latest_release_at is not None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["info"].pop("version"),
        lambda d: d.pop("urls"),
        lambda d: d.__setitem__("info", []),
        lambda d: d.__setitem__("urls", "nope"),
    ],
)
def test_parse_rejects_bad_shapes(mutate) -> None:
    data = copy.deepcopy(FIXTURE)
    mutate(data)
    with pytest.raises(InvalidResponseError):
        parse_pypi_facts(data)


def test_parse_missing_optional_fields_become_none() -> None:
    data = copy.deepcopy(FIXTURE)
    for key in ("summary", "license", "requires_python", "project_urls"):
        data["info"].pop(key, None)
    data.pop("releases")
    facts = parse_pypi_facts(data)
    assert facts.summary is None and facts.release_count is None


async def test_fetch_normalises_name_and_returns_facts(
    client, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(return_value=Response(200, json=FIXTURE))
    assert (await client.fetch("Requests")).name == "requests"
    assert route.call_count == 1


async def test_fetch_404_is_not_found(client, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(URL).mock(return_value=Response(404))
    with pytest.raises(SourceNotFoundError):
        await client.fetch("requests")


async def test_fetch_invalid_name_makes_no_request(client, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.route()
    with pytest.raises(InvalidInputError):
        await client.fetch("../etc/passwd")
    assert route.call_count == 0
