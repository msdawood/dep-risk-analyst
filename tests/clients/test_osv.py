import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx
from httpx import Response
from tenacity import wait_none

from dep_risk.clients.osv import OSVClient, parse_osv_facts
from dep_risk.errors import (
    InvalidInputError,
    InvalidResponseError,
    RateLimitedError,
    SourceUnavailableError,
)

URL = "https://api.osv.dev/v1/query"


def _vuln(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "GHSA-8q59-q68h-6hv4",
        "summary": "Improper Input Validation in PyYAML",
        "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
        "database_specific": {"severity": "CRITICAL"},
        "affected": [
            {
                "package": {"name": "pyyaml", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}
                ],
            }
        ],
    }
    return base | overrides


@pytest.fixture
async def client() -> AsyncIterator[OSVClient]:
    async with httpx.AsyncClient() as http:
        yield OSVClient(http, max_attempts=3, wait=wait_none())


def test_parse_maps_a_vulnerability() -> None:
    facts = parse_osv_facts({"vulns": [_vuln()]}, "pyyaml", "5.3")

    assert facts.queried_version == "5.3"
    (vuln,) = facts.vulnerabilities
    assert vuln.id == "GHSA-8q59-q68h-6hv4"
    assert "CVE-2020-14343" in vuln.aliases
    assert vuln.severity == "CRITICAL"
    assert vuln.fixed_in == ["5.4"]


@pytest.mark.parametrize("empty", [{}, {"vulns": []}])
def test_empty_response_means_checked_and_found_none(empty: dict[str, Any]) -> None:
    facts = parse_osv_facts(empty, "requests", "2.34.2")

    assert facts.vulnerabilities == []
    assert facts.queried_version == "2.34.2"


@pytest.mark.parametrize(
    ("database_specific", "expected"),
    [
        ({"severity": "CRITICAL"}, "CRITICAL"),
        ({"severity": "moderate"}, "MODERATE"),
        ({"severity": "MEDIUM"}, "MODERATE"),
        ({"severity": "banana"}, None),
        ({}, None),
        (None, None),
    ],
)
def test_severity_is_normalised_or_unknown(
    database_specific: dict[str, Any] | None, expected: str | None
) -> None:
    raw = _vuln(database_specific=database_specific)

    (vuln,) = parse_osv_facts({"vulns": [raw]}, "pyyaml", "5.3").vulnerabilities

    assert vuln.severity == expected


def test_fixed_versions_ignore_other_packages_and_ecosystems() -> None:
    other = [
        {
            "package": {"name": "other-pkg", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9"}]}],
        },
        {
            "package": {"name": "pyyaml", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"fixed": "8.8"}]}],
        },
    ]
    raw = _vuln()
    raw["affected"] = [*raw["affected"], *other]

    (vuln,) = parse_osv_facts({"vulns": [raw]}, "pyyaml", "5.3").vulnerabilities

    assert vuln.fixed_in == ["5.4"]


def test_withdrawn_records_are_skipped() -> None:
    data = {"vulns": [_vuln(withdrawn="2024-01-01T00:00:00Z"), _vuln(id="GHSA-other")]}

    facts = parse_osv_facts(data, "pyyaml", "5.3")

    assert [v.id for v in facts.vulnerabilities] == ["GHSA-other"]


@pytest.mark.parametrize(
    "bad",
    [
        {"vulns": "nope"},
        {"vulns": [{"summary": "no id"}]},
        {"vulns": ["not an object"]},
        {"vulns": [_vuln(affected="oops")]},
    ],
)
def test_bad_shapes_raise_invalid_response(bad: dict[str, Any]) -> None:
    with pytest.raises(InvalidResponseError):
        parse_osv_facts(bad, "pyyaml", "5.3")


async def test_fetch_posts_the_expected_query(
    client: OSVClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(URL).mock(return_value=Response(200, json={"vulns": [_vuln()]}))

    facts = await client.fetch("PyYAML", "5.3")

    assert json.loads(route.calls.last.request.content) == {
        "package": {"name": "pyyaml", "ecosystem": "PyPI"},
        "version": "5.3",
    }
    assert len(facts.vulnerabilities) == 1


async def test_fetch_empty_object_is_no_vulnerabilities(
    client: OSVClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(URL).mock(return_value=Response(200, json={}))

    facts = await client.fetch("requests", "2.34.2")

    assert facts.vulnerabilities == []


async def test_failure_is_never_reported_as_no_vulnerabilities(
    client: OSVClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(URL).mock(return_value=Response(500))

    with pytest.raises(SourceUnavailableError):
        await client.fetch("requests", "2.34.2")

    assert route.call_count == 3


async def test_rate_limit_is_not_retried(client: OSVClient, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(URL).mock(return_value=Response(429))

    with pytest.raises(RateLimitedError):
        await client.fetch("requests", "2.34.2")

    assert route.call_count == 1


@pytest.mark.parametrize(
    ("package", "version"), [("../x", "1.0"), ("requests", " "), ("requests", "1" * 65)]
)
async def test_invalid_input_makes_no_request(
    client: OSVClient, respx_mock: respx.MockRouter, package: str, version: str
) -> None:
    route = respx_mock.route()

    with pytest.raises(InvalidInputError):
        await client.fetch(package, version)

    assert route.call_count == 0
