import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import pytest

from dep_risk.errors import (
    InvalidInputError,
    SourceNotFoundError,
    SourceUnavailableError,
)
from dep_risk.gather import gather_facts
from dep_risk.models import (
    Confidence,
    GitHubFacts,
    OSVFacts,
    PyPIFacts,
    Rating,
    Source,
)
from dep_risk.scoring import score_package

REPO = "https://github.com/o/demo"


class _Fake:
    """Stands in for a client: returns a value, or raises it if it is an exception."""

    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[tuple[Any, ...]] = []

    async def fetch(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _pypi(repository_url: str | None = REPO) -> PyPIFacts:
    return PyPIFacts(
        name="demo-pkg",
        latest_version="2.0.0",
        summary=None,
        license=None,
        requires_python=None,
        author=None,
        maintainer=None,
        release_count=3,
        latest_release_at=datetime(2026, 9, 1, tzinfo=UTC),
        latest_yanked=False,
        repository_url=repository_url,
    )


def _github() -> GitHubFacts:
    return GitHubFacts(
        full_name="o/demo",
        archived=False,
        stars=1,
        open_issues=0,
        last_commit_at=datetime(2026, 9, 20, tzinfo=UTC),
        contributor_count=None,
    )


def _osv() -> OSVFacts:
    return OSVFacts(queried_version="2.0.0", vulnerabilities=[])


async def test_happy_path_collects_everything_and_passes_the_right_arguments() -> None:
    pypi, osv, github = _Fake(_pypi()), _Fake(_osv()), _Fake(_github())

    facts = await gather_facts("Demo_Pkg", pypi, osv, github)

    assert facts.package == "demo-pkg"
    assert (facts.pypi, facts.osv, facts.github) == (_pypi(), _osv(), _github())
    assert facts.gaps == ()
    assert pypi.calls == [("demo-pkg",)]
    assert osv.calls == [("demo-pkg", "2.0.0")]
    assert github.calls == [(REPO,)]


async def test_github_not_found_is_a_gap_not_a_failure() -> None:
    github = _Fake(SourceNotFoundError("github", "HTTP 404"))

    facts = await gather_facts("demo", _Fake(_pypi()), _Fake(_osv()), github)

    assert facts.github is None
    assert facts.osv == _osv() and facts.pypi == _pypi()
    assert [(g.source, g.reason) for g in facts.gaps] == [(Source.GITHUB, "[github] HTTP 404")]


async def test_osv_failure_is_a_gap_and_never_an_empty_result() -> None:
    osv = _Fake(SourceUnavailableError("osv", "ReadTimeout"))

    facts = await gather_facts("demo", _Fake(_pypi()), osv, _Fake(_github()))

    assert facts.osv is None  # not OSVFacts(vulnerabilities=[]): that would claim "none found"
    assert [g.source for g in facts.gaps] == [Source.OSV]


async def test_both_downstream_sources_failing_gives_two_gaps() -> None:
    osv = _Fake(SourceUnavailableError("osv", "boom"))
    github = _Fake(SourceUnavailableError("github", "boom"))

    facts = await gather_facts("demo", _Fake(_pypi()), osv, github)

    assert {g.source for g in facts.gaps} == {Source.OSV, Source.GITHUB}


async def test_missing_repository_link_is_a_gap_and_github_is_not_called() -> None:
    github = _Fake(_github())

    facts = await gather_facts("demo", _Fake(_pypi(repository_url=None)), _Fake(_osv()), github)

    assert github.calls == []
    assert facts.github is None
    (gap,) = facts.gaps
    assert gap.source is Source.GITHUB and "no GitHub repository linked" in gap.reason


async def test_package_not_found_on_pypi_is_fatal() -> None:
    osv, github = _Fake(_osv()), _Fake(_github())

    with pytest.raises(SourceNotFoundError):
        await gather_facts("demo", _Fake(SourceNotFoundError("pypi", "HTTP 404")), osv, github)

    assert osv.calls == [] and github.calls == []


async def test_pypi_outage_leaves_three_gaps_and_no_facts() -> None:
    pypi = _Fake(SourceUnavailableError("pypi", "HTTP 503"))
    osv, github = _Fake(_osv()), _Fake(_github())

    facts = await gather_facts("demo", pypi, osv, github)

    assert (facts.pypi, facts.osv, facts.github) == (None, None, None)
    assert [g.source for g in facts.gaps] == [Source.PYPI, Source.OSV, Source.GITHUB]
    assert osv.calls == [] and github.calls == []


async def test_invalid_package_name_is_rejected_before_any_call() -> None:
    pypi = _Fake(_pypi())

    with pytest.raises(InvalidInputError):
        await gather_facts("../etc/passwd", pypi, _Fake(_osv()), _Fake(_github()))

    assert pypi.calls == []


async def test_unexpected_error_becomes_a_generic_gap_and_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    osv = _Fake(RuntimeError("secret internal detail"))

    with caplog.at_level(logging.ERROR, logger="dep_risk.gather"):
        facts = await gather_facts("demo", _Fake(_pypi()), osv, _Fake(_github()))

    (gap,) = facts.gaps
    assert gap.source is Source.OSV
    assert gap.reason == "unexpected internal error"
    assert "secret internal detail" not in gap.reason
    assert "secret internal detail" in caplog.text  # logged with traceback for the developer


async def test_osv_and_github_are_fetched_concurrently() -> None:
    github_started = asyncio.Event()

    class _WaitsForGitHub(_Fake):
        async def fetch(self, *args: Any) -> Any:
            await asyncio.wait_for(github_started.wait(), timeout=1)  # deadlocks if sequential
            return await super().fetch(*args)

    class _SignalsStart(_Fake):
        async def fetch(self, *args: Any) -> Any:
            github_started.set()
            return await super().fetch(*args)

    facts = await gather_facts(
        "demo", _Fake(_pypi()), _WaitsForGitHub(_osv()), _SignalsStart(_github())
    )

    assert facts.gaps == ()


async def test_facts_with_gaps_flow_into_scoring_and_never_rate_low() -> None:
    facts = await gather_facts(
        "demo",
        _Fake(SourceUnavailableError("pypi", "HTTP 503")),
        _Fake(_osv()),
        _Fake(_github()),
    )

    result = score_package(facts, datetime(2026, 10, 4, tzinfo=UTC))

    assert (result.rating, result.confidence) == (Rating.MEDIUM, Confidence.LOW)
