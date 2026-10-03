from datetime import UTC, datetime, timedelta

import pytest

from dep_risk.models import (
    Confidence,
    DataGap,
    GitHubFacts,
    OSVFacts,
    PackageFacts,
    PyPIFacts,
    Rating,
    Source,
    Vulnerability,
)
from dep_risk.scoring import score_package

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


def _ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def _pypi(release_age: int | None = 10, yanked: bool = False) -> PyPIFacts:
    return PyPIFacts(
        name="demo",
        latest_version="1.0.0",
        summary=None,
        license=None,
        requires_python=None,
        author=None,
        maintainer=None,
        release_count=3,
        latest_release_at=None if release_age is None else _ago(release_age),
        latest_yanked=yanked,
        repository_url="https://github.com/o/demo",
    )


def _github(push_age: int | None = 10, archived: bool = False) -> GitHubFacts:
    return GitHubFacts(
        full_name="o/demo",
        archived=archived,
        stars=1,
        open_issues=0,
        last_commit_at=None if push_age is None else _ago(push_age),
        contributor_count=None,
    )


def _vuln(id: str, severity: str | None, aliases: list[str] | None = None) -> Vulnerability:
    return Vulnerability(id=id, aliases=aliases or [], summary=None, severity=severity, fixed_in=[])


def _osv(*vulns: Vulnerability) -> OSVFacts:
    return OSVFacts(queried_version="1.0.0", vulnerabilities=list(vulns))


def _facts(
    pypi: PyPIFacts | None = None,
    github: GitHubFacts | None = None,
    osv: OSVFacts | None = None,
    gaps: tuple[DataGap, ...] = (),
) -> PackageFacts:
    return PackageFacts(
        package="demo",
        pypi=pypi or (None if any(g.source is Source.PYPI for g in gaps) else _pypi()),
        github=github or (None if any(g.source is Source.GITHUB for g in gaps) else _github()),
        osv=osv or (None if any(g.source is Source.OSV for g in gaps) else _osv()),
        gaps=gaps,
    )


def _gap(source: Source) -> DataGap:
    return DataGap(source=source, reason="unavailable")


def test_clean_recent_package_is_low_risk_with_high_confidence() -> None:
    result = score_package(_facts(), NOW)

    assert (result.score, result.rating, result.confidence) == (0, Rating.LOW, Confidence.HIGH)
    assert result.factors == ()


@pytest.mark.parametrize(
    ("age", "points"),
    [(365, 0), (366, 8), (548, 8), (549, 15), (1095, 15), (1096, 25)],
)
def test_release_age_boundaries(age: int, points: int) -> None:
    result = score_package(_facts(pypi=_pypi(release_age=age)), NOW)

    assert result.score == points


@pytest.mark.parametrize(("age", "points"), [(365, 0), (366, 8), (730, 8), (731, 15)])
def test_push_age_boundaries(age: int, points: int) -> None:
    result = score_package(_facts(github=_github(push_age=age)), NOW)

    assert result.score == points


@pytest.mark.parametrize(
    ("severity", "points", "rating"),
    [
        ("CRITICAL", 60, Rating.HIGH),
        ("HIGH", 50, Rating.HIGH),
        ("MODERATE", 25, Rating.MEDIUM),
        (None, 25, Rating.MEDIUM),
        ("LOW", 10, Rating.LOW),
    ],
)
def test_single_issue_severity_points(severity: str | None, points: int, rating: Rating) -> None:
    result = score_package(_facts(osv=_osv(_vuln("GHSA-1", severity))), NOW)

    assert (result.score, result.rating) == (points, rating)


def test_duplicate_records_for_one_flaw_count_once() -> None:
    osv = _osv(
        _vuln("GHSA-1", "CRITICAL", ["CVE-1", "PYSEC-1"]),
        _vuln("PYSEC-1", None, ["CVE-1", "GHSA-1"]),
    )

    result = score_package(_facts(osv=osv), NOW)

    assert result.score == 60


def test_extra_issues_add_three_each_up_to_ten() -> None:
    two = _osv(_vuln("A", "CRITICAL"), _vuln("B", "LOW"))
    many = _osv(_vuln("A", "CRITICAL"), *(_vuln(f"L{i}", "LOW") for i in range(10)))

    assert score_package(_facts(osv=two), NOW).score == 63
    assert score_package(_facts(osv=many), NOW).score == 70


def test_unknown_severity_outranks_low_when_picking_the_worst_issue() -> None:
    result = score_package(_facts(osv=_osv(_vuln("A", "LOW"), _vuln("B", None))), NOW)

    assert result.score == 25 + 3


def test_yanked_latest_release_is_medium() -> None:
    result = score_package(_facts(pypi=_pypi(yanked=True)), NOW)

    assert (result.score, result.rating) == (30, Rating.MEDIUM)


def test_archived_repository_alone_is_medium_and_with_old_release_is_high() -> None:
    archived = score_package(_facts(github=_github(archived=True)), NOW)
    abandoned = score_package(
        _facts(pypi=_pypi(release_age=4 * 365), github=_github(archived=True)), NOW
    )

    assert (archived.score, archived.rating) == (35, Rating.MEDIUM)
    assert (abandoned.score, abandoned.rating) == (60, Rating.HIGH)


def test_score_is_clamped_to_100() -> None:
    facts = _facts(
        pypi=_pypi(release_age=4000, yanked=True),
        github=_github(push_age=4000, archived=True),
        osv=_osv(_vuln("A", "CRITICAL")),
    )

    assert score_package(facts, NOW).score == 100


def test_github_gap_on_a_clean_package_is_medium_with_medium_confidence() -> None:
    result = score_package(_facts(gaps=(_gap(Source.GITHUB),)), NOW)

    assert (result.score, result.rating, result.confidence) == (
        25,
        Rating.MEDIUM,
        Confidence.MEDIUM,
    )
    assert result.factors[0].name == "data gaps"


@pytest.mark.parametrize("source", [Source.OSV, Source.PYPI])
def test_missing_osv_or_pypi_is_never_low_and_confidence_is_low(source: Source) -> None:
    result = score_package(_facts(gaps=(_gap(source),)), NOW)

    assert (result.rating, result.confidence) == (Rating.MEDIUM, Confidence.LOW)


def test_gap_does_not_lower_a_high_score() -> None:
    facts = _facts(osv=_osv(_vuln("A", "CRITICAL")), gaps=(_gap(Source.GITHUB),))

    result = score_package(facts, NOW)

    assert (result.score, result.rating, result.confidence) == (60, Rating.HIGH, Confidence.MEDIUM)
    assert all(f.name != "data gaps" for f in result.factors)


def test_unknown_dates_add_zero_point_factors() -> None:
    facts = _facts(pypi=_pypi(release_age=None), github=_github(push_age=None))

    result = score_package(facts, NOW)

    assert result.score == 0
    assert [(f.points, f.detail) for f in result.factors] == [
        (0, "latest release date unknown"),
        (0, "last push date unknown"),
    ]


def test_factor_details_come_from_the_facts() -> None:
    osv = _osv(_vuln("GHSA-1", "HIGH", ["CVE-2020-1"]))

    (factor,) = score_package(_facts(osv=osv), NOW).factors

    assert factor.name == "known vulnerabilities"
    assert factor.detail == "1 unpatched issue affecting 1.0.0 (worst: HIGH, CVE-2020-1)"


def test_naive_now_is_rejected() -> None:
    with pytest.raises(ValueError):
        score_package(_facts(), datetime(2026, 10, 3))
