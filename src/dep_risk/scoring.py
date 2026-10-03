from dataclasses import dataclass
from datetime import datetime

from dep_risk.issues import Issue, unique_issues
from dep_risk.models import (
    Confidence,
    DataGap,
    GitHubFacts,
    OSVFacts,
    PackageFacts,
    PyPIFacts,
    Rating,
    Source,
)

# Thresholds. docs/scoring-rubric.md describes the same numbers.
_SEVERITY_POINTS = {"CRITICAL": 60, "HIGH": 50, "MODERATE": 25, "LOW": 10}
_UNKNOWN_SEVERITY_POINTS = 25  # unknown severity is treated like MODERATE, never as zero
_EXTRA_ISSUE_POINTS = 3
_EXTRA_ISSUES_CAP = 10
_YANKED_POINTS = 30
_ARCHIVED_POINTS = 35
# (older than N days, points), checked from the oldest threshold down
_RELEASE_AGE_POINTS = ((1095, 25), (548, 15), (365, 8))
_PUSH_AGE_POINTS = ((730, 15), (365, 8))
_MEDIUM_FROM = 25
_HIGH_FROM = 50
_MAX_SCORE = 100


@dataclass(frozen=True)
class Factor:
    name: str
    points: int
    detail: str  # built from facts only, e.g. "1 unpatched issue affecting 5.3 (worst: CRITICAL)"


@dataclass(frozen=True)
class ScoreResult:
    score: int
    rating: Rating
    confidence: Confidence
    factors: tuple[Factor, ...]


def _age_points(age_days: int, table: tuple[tuple[int, int], ...]) -> int:
    for threshold, points in table:
        if age_days > threshold:
            return points
    return 0


def _issue_points(issue: Issue) -> int:
    return _SEVERITY_POINTS.get(issue.severity or "", _UNKNOWN_SEVERITY_POINTS)


def _issue_label(issue: Issue) -> str:
    return next((i for i in issue.ids if i.startswith("CVE-")), issue.ids[0])


def _vulnerability_factor(osv: OSVFacts) -> Factor | None:
    issues = unique_issues(osv.vulnerabilities)  # one flaw can appear as several records
    if not issues:
        return None
    worst = max(issues, key=_issue_points)
    extra = min((len(issues) - 1) * _EXTRA_ISSUE_POINTS, _EXTRA_ISSUES_CAP)
    severity = worst.severity or "unknown severity"
    count = f"{len(issues)} unpatched issue{'s' if len(issues) != 1 else ''}"
    detail = f"{count} affecting {osv.queried_version} (worst: {severity}, {_issue_label(worst)})"
    return Factor("known vulnerabilities", _issue_points(worst) + extra, detail)


def _yanked_factor(pypi: PyPIFacts) -> Factor | None:
    if not pypi.latest_yanked:
        return None
    return Factor("latest release yanked", _YANKED_POINTS, f"{pypi.latest_version} was yanked")


def _release_age_factor(pypi: PyPIFacts, now: datetime) -> Factor | None:
    if pypi.latest_release_at is None:
        return Factor("release age", 0, "latest release date unknown")
    age_days = (now - pypi.latest_release_at).days
    points = _age_points(age_days, _RELEASE_AGE_POINTS)
    if points == 0:
        return None
    return Factor("stale release", points, f"latest release is {age_days} days old")


def _archived_factor(github: GitHubFacts) -> Factor | None:
    if not github.archived:
        return None
    return Factor("repository archived", _ARCHIVED_POINTS, f"{github.full_name} is archived")


def _push_age_factor(github: GitHubFacts, now: datetime) -> Factor | None:
    if github.last_commit_at is None:
        return Factor("repository activity", 0, "last push date unknown")
    age_days = (now - github.last_commit_at).days
    points = _age_points(age_days, _PUSH_AGE_POINTS)
    if points == 0:
        return None
    return Factor("inactive repository", points, f"last push was {age_days} days ago")


def _confidence(gaps: tuple[DataGap, ...]) -> Confidence:
    sources = {gap.source for gap in gaps}
    if not sources:
        return Confidence.HIGH
    if sources == {Source.GITHUB}:
        return Confidence.MEDIUM
    return Confidence.LOW  # OSV or PyPI missing: the most important signals are absent


def _rating(score: int) -> Rating:
    if score >= _HIGH_FROM:
        return Rating.HIGH
    if score >= _MEDIUM_FROM:
        return Rating.MEDIUM
    return Rating.LOW


def score_package(facts: PackageFacts, now: datetime) -> ScoreResult:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    candidates: list[Factor | None] = []
    if facts.osv is not None:
        candidates.append(_vulnerability_factor(facts.osv))
    if facts.pypi is not None:
        candidates += [_yanked_factor(facts.pypi), _release_age_factor(facts.pypi, now)]
    if facts.github is not None:
        candidates += [_archived_factor(facts.github), _push_age_factor(facts.github, now)]
    factors = [factor for factor in candidates if factor is not None]

    score = min(sum(factor.points for factor in factors), _MAX_SCORE)

    if facts.gaps and score < _MEDIUM_FROM:
        # Missing evidence is not evidence of safety: a gap can never produce a LOW rating.
        reasons = "; ".join(f"{gap.source}: {gap.reason}" for gap in facts.gaps)
        factors.append(Factor("data gaps", _MEDIUM_FROM - score, reasons))
        score = _MEDIUM_FROM

    factors.sort(key=lambda factor: -factor.points)
    return ScoreResult(score, _rating(score), _confidence(facts.gaps), tuple(factors))
