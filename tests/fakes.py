from datetime import UTC, datetime
from typing import Any

from dep_risk.models import GitHubFacts, OSVFacts, PyPIFacts, Vulnerability

REPO = "https://github.com/o/demo"


class _Fake:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[tuple[Any, ...]] = []

    async def fetch(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _pypi(summary: str | None = None, repository_url: str | None = REPO) -> PyPIFacts:
    return PyPIFacts(
        name="demo",
        latest_version="2.0.0",
        summary=summary,
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


def _osv(critical: bool = False) -> OSVFacts:
    vulns = (
        [
            Vulnerability(
                id="CVE-2026-1",
                aliases=[],
                summary="bad",
                severity="CRITICAL",
                fixed_in=[],
            )
        ]
        if critical
        else []
    )
    return OSVFacts(queried_version="2.0.0", vulnerabilities=vulns)
