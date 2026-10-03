from collections.abc import Sequence
from dataclasses import dataclass

from dep_risk.models import Vulnerability

SEVERITY_ORDER = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Issue:
    """One underlying flaw, possibly published under several advisory IDs."""

    ids: tuple[str, ...]
    severity: str | None
    fixed_in: tuple[str, ...]


def unique_issues(vulns: Sequence[Vulnerability]) -> list[Issue]:
    """Merge records that reference each other via aliases (GHSA/PYSEC/CVE)."""
    parent: dict[str, str] = {}

    def find(item: str) -> str:
        parent.setdefault(item, item)
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for vuln in vulns:
        find(vuln.id)
        for alias in vuln.aliases:
            parent[find(alias)] = find(vuln.id)

    groups: dict[str, list[Vulnerability]] = {}
    for vuln in vulns:
        groups.setdefault(find(vuln.id), []).append(vuln)

    issues: list[Issue] = []
    for members in groups.values():
        ids = sorted({v.id for v in members} | {a for v in members for a in v.aliases})
        severities = [v.severity for v in members if v.severity in SEVERITY_ORDER]
        severity = max(severities, key=SEVERITY_ORDER.__getitem__, default=None)
        fixed = tuple(dict.fromkeys(f for v in members for f in v.fixed_in))
        issues.append(Issue(tuple(ids), severity, fixed))
    return issues
