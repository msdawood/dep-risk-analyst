import logging
from collections.abc import Mapping
from typing import Any

from dep_risk.clients.base import BaseClient, as_object
from dep_risk.clients.common import canonical_name, clean_text
from dep_risk.clients.pypi import normalize_package_name
from dep_risk.errors import InvalidInputError, InvalidResponseError
from dep_risk.models import OSVFacts, Source, Vulnerability

logger = logging.getLogger(__name__)

_QUERY_URL = "https://api.osv.dev/v1/query"
_MAX_VERSION_LENGTH = 64
_SEVERITY_LEVELS = {
    "LOW": "LOW",
    "MODERATE": "MODERATE",
    "MEDIUM": "MODERATE",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


def _severity(raw: Mapping[str, Any]) -> str | None:
    # GitHub-reviewed advisories carry database_specific.severity; many PYSEC records do not.
    # Raw CVSS vectors are deliberately not parsed.
    database_specific = raw.get("database_specific")
    if not isinstance(database_specific, Mapping):
        return None
    level = clean_text(database_specific.get("severity"))
    return _SEVERITY_LEVELS.get(level.upper()) if level else None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _fixed_versions(raw: Mapping[str, Any], package: str) -> list[str]:
    """Versions that fix this issue for *this* PyPI package (a record can list others)."""
    fixed: list[str] = []
    for affected in raw.get("affected") or []:
        target = affected.get("package") or {}
        if target.get("ecosystem") != "PyPI":
            continue
        if canonical_name(str(target.get("name", ""))) != package:
            continue
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                version = event.get("fixed")
                if isinstance(version, str) and version not in fixed:
                    fixed.append(version)
    return fixed


def parse_osv_facts(data: Mapping[str, Any], package: str, version: str) -> OSVFacts:
    try:
        raw_vulns = data.get("vulns") or []  # an empty response means "none found"
        if not isinstance(raw_vulns, list):
            raise TypeError("'vulns' is not a list")
        vulnerabilities = [
            Vulnerability(
                id=raw["id"],
                aliases=_string_list(raw.get("aliases")),
                summary=clean_text(raw.get("summary")),
                severity=_severity(raw),
                fixed_in=_fixed_versions(raw, package),
            )
            for raw in raw_vulns
            if not raw.get("withdrawn")
        ]
        return OSVFacts(queried_version=version, vulnerabilities=vulnerabilities)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise InvalidResponseError(
            Source.OSV, f"unexpected response shape ({type(exc).__name__})"
        ) from exc


class OSVClient(BaseClient):
    source = Source.OSV

    async def fetch(self, package: str, version: str) -> OSVFacts:
        name = normalize_package_name(package)
        version = version.strip()
        if not version or len(version) > _MAX_VERSION_LENGTH:
            raise InvalidInputError("Invalid version")
        payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        data = as_object(self.source, await self._request_json("POST", _QUERY_URL, json=payload))
        if data.get("next_page_token"):
            logger.warning("OSV returned more than one page for %s; results are truncated", name)
        return parse_osv_facts(data, name, version)
