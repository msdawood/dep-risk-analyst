import re
from collections.abc import Mapping
from datetime import datetime
from email.utils import getaddresses
from typing import Any
from urllib.parse import urlsplit

from dep_risk.clients.base import BaseClient, as_object
from dep_risk.errors import InvalidInputError, InvalidResponseError
from dep_risk.models import PyPIFacts, Source

_GITHUB_HOSTS = {"github.com", "www.github.com"}
_RESERVED_GITHUB_OWNERS = {"apps", "orgs", "organizations", "sponsors"}
_PROJECT_URL_PREFERENCE = ("source", "source code", "repository", "code", "github")

_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_MAX_LICENSE_LENGTH = 100


def _clean(value: object) -> str | None:
    """Return a stripped, non-empty string, or None."""
    if isinstance(value, str):
        return value.strip() or None
    return None


def _short_license(info: Mapping[str, Any]) -> str | None:
    # Some packages put a whole license text in `license`; treat that as unknown.
    for key in ("license_expression", "license"):
        value = _clean(info.get(key))
        if value is not None and len(value) <= _MAX_LICENSE_LENGTH:
            return value
    return None


def _display_names(raw: object) -> str | None:
    """'Ann <a@x.org>, Bo <b@y.org>' -> 'Ann, Bo'. Email addresses are never kept."""
    if not isinstance(raw, str):
        return None
    names = [name.strip() for name, _address in getaddresses([raw]) if name.strip()]
    return ", ".join(names) or None


def _release_count(data: Mapping[str, Any]) -> int | None:
    # PyPI documents `releases` as deprecated, so its absence is not an error.
    releases = data.get("releases")
    return len(releases) if isinstance(releases, dict) else None


def _latest_upload(files: object) -> datetime | None:
    if not isinstance(files, list):
        raise TypeError("'urls' is not a list")
    uploads = [datetime.fromisoformat(file["upload_time_iso_8601"]) for file in files]
    return max(uploads, default=None)


def normalize_package_name(name: str) -> str:
    if len(name) > 100 or not _NAME_RE.fullmatch(name):
        raise InvalidInputError(f"Invalid package name: {name[:50]!r}")
    return re.sub(r"[-_.]+", "-", name).lower()


def _canonical_github_repo(value: object) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()
    if value.lower().startswith("git+https://"):
        value = value[4:]

    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or host not in _GITHUB_HOSTS
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None

    segments = parsed.path.strip("/").split("/")
    if len(segments) < 2:
        return None

    owner, repository = segments[:2]
    if repository.lower().endswith(".git"):
        repository = repository[:-4]
    if not owner or owner.casefold() in _RESERVED_GITHUB_OWNERS or not repository:
        return None

    return f"https://github.com/{owner}/{repository}"


def extract_github_repo(
    project_urls: Mapping[str, str] | None,
    home_page: str | None,
) -> str | None:
    """
    Return a canonical GitHub repository URL from PyPI project metadata.

    Project URL keys are matched case-insensitively and considered in this order:
    Source, Source Code, Repository, Code, GitHub, Homepage, then other keys.
    The home_page field is considered last.
    """
    entries = [
        (key.casefold(), value)
        for key, value in (project_urls or {}).items()
        if isinstance(key, str)
    ]

    for preferred_key in _PROJECT_URL_PREFERENCE:
        for key, value in entries:
            if key == preferred_key:
                repository = _canonical_github_repo(value)
                if repository is not None:
                    return repository

    for key, value in entries:
        if key == "homepage":
            repository = _canonical_github_repo(value)
            if repository is not None:
                return repository

    preferred_keys = {*_PROJECT_URL_PREFERENCE, "homepage"}
    for key, value in entries:
        if key not in preferred_keys:
            repository = _canonical_github_repo(value)
            if repository is not None:
                return repository

    return _canonical_github_repo(home_page)


def parse_pypi_facts(data: dict[str, Any]) -> PyPIFacts:
    try:
        info = data["info"]
        files = data["urls"]
        return PyPIFacts(
            name=info["name"],
            latest_version=info["version"],
            summary=_clean(info.get("summary")),
            license=_short_license(info),
            requires_python=_clean(info.get("requires_python")),
            author=_clean(info.get("author")) or _display_names(info.get("author_email")),
            maintainer=_clean(info.get("maintainer"))
            or _display_names(info.get("maintainer_email")),
            release_count=_release_count(data),
            latest_release_at=_latest_upload(files),
            latest_yanked=bool(info.get("yanked")),
            repository_url=extract_github_repo(info.get("project_urls"), info.get("home_page")),
        )
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise InvalidResponseError(
            Source.PYPI, f"unexpected response shape ({type(exc).__name__})"
        ) from exc


class PyPIClient(BaseClient):
    source = Source.PYPI

    async def fetch(self, package: str) -> PyPIFacts:
        name = normalize_package_name(package)  # raises before any network call
        data = as_object(
            self.source, await self._request_json("GET", f"https://pypi.org/pypi/{name}/json")
        )
        return parse_pypi_facts(data)
