"""LLM-facing tools.

Design rule: the model decides *when* to call a tool, never *what* to look up.
The version and repository URL come from the PyPI result held in the Collector, not from
model-supplied arguments, so the model cannot query the wrong version or repository.
Tools never raise into the model: a failure becomes a recorded DataGap plus an error string.
"""

import json
from dataclasses import dataclass, field

from langchain_core.tools import BaseTool, tool
from pydantic import BaseModel

from dep_risk.clients.github import GitHubClient
from dep_risk.clients.osv import OSVClient
from dep_risk.clients.pypi import PyPIClient, normalize_package_name
from dep_risk.errors import InvalidInputError, SourceNotFoundError
from dep_risk.gather import attempt
from dep_risk.models import DataGap, GitHubFacts, OSVFacts, PackageFacts, PyPIFacts, Source

type SourceResult = PyPIFacts | OSVFacts | GitHubFacts | DataGap


@dataclass
class Collector:
    """Typed results of the tool calls made during one run."""

    results: dict[Source, SourceResult] = field(default_factory=dict)
    package_not_found: bool = False


def facts_from_collector(package: str, collector: Collector) -> PackageFacts | None:
    """Build PackageFacts from tool results, or None if the model did not finish the job."""
    if collector.package_not_found:
        return None
    pypi = collector.results.get(Source.PYPI)
    osv = collector.results.get(Source.OSV)
    github = collector.results.get(Source.GITHUB)
    if pypi is None or osv is None or github is None:
        return None
    ordered = (pypi, osv, github)
    return PackageFacts(
        package=package,
        pypi=pypi if isinstance(pypi, PyPIFacts) else None,
        osv=osv if isinstance(osv, OSVFacts) else None,
        github=github if isinstance(github, GitHubFacts) else None,
        gaps=tuple(r for r in ordered if isinstance(r, DataGap)),
    )


def _error(message: str) -> str:
    return json.dumps(
        {"error": message, "instruction": "This data is unavailable. Do not estimate or guess it."}
    )


def _dump(model: BaseModel) -> str:
    return model.model_dump_json()


def build_tools(
    package: str,
    collector: Collector,
    pypi: PyPIClient,
    osv: OSVClient,
    github: GitHubClient,
) -> list[BaseTool]:
    target = normalize_package_name(package)  # raises InvalidInputError for a bad name

    def wrong_package(requested: str) -> str | None:
        try:
            same = normalize_package_name(requested) == target
        except InvalidInputError:
            same = False
        return None if same else _error(f"This run analyses '{target}' only.")

    @tool
    async def get_pypi_metadata(package: str) -> str:
        """Fetch release history, maintainer details and repository link from PyPI. Call first."""
        if (bad := wrong_package(package)) is not None:
            return bad
        try:
            result = await attempt(Source.PYPI, pypi.fetch(target), fatal=(SourceNotFoundError,))
        except SourceNotFoundError as exc:
            collector.package_not_found = True
            return _error(str(exc))
        collector.results[Source.PYPI] = result
        return _error(result.reason) if isinstance(result, DataGap) else _dump(result)

    @tool
    async def get_osv_vulnerabilities(package: str) -> str:
        """List known vulnerabilities (OSV.dev) for the latest release. Call after PyPI."""
        if (bad := wrong_package(package)) is not None:
            return bad
        pypi_result = collector.results.get(Source.PYPI)
        if pypi_result is None:
            return _error("Call get_pypi_metadata first: the version comes from PyPI.")
        if isinstance(pypi_result, DataGap) or not isinstance(pypi_result, PyPIFacts):
            gap = DataGap(source=Source.OSV, reason="needs the latest version from PyPI")
            collector.results[Source.OSV] = gap
            return _error(gap.reason)
        result = await attempt(Source.OSV, osv.fetch(target, pypi_result.latest_version))
        collector.results[Source.OSV] = result
        return _error(result.reason) if isinstance(result, DataGap) else _dump(result)

    @tool
    async def get_github_activity(package: str) -> str:
        """Fetch repository activity (archived, last push, stars, open issues) from GitHub."""
        if (bad := wrong_package(package)) is not None:
            return bad
        pypi_result = collector.results.get(Source.PYPI)
        if pypi_result is None:
            return _error("Call get_pypi_metadata first: the repository link comes from PyPI.")
        if not isinstance(pypi_result, PyPIFacts):
            gap = DataGap(source=Source.GITHUB, reason="needs the repository URL from PyPI")
        elif pypi_result.repository_url is None:
            gap = DataGap(
                source=Source.GITHUB, reason="no GitHub repository linked from PyPI metadata"
            )
        else:
            result = await attempt(Source.GITHUB, github.fetch(pypi_result.repository_url))
            collector.results[Source.GITHUB] = result
            return _error(result.reason) if isinstance(result, DataGap) else _dump(result)
        collector.results[Source.GITHUB] = gap
        return _error(gap.reason)

    return [get_pypi_metadata, get_osv_vulnerabilities, get_github_activity]
