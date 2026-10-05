import asyncio
import logging
from collections.abc import Awaitable

from dep_risk.clients.github import GitHubClient
from dep_risk.clients.osv import OSVClient
from dep_risk.clients.pypi import PyPIClient, normalize_package_name
from dep_risk.errors import InvalidInputError, SourceError, SourceNotFoundError
from dep_risk.models import DataGap, GitHubFacts, OSVFacts, PackageFacts, PyPIFacts, Source

logger = logging.getLogger(__name__)


async def attempt[T](
    source: Source,
    call: Awaitable[T],
    *,
    fatal: tuple[type[Exception], ...] = (),
) -> T | DataGap:
    """Run one source call and turn any failure into a DataGap instead of raising."""
    try:
        return await call
    except fatal:
        raise
    except (SourceError, InvalidInputError) as exc:
        return DataGap(source=source, reason=str(exc))
    except Exception:
        # Programming errors must not look like data, and their text must not reach a report.
        logger.exception("Unexpected error while fetching %s facts", source.value)
        return DataGap(source=source, reason="unexpected internal error")


async def gather_facts(
    package: str, pypi: PyPIClient, osv: OSVClient, github: GitHubClient
) -> PackageFacts:
    name = normalize_package_name(package)  # InvalidInputError propagates: nothing to analyse

    # PyPI comes first: OSV needs its version and GitHub needs its repository link.
    # A missing package is fatal. Any other PyPI failure leaves nothing to look up.
    pypi_result: PyPIFacts | DataGap = await attempt(
        Source.PYPI, pypi.fetch(name), fatal=(SourceNotFoundError, InvalidInputError)
    )
    if isinstance(pypi_result, DataGap):
        return PackageFacts(
            package=name,
            gaps=(
                pypi_result,
                DataGap(source=Source.OSV, reason="needs the latest version from PyPI"),
                DataGap(source=Source.GITHUB, reason="needs the repository URL from PyPI"),
            ),
        )

    osv_call = attempt(Source.OSV, osv.fetch(name, pypi_result.latest_version))
    github_result: GitHubFacts | DataGap
    osv_result: OSVFacts | DataGap
    if pypi_result.repository_url is None:
        github_result = DataGap(
            source=Source.GITHUB, reason="no GitHub repository linked from PyPI metadata"
        )
        osv_result = await osv_call
    else:
        osv_result, github_result = await asyncio.gather(
            osv_call, attempt(Source.GITHUB, github.fetch(pypi_result.repository_url))
        )

    return PackageFacts(
        package=name,
        pypi=pypi_result,
        osv=None if isinstance(osv_result, DataGap) else osv_result,
        github=None if isinstance(github_result, DataGap) else github_result,
        gaps=tuple(r for r in (osv_result, github_result) if isinstance(r, DataGap)),
    )
