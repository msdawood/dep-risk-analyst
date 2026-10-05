import asyncio
import json
from datetime import UTC, datetime

import httpx
import typer

from dep_risk.agent import analyse_package, make_llm
from dep_risk.clients.github import GitHubClient
from dep_risk.clients.osv import OSVClient
from dep_risk.clients.pypi import PyPIClient
from dep_risk.config import get_settings
from dep_risk.errors import DepRiskError
from dep_risk.gather import gather_facts
from dep_risk.scoring import score_package

app = typer.Typer(help="Dependency risk analyst.", no_args_is_help=True)


async def _analyse(package: str, *, use_llm: bool) -> dict[str, object]:
    settings = get_settings()
    async with httpx.AsyncClient(
        timeout=settings.http_timeout_seconds, follow_redirects=True
    ) as http:
        pypi, osv = PyPIClient(http), OSVClient(http)
        github = GitHubClient(http, token=settings.github_token)
        if use_llm:
            report = await analyse_package(
                package,
                llm=make_llm(settings),
                pypi=pypi,
                osv=osv,
                github=github,
                max_iterations=settings.max_agent_iterations,
            )
            return report.model_dump(mode="json")
        facts = await gather_facts(package, pypi, osv, github)
    result = score_package(facts, datetime.now(UTC))
    return {
        "package": facts.package,
        "rating": result.rating.value,
        "score": result.score,
        "confidence": result.confidence.value,
        "factors": [
            {"name": f.name, "points": f.points, "detail": f.detail} for f in result.factors
        ],
        "data_gaps": [{"source": g.source.value, "reason": g.reason} for g in facts.gaps],
    }


@app.callback()
def _main() -> None:
    """Keeps `analyse` a named subcommand."""


@app.command()
def analyse(
    package: str = typer.Argument(..., help="PyPI package name"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Deterministic score only; no model call."),
) -> None:
    """Print a risk report for PACKAGE as JSON on stdout (logs go to stderr)."""
    try:
        output = asyncio.run(_analyse(package, use_llm=not no_llm))
    except DepRiskError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(output, indent=2))


if __name__ == "__main__":
    app()
