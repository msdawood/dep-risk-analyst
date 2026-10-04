import asyncio
import json
from datetime import UTC, datetime

import httpx
import typer

from dep_risk.clients.github import GitHubClient
from dep_risk.clients.osv import OSVClient
from dep_risk.clients.pypi import PyPIClient
from dep_risk.config import get_settings
from dep_risk.errors import DepRiskError
from dep_risk.gather import gather_facts
from dep_risk.scoring import score_package

app = typer.Typer(help="Dependency risk analyst.", no_args_is_help=True)


async def _analyse(package: str) -> dict[str, object]:
    settings = get_settings()
    async with httpx.AsyncClient(
        timeout=settings.http_timeout_seconds, follow_redirects=True
    ) as http:
        facts = await gather_facts(
            package,
            PyPIClient(http),
            OSVClient(http),
            GitHubClient(http, token=settings.github_token),
        )
    result = score_package(facts, datetime.now(UTC))
    return {
        "package": facts.package,
        "rating": result.rating.value,
        "confidence": result.confidence.value,
        "score": result.score,
        "factors": [
            {"name": f.name, "points": f.points, "detail": f.detail} for f in result.factors
        ],
        "data_gaps": [{"source": g.source.value, "reason": g.reason} for g in facts.gaps],
    }


@app.callback()
def _main() -> None:
    """Keeps `analyse` a named subcommand."""


@app.command()
def analyse(package: str = typer.Argument(..., help="PyPI package name")) -> None:
    """Print a risk assessment for PACKAGE as JSON on stdout (logs go to stderr)."""
    try:
        report = asyncio.run(_analyse(package))
    except DepRiskError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(report, indent=2))


if __name__ == "__main__":
    app()
