"""Run the evaluation set against live data.

    uv run python eval/run_eval.py            # print the results table
    uv run python eval/run_eval.py --write    # also save docs/eval-results.md

Exit code 1 if any case does not match its expectation.
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from dep_risk.clients.github import GitHubClient
from dep_risk.clients.osv import OSVClient
from dep_risk.clients.pypi import PyPIClient
from dep_risk.config import get_settings
from dep_risk.evaluation import load_cases, render_markdown, run_case

ROOT = Path(__file__).resolve().parent.parent


async def main(write: bool) -> int:
    settings = get_settings()
    cases = load_cases(ROOT / "eval" / "cases.json")
    async with httpx.AsyncClient(
        timeout=settings.http_timeout_seconds, follow_redirects=True
    ) as http:
        pypi, osv = PyPIClient(http), OSVClient(http)
        github = GitHubClient(http, token=settings.github_token)
        now = datetime.now(UTC)
        results = [await run_case(case, pypi, osv, github, now) for case in cases]
    report = render_markdown(results, now)
    print(report)
    if write:
        (ROOT / "docs" / "eval-results.md").write_text(report)
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="save docs/eval-results.md")
    sys.exit(asyncio.run(main(parser.parse_args().write)))
