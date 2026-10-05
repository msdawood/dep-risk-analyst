"""Evaluation harness: run the deterministic pipeline on a fixed set of packages and compare
the rating and confidence with expectations written down *before* looking at the output.

No LLM is involved, so a run is free and the only moving part is the live data.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from dep_risk.clients.github import GitHubClient
from dep_risk.clients.osv import OSVClient
from dep_risk.clients.pypi import PyPIClient
from dep_risk.errors import DepRiskError, InvalidInputError, SourceNotFoundError
from dep_risk.gather import gather_facts
from dep_risk.models import Confidence, Rating
from dep_risk.scoring import score_package


class EvalCase(BaseModel):
    package: str
    rating: Rating | None = None
    confidence: Confidence | None = None
    expect_error: Literal["not_found", "invalid_input"] | None = None
    note: str = ""

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def _expectation_is_complete(self) -> Self:
        if self.expect_error is None and (self.rating is None or self.confidence is None):
            raise ValueError("a case needs rating and confidence, or expect_error")
        if self.expect_error is not None and (self.rating or self.confidence):
            raise ValueError("a case cannot expect both an error and a rating")
        return self

    @property
    def expected(self) -> str:
        if self.expect_error is not None:
            return f"error: {self.expect_error}"
        assert self.rating is not None and self.confidence is not None
        return f"{self.rating.value} / {self.confidence.value}"


@dataclass(frozen=True)
class CaseResult:
    case: EvalCase
    actual: str

    @property
    def passed(self) -> bool:
        return self.actual == self.case.expected


def load_cases(path: Path) -> list[EvalCase]:
    return [EvalCase.model_validate(item) for item in json.loads(path.read_text())]


async def run_case(
    case: EvalCase,
    pypi: PyPIClient,
    osv: OSVClient,
    github: GitHubClient,
    now: datetime,
) -> CaseResult:
    try:
        facts = await gather_facts(case.package, pypi, osv, github)
    except SourceNotFoundError:
        return CaseResult(case, "error: not_found")
    except InvalidInputError:
        return CaseResult(case, "error: invalid_input")
    except DepRiskError as exc:
        return CaseResult(case, f"error: {type(exc).__name__}")
    result = score_package(facts, now)
    return CaseResult(case, f"{result.rating.value} / {result.confidence.value}")


def render_markdown(results: list[CaseResult], generated_at: datetime) -> str:
    passed = sum(r.passed for r in results)
    lines = [
        "# Evaluation results",
        "",
        f"Generated {generated_at:%Y-%m-%d %H:%M} UTC from live PyPI, OSV.dev and GitHub data "
        "(deterministic path, no LLM). Format: `rating / confidence`.",
        "",
        f"**{passed}/{len(results)} cases match expectations.**",
        "",
        "| Package | Expected | Actual | Result | Why this case |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        mark = "pass" if r.passed else "**FAIL**"
        lines.append(
            f"| `{r.case.package}` | {r.case.expected} | {r.actual} | {mark} | {r.case.note} |"
        )
    lines += [
        "",
        "Expectations were written from the package's known state before the run. A mismatch "
        "means the data changed, the rubric needs revisiting, or there is a bug; each is worth "
        "reading, not silencing.",
        "",
    ]
    return "\n".join(lines)
