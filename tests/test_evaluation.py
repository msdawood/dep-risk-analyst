import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from dep_risk.errors import SourceNotFoundError, SourceUnavailableError
from dep_risk.evaluation import (
    CaseResult,
    EvalCase,
    load_cases,
    render_markdown,
    run_case,
)
from fakes import _Fake, _github, _osv, _pypi

NOW = datetime(2026, 10, 4, tzinfo=UTC)


async def _run(case: EvalCase, pypi: _Fake, osv: _Fake | None = None) -> CaseResult:
    return await run_case(
        case,
        pypi,  # type: ignore[arg-type]
        osv or _Fake(_osv()),  # type: ignore[arg-type]
        _Fake(_github()),  # type: ignore[arg-type]
        NOW,
    )


async def test_matching_report_case_passes() -> None:
    case = EvalCase(package="demo", rating="low", confidence="high")

    result = await _run(case, _Fake(_pypi()))

    assert result.actual == "low / high" and result.passed


async def test_a_wrong_expectation_is_reported_as_a_failure() -> None:
    case = EvalCase(package="demo", rating="high", confidence="high")

    result = await _run(case, _Fake(_pypi()))

    assert result.actual == "low / high" and not result.passed


async def test_gaps_show_up_in_the_confidence() -> None:
    case = EvalCase(package="demo", rating="medium", confidence="low")
    pypi = _Fake(SourceUnavailableError("pypi", "HTTP 503"))

    result = await _run(case, pypi)

    assert result.actual == "medium / low" and result.passed


async def test_not_found_is_an_expected_error() -> None:
    case = EvalCase(package="nope", expect_error="not_found")

    result = await _run(case, _Fake(SourceNotFoundError("pypi", "HTTP 404")))

    assert result.actual == "error: not_found" and result.passed


async def test_invalid_name_is_an_expected_error() -> None:
    case = EvalCase(package="../etc/passwd", expect_error="invalid_input")

    result = await _run(case, _Fake(_pypi()))

    assert result.actual == "error: invalid_input" and result.passed


async def test_an_error_where_a_report_was_expected_fails() -> None:
    case = EvalCase(package="demo", rating="low", confidence="high")

    result = await _run(case, _Fake(SourceNotFoundError("pypi", "HTTP 404")))

    assert result.actual == "error: not_found" and not result.passed


def test_case_needs_an_expectation() -> None:
    with pytest.raises(ValidationError):
        EvalCase(package="demo")
    with pytest.raises(ValidationError):
        EvalCase(package="demo", rating="low", confidence="high", expect_error="not_found")


def test_shipped_cases_file_is_valid() -> None:
    cases = load_cases(Path(__file__).parent.parent / "eval" / "cases.json")

    assert len(cases) >= 5
    assert any(c.expect_error for c in cases) and any(c.rating for c in cases)
    assert len({c.package for c in cases}) == len(cases)


def test_load_cases_reads_json(tmp_path: Path) -> None:
    path = tmp_path / "cases.json"
    path.write_text(json.dumps([{"package": "a", "rating": "low", "confidence": "high"}]))

    assert load_cases(path) == [EvalCase(package="a", rating="low", confidence="high")]


def test_markdown_report_summarises_and_flags_failures() -> None:
    ok = CaseResult(EvalCase(package="a", rating="low", confidence="high", note="n1"), "low / high")
    bad = CaseResult(EvalCase(package="b", rating="high", confidence="high"), "low / high")

    text = render_markdown([ok, bad], NOW)

    assert "1/2 cases match expectations" in text
    assert "| `a` | low / high | low / high | pass | n1 |" in text
    assert "**FAIL**" in text and "2026-10-04" in text
