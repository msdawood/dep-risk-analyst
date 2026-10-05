import json
from typing import Any

import pytest
from typer.testing import CliRunner

from dep_risk import cli
from dep_risk.errors import InvalidInputError

runner = CliRunner()


def test_analyse_prints_json_and_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    async def fake(package: str, *, use_llm: bool) -> dict[str, object]:
        seen.update(package=package, use_llm=use_llm)
        return {"package": package, "rating": "low"}

    monkeypatch.setattr(cli, "_analyse", fake)

    result = runner.invoke(cli.app, ["analyse", "demo", "--no-llm"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"package": "demo", "rating": "low"}
    assert seen == {"package": "demo", "use_llm": False}


def test_domain_errors_exit_one_with_a_message(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(package: str, *, use_llm: bool) -> dict[str, object]:
        raise InvalidInputError("bad name")

    monkeypatch.setattr(cli, "_analyse", fake)

    result = runner.invoke(cli.app, ["analyse", "../x"])

    assert result.exit_code == 1
    assert "bad name" in result.output and result.stdout.strip() == ""
