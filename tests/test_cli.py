import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dep_risk.cli import app
from dep_risk.errors import InvalidInputError

runner = CliRunner()


def test_analyse_prints_json_on_stdout() -> None:
    report = {"package": "demo", "rating": "low", "score": 5}

    with patch("dep_risk.cli._analyse", new=AsyncMock(return_value=report)):
        result = runner.invoke(app, ["analyse", "demo"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == report


def test_analyse_invalid_input_exits_1_with_error_on_stderr() -> None:
    failing = AsyncMock(side_effect=InvalidInputError("Invalid package name: demo"))

    with patch("dep_risk.cli._analyse", new=failing):
        result = runner.invoke(app, ["analyse", "demo"])

    assert result.exit_code == 1
    assert result.stderr.startswith("error:")
    assert result.stdout == ""
