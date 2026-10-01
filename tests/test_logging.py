import json
import logging
from collections.abc import Iterator
from datetime import datetime

import pytest
from _pytest.capture import CaptureFixture

from dep_risk.logging import configure_logging


@pytest.fixture
def restore_root_logger() -> Iterator[None]:
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level
    httpx_logger = logging.getLogger("httpx")
    original_httpx_level = httpx_logger.level
    yield
    for handler in root_logger.handlers[:]:
        if handler not in original_handlers:
            root_logger.removeHandler(handler)
    for handler in original_handlers:
        if handler not in root_logger.handlers:
            root_logger.addHandler(handler)
    root_logger.setLevel(original_level)
    httpx_logger.setLevel(original_httpx_level)


def test_json_logging_is_valid_and_written_to_stderr(
    capsys: CaptureFixture[str], restore_root_logger: None
) -> None:
    configure_logging("INFO", json_output=True)
    logging.getLogger("dep_risk.test").info("analysis complete")

    captured = capsys.readouterr()
    assert captured.out == ""
    log_record = json.loads(captured.err)
    datetime.fromisoformat(log_record["time"])
    assert log_record["level"] == "INFO"
    assert log_record["logger"] == "dep_risk.test"
    assert log_record["message"] == "analysis complete"


def test_json_logging_includes_exception_text(
    capsys: CaptureFixture[str], restore_root_logger: None
) -> None:
    configure_logging("INFO", json_output=True)
    try:
        raise RuntimeError("retry failed")
    except RuntimeError:
        logging.getLogger("dep_risk.test").exception("request failed")

    log_record = json.loads(capsys.readouterr().err)
    assert log_record["exception"].startswith("Traceback")
    assert "RuntimeError: retry failed" in log_record["exception"]


def test_configure_logging_suppresses_httpx_info(
    capsys: CaptureFixture[str], restore_root_logger: None
) -> None:
    configure_logging("INFO", json_output=True)
    httpx_logger = logging.getLogger("httpx")
    httpx_logger.info("request sent")
    httpx_logger.warning("request retries exhausted")

    log_records = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert len(log_records) == 1
    assert log_records[0]["level"] == "WARNING"
    assert log_records[0]["message"] == "request retries exhausted"


def test_configure_logging_does_not_duplicate_handlers(
    capsys: CaptureFixture[str], restore_root_logger: None
) -> None:
    configure_logging("INFO", json_output=True)
    configure_logging("INFO", json_output=True)
    logging.getLogger("dep_risk.test").info("once")

    captured = capsys.readouterr()
    assert len(captured.err.splitlines()) == 1
