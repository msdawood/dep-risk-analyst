import json
import logging
from collections.abc import Iterator

import pytest

from dep_risk.logging import configure_logging


@pytest.fixture
def restore_root_logger() -> Iterator[None]:
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level
    yield
    for handler in root_logger.handlers[:]:
        if handler not in original_handlers:
            root_logger.removeHandler(handler)
    for handler in original_handlers:
        if handler not in root_logger.handlers:
            root_logger.addHandler(handler)
    root_logger.setLevel(original_level)


def test_json_logging_is_valid_and_written_to_stderr(capsys, restore_root_logger) -> None:
    configure_logging("INFO", json_output=True)
    logging.getLogger("dep_risk.test").info("analysis complete")

    captured = capsys.readouterr()
    assert captured.out == ""
    log_record = json.loads(captured.err)
    assert log_record["level"] == "INFO"
    assert log_record["message"] == "analysis complete"


def test_configure_logging_does_not_duplicate_handlers(capsys, restore_root_logger) -> None:
    configure_logging("INFO", json_output=True)
    configure_logging("INFO", json_output=True)
    logging.getLogger("dep_risk.test").info("once")

    captured = capsys.readouterr()
    assert len(captured.err.splitlines()) == 1
