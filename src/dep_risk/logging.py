import json
import logging
import sys
from datetime import UTC, datetime
from typing import TextIO


class _ConfiguredStreamHandler(logging.StreamHandler[TextIO]):
    pass


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "time": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def configure_logging(level: str, json_output: bool) -> None:
    numeric_level = logging.getLevelName(level.upper())
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid logging level: {level}")

    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        if isinstance(handler, _ConfiguredStreamHandler):
            root_logger.removeHandler(handler)

    handler = _ConfiguredStreamHandler(sys.stderr)
    if json_output:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    root_logger.setLevel(numeric_level)
    root_logger.addHandler(handler)

    for package in ("httpx", "httpx2", "httpcore"):
        logging.getLogger(package).setLevel(logging.WARNING)
