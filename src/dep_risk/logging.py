import json
import logging
import sys
from typing import TextIO


class _ConfiguredStreamHandler(logging.StreamHandler[TextIO]):
    pass


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"level": record.levelname, "message": record.getMessage()})


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
