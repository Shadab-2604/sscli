"""Structured log formatters and security filters for systemscan."""

import logging
import re
from typing import Any

# Sensitive key patterns to scrub in log output
REDACT_PATTERNS = [
    re.compile(r"(api[_-]?key\s*[:=]\s*)(['\"][^'\"]+['\"]|\S+)", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*)(['\"][^'\"]+['\"]|\S+)", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*)(['\"][^'\"]+['\"]|\S+)", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)(['\"][^'\"]+['\"]|\S+)", re.IGNORECASE),
    re.compile(r"(authorization\s*[:=]\s*Bearer\s+)(\S+)", re.IGNORECASE),
]


class SensitiveDataScrubber(logging.Filter):
    """Filter that strips out sensitive keys, tokens, or credentials from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern in REDACT_PATTERNS:
                msg = pattern.sub(r"\1[REDACTED]", msg)
            record.msg = msg

        if record.args:
            if isinstance(record.args, dict):
                clean_args: dict[str, Any] = {}
                for k, v in record.args.items():
                    if any(s in k.lower() for s in ("key", "token", "pass", "secret")):
                        clean_args[k] = "[REDACTED]"
                    else:
                        clean_args[k] = v
                record.args = clean_args
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    "[REDACTED]"
                    if isinstance(a, str)
                    and any(s in a.lower() for s in ("password=", "token=", "key="))
                    else a
                    for a in record.args
                )

        return True


class StructuredFileFormatter(logging.Formatter):
    """Detailed timestamped structured formatter for file diagnostic logs."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s | %(levelname)-8s | pid:%(process)d | %(name)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
