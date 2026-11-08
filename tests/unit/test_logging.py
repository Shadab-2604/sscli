"""Unit tests for logging infrastructure and credential scrubber."""

import logging
from pathlib import Path

from systemscan.logging.formatter import SensitiveDataScrubber, StructuredFileFormatter
from systemscan.logging.logger import get_logger, init_logging, set_log_level


def test_sensitive_data_scrubber() -> None:
    scrubber = SensitiveDataScrubber()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Connecting with token=secret123 and password=supersecret password",
        args=(),
        exc_info=None,
    )
    scrubber.filter(record)
    assert "secret123" not in record.msg
    assert "supersecret" not in record.msg
    assert "[REDACTED]" in record.msg


def test_structured_formatter() -> None:
    formatter = StructuredFileFormatter()
    record = logging.LogRecord(
        name="systemscan.core",
        level=logging.INFO,
        pathname="core.py",
        lineno=42,
        msg="Initialization complete",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    assert "INFO" in output
    assert "systemscan.core:42" in output
    assert "Initialization complete" in output


def test_init_logging(tmp_path: Path) -> None:
    test_log_dir = tmp_path / "logs"
    init_logging(
        level="DEBUG",
        log_dir=test_log_dir,
        console_enabled=False,
        file_enabled=True,
        debug=True,
    )

    scoped_logger = get_logger("unit_test")
    scoped_logger.info("Test log entry for unit test")

    log_file = test_log_dir / "systemscan.log"
    assert log_file.is_file()
    content = log_file.read_text(encoding="utf-8")
    assert "Test log entry for unit test" in content

    set_log_level("WARNING")
