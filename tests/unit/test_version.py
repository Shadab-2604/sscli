"""Unit tests for version definitions."""

from systemscan.version import APP_NAME, CLI_NAME, __version__


def test_version_values() -> None:
    assert __version__ == "1.0.0"
    assert "Universal System Security" in APP_NAME
    assert CLI_NAME == "systemscan"
