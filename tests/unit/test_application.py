"""Unit tests for Application coordinator container."""

from pathlib import Path

from systemscan.core.application import Application
from systemscan.core.lifecycle import LifecycleState
from systemscan.utils.paths import AppPaths


def test_application_bootstrap_safe_run(tmp_path: Path) -> None:
    custom_paths = AppPaths(base_dir=tmp_path)
    app = Application(app_paths=custom_paths)
    app.bootstrap(debug=True)

    assert app.lifecycle.state == LifecycleState.READY
    assert app.is_debug is True
    assert app.config.schema_version == 1

    # Safe run execution
    res = app.run_safe(lambda: 0)
    assert res == 0
    assert app.lifecycle.state == LifecycleState.TERMINATED
