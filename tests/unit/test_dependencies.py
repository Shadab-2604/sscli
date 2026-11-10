"""Unit tests for dependency registry, installer, external tool inspector, and environment doctor."""

from __future__ import annotations

from unittest.mock import patch

from systemscan.core.dependencies import (
    DependencyRegistry,
    DependencySpec,
    DependencyType,
    EnvironmentDoctor,
    ExternalToolInspector,
    SafeDependencyInstaller,
)


def test_dependency_registry_basics() -> None:
    reg = DependencyRegistry()

    # Core dependencies registered
    typer_spec = reg.get_spec("typer")
    assert typer_spec is not None
    assert typer_spec.category in (DependencyType.REQUIRED, DependencyType.CORE)

    pytest_spec = reg.get_spec("pytest")
    assert pytest_spec is not None
    assert pytest_spec.category == DependencyType.DEV

    # Inspection
    status = reg.check_dependency(typer_spec)
    assert status.is_installed is True
    assert status.is_compatible is True

    # Verification of all required
    ok, missing = reg.verify_required()
    assert ok is True
    assert len(missing) == 0


def test_missing_dependency_reporting() -> None:
    reg = DependencyRegistry()
    fake_spec = DependencySpec(
        name="nonexistent_pkg_xyz_12345",
        min_version="1.0.0",
        category=DependencyType.REQUIRED,
    )
    reg.register(fake_spec)

    status = reg.check_dependency(fake_spec)
    assert status.is_installed is False
    assert status.is_compatible is False
    assert "Missing" in status.status_message


def test_incompatible_version_detection() -> None:
    reg = DependencyRegistry()
    # Pydantic is installed at ~2.14, require 99.0.0 to trigger incompatible version
    high_spec = DependencySpec(
        name="pydantic",
        min_version="99.0.0",
        category=DependencyType.REQUIRED,
    )
    st = reg.check_dependency(high_spec)
    assert st.is_installed is True
    assert st.is_compatible is False
    assert "Incompatible" in st.status_message

    # Test max version limit
    low_max_spec = DependencySpec(
        name="pydantic",
        min_version="1.0.0",
        max_version="1.5.0",
        category=DependencyType.REQUIRED,
    )
    st_max = reg.check_dependency(low_max_spec)
    assert st_max.is_installed is True
    assert st_max.is_compatible is False
    assert "allowed max" in st_max.status_message


def test_environment_info() -> None:
    reg = DependencyRegistry()
    info = reg.get_python_environment_info()
    assert "python_version" in info
    assert "executable" in info
    assert "is_venv" in info


def test_external_tool_inspector() -> None:
    # Test inspecting registered tools
    statuses = ExternalToolInspector.inspect_all()
    assert len(statuses) > 0
    tool_names = [s.name for s in statuses]
    assert "nmap" in tool_names
    assert "powershell" in tool_names or "pwsh" in tool_names

    # Test non-existent tool
    dummy = ExternalToolInspector.inspect_tool("totally_fake_tool_xyz_99")
    assert dummy.is_installed is False
    assert dummy.executable_path is None


def test_safe_dependency_installer_sanitization() -> None:
    # Injection prevention
    bad_specs = [
        "requests; rm -rf /",
        "requests && whoami",
        "requests | bash",
        "requests\nls",
        "requests`id`",
    ]
    for bad in bad_specs:
        ok, msg = SafeDependencyInstaller.install_package(bad)
        assert ok is False
        assert "Rejected unsafe package specification" in msg


def test_safe_dependency_installer_global_guard() -> None:
    with patch.object(SafeDependencyInstaller, "is_in_virtualenv", return_value=False):
        ok, msg = SafeDependencyInstaller.install_package("requests", allow_global=False)
        assert ok is False
        assert "Refusing to install into global/system Python" in msg

        # With allow_global=True and dry_run=True, should simulate command
        ok_dry, msg_dry = SafeDependencyInstaller.install_package(
            "requests", allow_global=True, dry_run=True
        )
        assert ok_dry is True
        assert "[DRY-RUN]" in msg_dry


def test_safe_dependency_installer_dry_run() -> None:
    with patch.object(SafeDependencyInstaller, "is_in_virtualenv", return_value=True):
        ok, msg = SafeDependencyInstaller.install_package(
            "pytest>=8.0.0", dry_run=True, index_url="https://pypi.org/simple"
        )
        assert ok is True
        assert "[DRY-RUN] Would execute:" in msg
        assert "pytest>=8.0.0" in msg
        assert "--index-url https://pypi.org/simple" in msg


def test_environment_doctor_diagnosis() -> None:
    doctor = EnvironmentDoctor()
    diag = doctor.diagnose()

    assert diag.status in ("HEALTHY", "WARNING", "CRITICAL")
    assert diag.python_version_ok is True
    assert diag.is_64bit in (True, False)
    assert len(diag.core_dependencies) > 0
    assert len(diag.writable_dirs) >= 6
    assert all(d["writable"] for d in diag.writable_dirs)
