"""Dependency registry, compatibility verification, external tool inspection, and environment diagnostics."""

from __future__ import annotations

import importlib.metadata
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from packaging.version import InvalidVersion, Version

from systemscan.logging.logger import get_logger
from systemscan.utils.paths import AppPaths

logger = get_logger("core.dependencies")


class DependencyType(str, Enum):
    """Categorization of dependency necessity and origin."""

    CORE = "core"
    REQUIRED = "core"  # Backward compatibility alias
    OPTIONAL = "optional"
    PLATFORM_SPECIFIC = "platform_specific"
    DEV = "dev"
    DEVELOPMENT = "dev"  # Alias
    EXTERNAL_TOOL = "external_tool"


@dataclass(frozen=True)
class DependencySpec:
    """Specification of an external package or system tool dependency."""

    name: str
    min_version: str | None = None
    max_version: str | None = None
    description: str = ""
    category: DependencyType = DependencyType.CORE
    purpose: str = ""
    target_module: str | None = None
    platforms: tuple[str, ...] = ("linux", "windows", "darwin")
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def dependency_type(self) -> DependencyType:
        return self.category

    @property
    def spec_version(self) -> str | None:
        if self.min_version and self.max_version:
            return f">={self.min_version},<={self.max_version}"
        if self.min_version:
            return f">={self.min_version}"
        return None


@dataclass(frozen=True)
class DependencyStatus:
    """Runtime status of a registered dependency."""

    spec: DependencySpec
    is_installed: bool
    installed_version: str | None
    is_compatible: bool
    status_message: str

    @property
    def installed(self) -> bool:
        return self.is_installed

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def dependency_type(self) -> DependencyType:
        return self.spec.category

    @property
    def spec_version(self) -> str | None:
        if self.spec.min_version and self.spec.max_version:
            return f">={self.spec.min_version},<={self.spec.max_version}"
        if self.spec.min_version:
            return f">={self.spec.min_version}"
        return None


@dataclass(frozen=True)
class ExternalToolStatus:
    """Runtime availability and version telemetry of an external CLI binary."""

    name: str
    is_installed: bool
    executable_path: str | None
    version: str | None
    is_compatible: bool
    status_message: str

    @property
    def available(self) -> bool:
        return self.is_installed

    @property
    def category(self) -> str:
        return "Security / System"


class ExternalToolInspector:
    """Discovers and safely verifies optional system binaries and external security tools."""

    TOOLS_CONFIG: dict[str, dict[str, Any]] = {
        "nmap": {
            "version_args": ["--version"],
            "version_prefix": "Nmap version",
            "platforms": ("linux", "windows", "darwin"),
        },
        "yara": {
            "version_args": ["--version"],
            "platforms": ("linux", "windows", "darwin"),
        },
        "ufw": {
            "version_args": ["--version"],
            "platforms": ("linux",),
        },
        "nft": {
            "version_args": ["--version"],
            "platforms": ("linux",),
        },
        "iptables": {
            "version_args": ["--version"],
            "platforms": ("linux",),
        },
        "powershell": {
            "version_args": ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
            "platforms": ("windows",),
        },
        "pwsh": {
            "version_args": ["--version"],
            "platforms": ("linux", "darwin", "windows"),
        },
    }

    @classmethod
    def inspect_tool(cls, name: str) -> ExternalToolStatus:
        """Safely probe for the presence and version of an external command-line tool."""
        exe_path = shutil.which(name)
        if not exe_path:
            return ExternalToolStatus(
                name=name,
                is_installed=False,
                executable_path=None,
                version=None,
                is_compatible=False,
                status_message=f"Executable '{name}' was not found in PATH.",
            )

        cfg = cls.TOOLS_CONFIG.get(name.lower(), {"version_args": ["--version"]})
        version_str: str | None = None

        try:
            cmd = [exe_path] + cfg.get("version_args", ["--version"])
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            raw_out = (res.stdout or res.stderr or "").strip()
            if raw_out:
                first_line = raw_out.splitlines()[0]
                version_str = first_line[:60]
        except (subprocess.TimeoutExpired, PermissionError, OSError) as e:
            logger.debug(f"Tool version probe failed for '{name}': {e}")
            version_str = "Present (version probe timed out or restricted)"

        return ExternalToolStatus(
            name=name,
            is_installed=True,
            executable_path=exe_path,
            version=version_str,
            is_compatible=True,
            status_message=f"Detected at {exe_path}" + (f" ({version_str})" if version_str else ""),
        )

    @classmethod
    def inspect_all(cls) -> list[ExternalToolStatus]:
        """Inspect all registered external system utilities."""
        current_platform = sys.platform.lower()
        results: list[ExternalToolStatus] = []

        for name, cfg in cls.TOOLS_CONFIG.items():
            plats = cfg.get("platforms", ("linux", "windows", "darwin"))
            # Match platform prefix (e.g. win32 matches windows, darwin matches darwin, linux matches linux)
            matched = any(
                p in current_platform or (p == "windows" and "win" in current_platform)
                for p in plats
            )
            if matched:
                results.append(cls.inspect_tool(name))

        return results


class SafeDependencyInstaller:
    """Manages secure installation of required or optional Python packages inside active virtual environments."""

    @staticmethod
    def is_in_virtualenv() -> bool:
        """Return True if executing within a Python virtual environment."""
        return sys.prefix != getattr(sys, "base_prefix", sys.prefix) or bool(
            os.environ.get("VIRTUAL_ENV")
        )

    @classmethod
    def install_package(
        cls,
        package_spec: str,
        dry_run: bool = False,
        allow_global: bool = False,
        index_url: str | None = None,
    ) -> tuple[bool, str]:
        """Install a package into the active environment using isolated subprocess calls.

        Guarantees:
        - Never installs into global system Python by default without allow_global=True.
        - Verifies installed version after execution.
        """
        if not cls.is_in_virtualenv() and not allow_global:
            msg = (
                "Refusing to install into global/system Python environment. "
                "Activate a virtual environment or explicitly permit global installation."
            )
            logger.warning(msg)
            return False, msg

        clean_spec = package_spec.strip()
        # Security sanitization: reject command injection tokens (ADR-025)
        if any(c in clean_spec for c in (";", "&", "|", "`", "$", "\n", "\r", "(", ")")):
            return False, f"Rejected unsafe package specification: '{package_spec}'."

        cmd = [sys.executable, "-m", "pip", "install", clean_spec]
        if index_url:
            cmd.extend(["--index-url", index_url])

        if dry_run:
            return True, f"[DRY-RUN] Would execute: {' '.join(cmd)}"

        try:
            logger.info(f"Executing dependency installation: {' '.join(cmd)}")
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120.0,
                check=False,
            )
            if res.returncode == 0:
                return True, f"Successfully installed '{clean_spec}'."
            err_msg = res.stderr.strip() or res.stdout.strip()
            return False, f"pip install failed (code {res.returncode}): {err_msg}"
        except Exception as e:
            return False, f"Dependency installation error: {e}"


@dataclass
class DoctorDiagnosis:
    """Holistic health diagnosis covering environment, paths, dependencies, and tools."""

    status: str  # HEALTHY, WARNING, CRITICAL
    python_version: str
    is_virtualenv: bool
    platform_info: str
    writable_paths: dict[str, bool]
    core_dependencies: list[DependencyStatus]
    optional_dependencies: list[DependencyStatus]
    external_tools: list[ExternalToolStatus]
    remediation_steps: list[str]

    @property
    def python_version_ok(self) -> bool:
        return sys.version_info >= (3, 10)

    @property
    def is_64bit(self) -> bool:
        return sys.maxsize > 2**32

    @property
    def virtualenv_path(self) -> str | None:
        if self.is_virtualenv:
            return sys.prefix
        return None

    @property
    def executable_path(self) -> str:
        return sys.executable

    @property
    def writable_dirs(self) -> list[dict[str, Any]]:
        return [{"name": k, "writable": v, "path": k} for k, v in self.writable_paths.items()]

    @property
    def dependencies(self) -> list[DependencyStatus]:
        return self.core_dependencies + self.optional_dependencies

    @property
    def overall_health(self) -> str:
        return self.status.lower()

    @property
    def recommendations(self) -> list[str]:
        return self.remediation_steps


class EnvironmentDoctor:
    """Diagnoses host environment, filesystem permissions, dependency integrity, and tool availability."""

    @classmethod
    def diagnose(cls, verbose: bool = False) -> DoctorDiagnosis:
        """Execute a comprehensive environment diagnostic check."""
        paths = AppPaths()

        # Check directories writable
        dir_checks: dict[str, bool] = {}
        for name, p in [
            ("config_dir", paths.config_dir),
            ("data_dir", paths.data_dir),
            ("cache_dir", paths.cache_dir),
            ("log_dir", paths.log_dir),
            ("report_dir", paths.report_dir),
            ("backup_dir", paths.backup_dir),
        ]:
            try:
                p.mkdir(parents=True, exist_ok=True)
                test_f = p / ".write_test"
                test_f.write_text("ok", encoding="utf-8")
                test_f.unlink()
                dir_checks[name] = True
            except Exception:
                dir_checks[name] = False

        # Dependency inspections
        core_statuses = dependency_registry.inspect_all(DependencyType.CORE)
        opt_statuses = dependency_registry.inspect_all(DependencyType.OPTIONAL)
        ext_statuses = ExternalToolInspector.inspect_all()

        remediations: list[str] = []
        overall_status = "HEALTHY"

        # Check Python version
        py_ver = sys.version.split()[0]
        if sys.version_info < (3, 10):  # noqa: UP036
            overall_status = "CRITICAL"
            remediations.append("Python 3.10+ is required. Upgrade system Python.")

        # Check core dependencies
        for s in core_statuses:
            if not s.is_installed or not s.is_compatible:
                overall_status = "CRITICAL"
                remediations.append(f"Install required dependency: pip install '{s.spec.name}'")

        # Check writable directories
        for name, ok in dir_checks.items():
            if not ok:
                if overall_status != "CRITICAL":
                    overall_status = "WARNING"
                remediations.append(f"Ensure write permissions for directory: {name}")

        # Check virtualenv recommendation
        is_venv = SafeDependencyInstaller.is_in_virtualenv()
        if not is_venv and overall_status == "HEALTHY":
            remediations.append(
                "Running outside a virtual environment. Recommended: create and activate a venv."
            )

        return DoctorDiagnosis(
            status=overall_status,
            python_version=py_ver,
            is_virtualenv=is_venv,
            platform_info=f"{sys.platform} ({sys.version.split()[0]})",
            writable_paths=dir_checks,
            core_dependencies=core_statuses,
            optional_dependencies=opt_statuses,
            external_tools=ext_statuses,
            remediation_steps=remediations,
        )


class DependencyRegistry:
    """Central registry and verification engine for systemscan dependencies."""

    def __init__(self) -> None:
        self._registry: dict[str, DependencySpec] = {}
        self._register_foundation_dependencies()

    def _register_foundation_dependencies(self) -> None:
        """Register Phase 1 through Phase 10 dependencies."""
        # Core Foundation Dependencies
        self.register(
            DependencySpec(
                name="typer",
                min_version="0.12.0",
                description="Modern CLI framework",
                category=DependencyType.CORE,
                purpose="Command line parsing and option handling",
            )
        )
        self.register(
            DependencySpec(
                name="rich",
                min_version="13.7.0",
                description="Terminal formatting and UI",
                category=DependencyType.CORE,
                purpose="Tables, panels, banners, and status rendering",
            )
        )
        self.register(
            DependencySpec(
                name="pydantic",
                min_version="2.6.0",
                description="Data validation and settings",
                category=DependencyType.CORE,
                purpose="Configuration schema definition and validation",
            )
        )
        self.register(
            DependencySpec(
                name="platformdirs",
                min_version="4.2.0",
                description="Cross-platform directory resolution",
                category=DependencyType.CORE,
                purpose="XDG, Windows AppData, and macOS path resolution",
            )
        )
        self.register(
            DependencySpec(
                name="psutil",
                min_version="5.9.0",
                description="Cross-platform process and system monitoring",
                category=DependencyType.CORE,
                purpose="Hardware telemetry, processes, memory, and storage inspection",
            )
        )
        self.register(
            DependencySpec(
                name="py-cpuinfo",
                min_version="9.0.0",
                description="CPU hardware information retrieval",
                category=DependencyType.CORE,
                purpose="Detailed CPU vendor, model, and instruction set discovery",
            )
        )

        # Optional Feature Dependencies
        self.register(
            DependencySpec(
                name="dnspython",
                min_version="2.6.0",
                description="DNS toolkit for Python",
                category=DependencyType.OPTIONAL,
                purpose="Richer DNS record inspection (MX, NS, TXT, CNAME)",
                target_module="network.dns",
            )
        )
        self.register(
            DependencySpec(
                name="python-nmap",
                min_version="0.7.1",
                description="Python wrapper for Nmap",
                category=DependencyType.OPTIONAL,
                purpose="Optional Nmap host and port scanning integration",
                target_module="network.discovery",
            )
        )
        self.register(
            DependencySpec(
                name="scapy",
                min_version="2.5.0",
                description="Packet manipulation tool",
                category=DependencyType.OPTIONAL,
                purpose="Advanced authorized network packet diagnostics",
                target_module="network.diagnostics",
            )
        )
        self.register(
            DependencySpec(
                name="yara-python",
                min_version="4.3.0",
                description="Pattern matching swiss knife for malware researchers",
                category=DependencyType.OPTIONAL,
                purpose="YARA rule compilation and byte signature scanning",
                target_module="malware.yara",
            )
        )

        # Development dependencies
        self.register(
            DependencySpec(
                name="pytest",
                min_version="8.0.0",
                description="Testing framework",
                category=DependencyType.DEV,
                purpose="Automated unit and integration testing",
            )
        )
        self.register(
            DependencySpec(
                name="ruff",
                min_version="0.4.0",
                description="Fast Python linter and formatter",
                category=DependencyType.DEV,
                purpose="Code quality and lint enforcement",
            )
        )
        self.register(
            DependencySpec(
                name="mypy",
                min_version="1.9.0",
                description="Static type checker",
                category=DependencyType.DEV,
                purpose="Type validation across the codebase",
            )
        )

    def register(self, spec: DependencySpec) -> None:
        """Register a new dependency specification."""
        self._registry[spec.name.lower()] = spec

    def get_spec(self, name: str) -> DependencySpec | None:
        """Retrieve a dependency specification by package name."""
        return self._registry.get(name.lower())

    def list_all(self, category: DependencyType | None = None) -> list[DependencySpec]:
        """List registered dependencies, optionally filtered by category."""
        if category is None:
            return list(self._registry.values())
        return [s for s in self._registry.values() if s.category == category]

    def check_dependency(self, spec: DependencySpec) -> DependencyStatus:
        """Inspect runtime presence and compatibility of a single dependency using importlib.metadata."""
        try:
            installed_ver = importlib.metadata.version(spec.name)
            is_installed = True
        except importlib.metadata.PackageNotFoundError:
            return DependencyStatus(
                spec=spec,
                is_installed=False,
                installed_version=None,
                is_compatible=False,
                status_message=f"Missing: package '{spec.name}' is not installed.",
            )

        # Version compatibility check
        is_compatible = True
        msg = f"Installed ({installed_ver})"

        if spec.min_version:
            try:
                curr_v = Version(installed_ver)
                req_v = Version(spec.min_version)
                if curr_v < req_v:
                    is_compatible = False
                    msg = f"Incompatible: {installed_ver} < required min {spec.min_version}"
            except InvalidVersion:
                msg = f"Installed ({installed_ver}) - Non-standard version format"

        if is_compatible and spec.max_version:
            try:
                curr_v = Version(installed_ver)
                max_v = Version(spec.max_version)
                if curr_v > max_v:
                    is_compatible = False
                    msg = f"Incompatible: {installed_ver} > allowed max {spec.max_version}"
            except InvalidVersion:
                pass

        return DependencyStatus(
            spec=spec,
            is_installed=is_installed,
            installed_version=installed_ver,
            is_compatible=is_compatible,
            status_message=msg,
        )

    def inspect_all(self, category: DependencyType | None = None) -> list[DependencyStatus]:
        """Inspect all registered dependencies."""
        specs = self.list_all(category)
        return [self.check_dependency(spec) for spec in specs]

    def verify_required(self) -> tuple[bool, list[DependencyStatus]]:
        """Verify that all CORE dependencies are installed and compatible."""
        core_specs = self.list_all(DependencyType.CORE)
        failures: list[DependencyStatus] = []

        for spec in core_specs:
            status = self.check_dependency(spec)
            if not status.is_installed or not status.is_compatible:
                failures.append(status)

        return (len(failures) == 0, failures)

    def get_python_environment_info(self) -> dict[str, str]:
        """Return system Python environment information."""
        return {
            "python_version": sys.version.split()[0],
            "executable": sys.executable,
            "prefix": sys.prefix,
            "base_prefix": getattr(sys, "base_prefix", sys.prefix),
            "is_venv": str(SafeDependencyInstaller.is_in_virtualenv()),
        }

    @classmethod
    def get_all_specs(cls) -> list[DependencySpec]:
        """Classmethod accessing the global registry's registered specs."""
        return dependency_registry.list_all()

    @classmethod
    def get_optional_specs(cls) -> list[DependencySpec]:
        """Classmethod accessing the global registry's optional specs."""
        return dependency_registry.list_all(DependencyType.OPTIONAL)

    @classmethod
    def check_installed(cls, name: str) -> tuple[bool, str | None]:
        """Classmethod checking if a dependency is installed."""
        spec = dependency_registry.get_spec(name)
        if not spec:
            return False, None
        status = dependency_registry.check_dependency(spec)
        return status.is_installed, status.installed_version

    @classmethod
    def is_compatible(cls, name: str) -> bool:
        """Classmethod checking if a dependency meets compatibility constraints."""
        spec = dependency_registry.get_spec(name)
        if not spec:
            return False
        status = dependency_registry.check_dependency(spec)
        return status.is_compatible

    @classmethod
    def verify_all(cls) -> tuple[list[DependencySpec], list[DependencySpec]]:
        """Classmethod inspecting all registered dependencies, returning (missing, incompatible)."""
        missing: list[DependencySpec] = []
        incompatible: list[DependencySpec] = []
        for spec in dependency_registry.list_all():
            status = dependency_registry.check_dependency(spec)
            if not status.is_installed:
                missing.append(spec)
            elif not status.is_compatible:
                incompatible.append(spec)
        return missing, incompatible


# Global registry singleton
dependency_registry = DependencyRegistry()
