# Dependency Management Architecture

## 1. Overview
The Universal System Security & Intelligence CLI (`systemscan`) integrates a deterministic, sandboxed Dependency Management Subsystem designed to discover, classify, inspect, verify, and safely install required and optional Python packages and external system binaries across Linux, macOS, and Windows.

## 2. Dependency Classification Hierarchy

All application dependencies are strictly classified under `systemscan.core.dependencies.DependencyType`:

| Classification | Purpose | Enforcement Level | Example Packages / Binaries |
| :--- | :--- | :--- | :--- |
| **`CORE` / `REQUIRED`** | Essential framework, configuration, and foundational engines | Mandatory; application fails fast with diagnostic report if missing or incompatible | `typer`, `rich`, `pydantic`, `platformdirs`, `psutil`, `py-cpuinfo` |
| **`OPTIONAL`** | Extended forensic, signature, and network inspection capabilities | Dynamic runtime detection; gracefully degrades features if absent | `yara-python`, `scapy`, `python-nmap`, `dnspython` |
| **`DEV` / `DEVELOPMENT`** | Quality gates, static analysis, and test suites | Developer environments only | `pytest`, `pytest-cov`, `ruff`, `mypy` |
| **`PLATFORM_SPECIFIC`** | Platform-specialized providers (WMI, Netlink, IOKit) | Activated only when host OS matches target platforms | Windows WMI / Netlink extensions |
| **`EXTERNAL_TOOL`** | Host CLI binaries for deep security assessment | External path probing with sanitized execution and timeout guards | `nmap`, `yara`, `ufw`, `nft`, `iptables`, `powershell`, `pwsh` |

## 3. Safe Dependency Installer (`SafeDependencyInstaller`)

The installer protects host operating systems and system Python environments:

- **Virtual Environment Isolation Guard**: Automatically detects whether execution is occurring inside a virtual environment (`sys.prefix != sys.base_prefix` or `VIRTUAL_ENV` environment variable). Refuses to install into global system Python unless the user explicitly passes `--allow-global`.
- **Command Injection Prevention**: Sanitizes package specifications, immediately rejecting malicious tokens (`;`, `&`, `|`, `` ` ``, `$`, `\n`, `\r`, `(`, `)`).
- **Subprocess Isolation**: Runs `[sys.executable, "-m", "pip", "install", clean_spec]` without invoking a shell (`shell=False`), enforcing strict execution boundaries and timeouts.
- **Dry-Run Capability**: Computes and prints the exact execution command without altering filesystem state when `--dry-run` is requested.

## 4. Environment Doctor (`EnvironmentDoctor`)

The `systemscan doctor` diagnostic tool performs an exhaustive, non-destructive audit:
1. **Runtime Verification**: Inspects Python version (asserting `>= 3.10`), architecture bitness (64-bit), and interpreter path.
2. **Virtual Environment Telemetry**: Validates whether virtualenv is active and reports its root location.
3. **App Storage Writability**: Tests write access to `config_dir`, `data_dir`, `cache_dir`, `log_dir`, `report_dir`, and `backup_dir`.
4. **Package Compatibility Matrix**: Queries `importlib.metadata` for installed versions against registered `DependencySpec` constraints (`min_version`, `max_version`).
5. **External Tool Discovery**: Probes `shutil.which` paths and executes `--version` probes with 2.0s timeouts to verify tool availability and version signatures.
6. **Actionable Remediation**: Generates step-by-step guidance to resolve any degraded or unhealthy conditions.

## 5. CLI Commands

```bash
# Comprehensive environment health audit
systemscan doctor
systemscan doctor --verbose

# Inspect registered dependencies
systemscan dependencies list
systemscan dependencies list --category optional

# Check for missing or incompatible packages
systemscan dependencies check
systemscan dependencies missing
systemscan dependencies verify

# Safely install optional extensions into active virtual environment
systemscan dependencies install yara-python
systemscan dependencies install --all-optional --dry-run
```

