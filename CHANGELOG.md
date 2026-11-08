# Changelog

All notable changes to the **Universal System Security & Intelligence CLI** (`systemscan`) project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-08

### Added
- **Phase 01: Project Foundation & Architecture**:
  - Standards-compliant packaging via Hatchling (`pyproject.toml`) and console scripts (`systemscan`, `python -m systemscan`).
  - Application lifecycle management with signal trapping (SIGINT/SIGTERM) and clean state transitions.
  - Interactive terminal menu and Typer non-interactive commands.
  - Centralized path resolution (`PlatformDirs`) and Pydantic configuration manager.
  - Structured file logging with rotation (5 MB, 5 backups) and credential scrubbing.
- **Phase 02: Hardware & System Intelligence Module**:
  - Comprehensive host discovery: OS distribution parser (`/etc/os-release`), kernel, uptime, shell, CPU cores/frequencies, memory/swap, GPU, motherboard/BIOS.
  - Sub-second process inspection, background service enumeration (systemd, Windows SCM, launchd), and startup boot persistence discovery.
  - Real-time terminal telemetry monitor (`systemscan monitor`) with live Rich dashboard.
- **Phase 03: Universal Filesystem Traversal Engine**:
  - Recursive iterative traversal via bounded deque stack, eliminating recursion depth limits and memory bloat.
  - Non-invasive file type identification, hidden file discovery, and strict symlink safety (`follow_symlinks=False` default).
  - Exclusions engine (globs, extensions, directories, OS safety defaults).
- **Phase 04: USB, Removable Storage & Device Monitoring**:
  - Removable storage classification and device inventory.
  - Real-time USB plug/unplug event monitor and active scan triggers.
- **Phase 05: Malware & Virus Detection Engine**:
  - Streaming SHA-256 matching against threat signature databases.
  - PE header static analysis (suspicious sections, anomalous entry points).
  - Shannon entropy heuristic analysis for packed binary detection.
  - Non-destructive, isolated quarantine management (`systemscan malware quarantine`).
- **Phase 06: Storage Analyzer, Cache Scanner & Safe Cleanup Engine**:
  - Filesystem disk usage, large file discovery, duplicate file detection, and extension analysis.
  - Browser and package manager cache scanners.
  - Safe cleanup workflow with mandatory preview assignment and human `--confirm` parameter.
- **Phase 07: Network Security Audit & Network Intelligence Engine**:
  - Network interface telemetry (IPv4, IPv6, MAC, subnet, gateway, DNS).
  - Listening port and active connection correlation to processes.
  - Bounded local subnet discovery (ARP + ping/TCP probe).
  - Read-only firewall audit (Windows Defender Firewall, UFW/nftables, macOS socketfilterfw).
  - Wi-Fi protocol inspection and network baseline drift detection.
- **Phase 08: Scan Intelligence & Performance Engine**:
  - Central scan orchestrator with standardized scan lifecycle state machine.
  - Adaptive concurrency manager scaling threads by physical cores, CPU/memory pressure, and battery state.
  - Dynamic ETA engine with Exponential Moving Average rate smoothing.
  - Incremental scanning metadata cache and fault-tolerant atomic checkpoints.
  - Pause, resume, and cancellation tokens.
- **Phase 09: Reporting & Export Engine**:
  - Unified `ScanReport` schema (v1.0) with finding severity and confidence calibration.
  - Multi-format exporters for UTF-8 JSON, multi-table CSV, and plain text.
  - Technical, Executive, and Compact reporting templates.
  - Immutable privacy redaction for usernames, paths, internal IPs, MACs, and secrets.
  - SHA-256 cryptographic manifest generation (`<report>.sha256`) and verification.
- **Phase 10: Dependency Manager & Application Self-Update System**:
  - Dependency governance typology (`CORE`, `REQUIRED`, `OPTIONAL`, `DEV`, `PLATFORM_SPECIFIC`, `EXTERNAL_TOOL`).
  - Environment Doctor (`systemscan doctor`) auditing runtime, venv, directory permissions, and external tools.
  - Safe dependency installer with virtualenv isolation enforcement and command injection sanitization.
  - 10-stage atomic self-update state machine with automated snapshot backup and rollback.
  - Configuration schema migration manager.
- **Phase 11: Production QA, Security Audit & Cross-Platform Hardening**:
  - 10 dedicated automated security regression tests (`tests/unit/test_security_hardening.py`).
  - Automated 12-runner GitHub Actions CI matrix across Ubuntu, Windows, and macOS on Python 3.10–3.13.
  - Empirical performance benchmarking harness (`scripts/benchmark_audit.py`).
  - Comprehensive documentation: `THREAT_MODEL.md`, `SECURITY_AUDIT.md`, `COMPATIBILITY.md`, `TESTING.md`, `PERFORMANCE_AUDIT.md`, `KNOWN_LIMITATIONS.md`.
- **Phase 12: Documentation, Setup Guides, Packaging & Release Preparation**:
  - Platform installation guides: `docs/INSTALLATION.md` for Linux, Windows, and macOS.
  - One-command safe installer scripts: `scripts/install.sh` and `scripts/install.ps1`.
  - Safe uninstallation scripts and CLI command (`systemscan uninstall` and `systemscan uninstall --remove-data`) with user data preservation by default.
  - Comprehensive `docs/CLI_REFERENCE.md`, `docs/CONFIGURATION.md`, `docs/TROUBLESHOOTING.md`, `docs/FAQ.md`, and `docs/STANDALONE_EXECUTABLES.md`.
  - Community governance: `CODE_OF_CONDUCT.md`, `SECURITY.md`, `.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`.
  - Release automation workflow: `.github/workflows/release.yml`.
  - Example configurations and sample export reports in `examples/`.
- **Phase 13: Final Integration, Production Acceptance & GitHub Readiness**:
  - Unified multi-engine scan orchestration within `CentralScanOrchestrator` linking Filesystem, Malware, Storage, Network, Devices, History, and Reporting.
  - End-to-end integration test suite (`tests/integration/test_phase13_full_integration.py`) validating the full workflow, modular isolation, and cooperative pause/resume lifecycle.
  - Added compatibility alias property `ScanReport.system_summary` pointing to `system_info`.
  - Automated report generation with SHA-256 checksum manifest creation upon scan completion.
  - Reset of scan lifecycle state on repeated orchestrator sessions to support concurrent and consecutive scans.
  - Rigorous empirical performance audit: 951.1 MB/s SHA-256 hashing, 5,788 items/s filesystem traversal, 0.77 ms checkpoint latency, and 2.27 MB memory footprint delta.
  - Complete project sign-off and production acceptance documented in `docs/FINAL_ACCEPTANCE_REPORT.md` (Verdicts: `PRODUCTION READY WITH DOCUMENTED LIMITATIONS`).

### Fixed
- Fixed archive extraction vulnerability by verifying all member paths resolve within canonical destination directory, eliminating zip-slip risks (SEC-01).
- Fixed potential symlink traversal attack vector in quarantine and file crawler engines (SEC-02).
- Fixed cleanup TOCTOU race condition by verifying candidate file modification time immediately prior to deletion (SEC-03).
- Fixed Rich console formatting leaking into stdout during `--format json` calls by directing logging exclusively to `stderr` (SEC-09).
- Fixed missing package `__init__.py` files in submodules preventing clean distribution wheel generation.
- Fixed root `.gitignore` pattern anchoring (`/quarantine/`, `/reports/`, `/logs/`) preventing package directory omission during builds.

### Security
- Enforced `shell=False` exclusively across all platform and update subprocess invocations.
- Enforced CIDR boundary clamping (/24 maximum) on network discovery probes to prevent accidental DoS flooding.
- Enforced virtual environment isolation guard prohibiting global system Python package installations without explicit override.
