# System Architecture & Technical Design

**Universal System Security & Intelligence CLI (`systemscan`)**

---

## 1. Architectural Vision & Principles

`systemscan` is designed as a modular, extensible, and cross-platform security and system diagnostics utility. The architectural foundation established in Phase 1 adheres to the following core tenets:

1. **Decoupled Platform Abstraction**: Operating system-specific behaviors are isolated behind the `PlatformInterface` contract, preventing platform conditions (`if os == 'windows'`) from scattering across domain logic.
2. **Defensive Configuration Management**: Configuration state is stored outside source repositories using platform conventions (XDG on Linux, `%APPDATA%` on Windows, Application Support on macOS). Schema validation via Pydantic prevents silent corruption, and atomic file operations protect against write aborts.
3. **Structured & Sanitized Diagnostics**: Centralized logging combines human-friendly, colored console alerts with rotating timestamped diagnostic files. Automatic credential scrubbers sanitize secrets, tokens, and passwords.
4. **Resilient Lifecycle Governance**: State transitions from initialization to termination are managed deterministically. Signal handlers catch interruptions (`Ctrl+C`, `SIGTERM`) and trigger ordered resource cleanups.
5. **No Blind Global Mutability**: Operations default to non-invasive, non-elevated read-only scans. Unprivileged execution is fully supported.

---

## 2. High-Level System Architecture

```
                          ┌───────────────────────────┐
                          │   CLI Entrypoint (Typer)  │
                          │   systemscan / python -m  │
                          └─────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   Application Coordinator  │
                         │   (Bootstrap & Lifecycle)  │
                         └──────┬───────────────┬─────┘
                                │               │
        ┌───────────────────────┼───────────────┼────────────────────────┐
        │                       │               │                        │
┌───────▼────────┐      ┌───────▼────────┐ ┌────▼───────────┐    ┌───────▼────────┐
│ Configuration  │      │ Logging Engine │ │ Path Resolver  │    │ Platform Engine│
│ (Pydantic/JSON)│      │ (Rich/Rotating)│ │ (PlatformDirs) │    │(Win/Linux/Mac) │
└────────────────┘      └────────────────┘ └────────────────┘    └────────────────┘
        │                       │               │                        │
        └───────────────────────┴───────┬───────┴────────────────────────┘
                                        │
                       ┌────────────────▼────────────────┐
                       │    Domain Subsystems (Phases)   │
                       │ ┌─────────────────────────────┐ │
                       │ │ Hardware / Sys Intelligence │ │ (Phase 02)
                       │ │ OS & Kernel Security        │ │ (Phase 03)
                       │ │ Process & Memory Inspection │ │ (Phase 04)
                       │ │ Network & Port Intelligence │ │ (Phase 05)
                       │ │ File Integrity / Malware    │ │ (Phase 06)
                       │ │ User & Access Security      │ │ (Phase 07)
                       │ │ Compliance Engine           │ │ (Phase 08)
                       │ │ Reporting Subsystem         │ │ (Phase 09)
                       │ └─────────────────────────────┘ │
                       └─────────────────────────────────┘
```

---

## 3. Package Structure

```
systemscan/
├── pyproject.toml              # Build metadata, entry points, dependencies & tool configs
├── src/
│   └── systemscan/
│       ├── __init__.py         # Package namespace root & semantic version exports
│       ├── __main__.py         # python -m systemscan direct execution entrypoint
│       ├── app.py              # Application factory facade
│       ├── version.py          # Centralized version and naming definitions
│       │
│       ├── core/               # Core framework engine
│       │   ├── __init__.py     # Core namespace with lazy module loading
│       │   ├── application.py  # Application bootstrap container and safe executor
│       │   ├── constants.py    # Standardized ExitCode, UpdateChannel, LogLevel enums
│       │   ├── dependencies.py # Dependency registry, version checker & verifier
│       │   ├── error_handler.py# Centralized exception classifier & rich renderer
│       │   ├── exceptions.py   # Hierarchical domain exception tree
│       │   └── lifecycle.py    # Finite state machine and signal trap manager
│       │
│       ├── config/             # Centralized configuration management
│       │   ├── __init__.py     # Config exports
│       │   ├── defaults.py     # Default configuration templates
│       │   ├── manager.py      # JSON persistence, atomic write, backup & reset
│       │   ├── schema.py       # Pydantic models for preferences, scanner, update
│       │   └── validator.py    # Strict schema validation engine
│       │
│       ├── logging/            # Centralized logging engine
│       │   ├── __init__.py     # Logging exports
│       │   ├── formatter.py    # ISO8601 file formatter & credential scrubber
│       │   └── logger.py       # Rotating file handler & Rich console handler
│       │
│       ├── cli/                # Terminal user interface & commands
│       │   ├── __init__.py     # Typer application root & console main()
│       │   ├── banner.py       # Dynamic ASCII/Rich system banner
│       │   ├── display.py      # Reusable UI components, tables, and notices
│       │   ├── menu.py         # Interactive terminal navigation loop (11 options)
│       │   └── commands/       # Modular command implementations
│       │       ├── __init__.py
│       │       ├── config.py   # show, path, validate, backup, reset
│       │       ├── hardware.py # cpu, memory, gpu, storage, firmware, devices
│       │       ├── info.py     # System intelligence overview & diagnostics
│       │       ├── monitor.py  # Real-time visual performance monitor
│       │       ├── processes.py# Process table inspection & sorting
│       │       ├── reports.py  # Report directory inspector
│       │       ├── scan.py     # Future scanner roadmap placeholder
│       │       ├── services.py # Host background services & daemons
│       │       ├── startup.py  # Startup apps & boot persistence
│       │       └── update.py   # Version status & channel inspector
│       │
│       ├── platform/           # Operating system abstraction
│       │   ├── __init__.py     # Platform exports
│       │   ├── base.py         # PlatformInterface base contract
│       │   ├── detector.py     # Cross-platform discovery & install mode
│       │   ├── linux.py        # Linux (/etc/os-release, dmi, systemd, lsblk)
│       │   ├── macos.py        # macOS (system_profiler, launchctl, diskutil)
│       │   └── windows.py      # Windows (Registry, CIM/WMI/PowerShell, SCM)
│       │
│       ├── modules/            # Domain inspection & intelligence modules
│       │   ├── __init__.py
│       │   ├── models.py       # Pydantic telemetry models (CPU, RAM, GPU, OS, etc.)
│       │   ├── hardware/       # Hardware asset inspection
│       │   │   ├── __init__.py
│       │   │   ├── cpu.py      # Core counts, frequencies, utilization gauges
│       │   │   ├── devices.py  # Device inventory (disks, GPUs, NICs)
│       │   │   ├── firmware.py # Motherboard & BIOS with serial redacting
│       │   │   ├── gpu.py      # NVIDIA, AMD, Intel, Apple Silicon discovery
│       │   │   ├── memory.py   # RAM & swap telemetry
│       │   │   └── storage.py  # Logical volumes & physical disk topology
│       │   ├── processes/      # Process & service auditing
│       │   │   ├── __init__.py
│       │   │   ├── collector.py# Process enumeration, sorting, and summaries
│       │   │   ├── metadata.py # High-performance sub-second process extractor
│       │   │   ├── services.py # Background services enumeration
│       │   │   └── startup.py  # Autostart applications and persistence
│       │   └── system_info/    # Operating system & environment intelligence
│       │       ├── __init__.py
│       │       ├── architecture.py # Machine & processor architecture
│       │       ├── collector.py    # Unified system overview aggregator
│       │       ├── environment.py  # User, privileges, venv, sanitized env vars
│       │       ├── network_interfaces.py # Adapter MAC, IPv4, IPv6, speed, link status
│       │       └── operating_system.py   # OS release, distro detection, shell, uptime
│       │
│       ├── filesystem/         # Universal filesystem traversal & metadata engine (Phase 03)
│       │   ├── __init__.py
│       │   ├── cancellation.py # Cooperative CancellationToken
│       │   ├── discovery.py    # Multi-platform filesystem root discovery
│       │   ├── engine.py       # High-level FilesystemScanner coordinator
│       │   ├── errors.py       # Filesystem domain exceptions
│       │   ├── exclusions.py   # Path/glob/ext/size/depth exclusion engine
│       │   ├── metadata.py     # Fast cached stat metadata extraction
│       │   ├── models.py       # Pydantic models (FileMetadata, DirectoryMetadata, etc.)
│       │   ├── path_validator.py # Path canonicalization & root deduplication
│       │   ├── permissions.py  # Error classification & permission handling
│       │   ├── statistics.py   # Thread-safe telemetry & throughput metrics
│       │   ├── symlinks.py     # Symlink cycle protection & boundary checks
│       │   ├── traversal.py    # Iterative DFS streaming generator
│       │   └── providers/      # Platform-specific filesystem adapters
│       │       ├── __init__.py
│       │       ├── base.py
│       │       ├── linux.py
│       │       ├── macos.py
│       │       └── windows.py
│       │
│       ├── reporting/          # Multi-format reporting engine (Phase 09)
│       │   └── __init__.py
│       │
│       ├── update/             # Application update engine (Phase 12)
│       │   └── __init__.py
│       │
│       └── utils/              # Cross-cutting utilities
│           ├── __init__.py
│           ├── formatting.py   # Human-readable bytes, time, %, MHz, °C
│           └── paths.py        # Cross-platform XDG/AppData/Support path resolver
│
├── tests/                      # Automated test suite
│   ├── fixtures/               # Test fixtures and mock datasets
│   ├── integration/            # End-to-end CLI integration tests
│   └── unit/                   # Component-level unit tests
│
└── docs/                       # Architectural and technical documentation
```

---

## 4. Application Lifecycle Flow

Application startup and execution follow an explicit sequence of states:

```
[ CREATED ]
     │
     ▼  bootstrap()
[ INITIALIZING ] ──── 1. Initialize bootstrap logging
     │                2. Resolve paths & ensure directory hierarchy
     │                3. Install SIGINT / SIGTERM signal traps
     ▼
[ CONFIGURED ]   ──── 4. Load & validate configuration (or generate defaults)
     │                5. Fine-tune logging level from user settings
     │                6. Verify core required dependencies
     ▼
[ READY ]
     │
     ▼  run_safe(action)
[ RUNNING ]      ──── Execute CLI command or interactive loop
     │
     ▼  shutdown()
[ SHUTTING_DOWN] ──── Run registered cleanup hooks (reverse order)
     │
     ▼
[ TERMINATED ]   ──── Return standardized ExitCode to OS
```

---

## 5. Configuration Flow

1. **Resolution**: `AppPaths.config_file` computes the target path according to OS conventions:
   - Windows: `%APPDATA%\systemscan\config.json`
   - Linux: `~/.config/systemscan/config.json`
   - macOS: `~/Library/Application Support/systemscan/config.json`
2. **First Launch**: If the file does not exist, `ConfigManager.initialize_default()` generates a pristine configuration with safe defaults, validated against `SystemScanConfig`.
3. **Atomic Persistence**: Saving writes to a temporary file in the destination folder, flushes disk buffers, and executes an atomic move (`shutil.move`), preventing partial file writes upon power loss or abrupt exit.
4. **Malformed Recovery**: If an existing file contains invalid JSON, `ConfigManager` automatically archives the corrupted file to `config_corrupted_<timestamp>.json` in the backups folder before raising `ConfigMalformedError`.
5. **Backups & Reset**: Explicit user resets generate timestamped backups before applying default templates.

---

## 6. Logging Architecture

- **Console Handler**: Powered by Rich `RichHandler`. Produces concise, color-coded status messages. Stack traces are suppressed unless `--debug` is explicitly supplied.
- **File Handler**: Uses Python's `RotatingFileHandler` with 5 MB rotation limits and 5-generation history. Always logs deep diagnostic detail in UTF-8.
- **Credential Scrubbing**: `SensitiveDataScrubber` intercepts every log record, applying regex patterns to mask API keys, bearer tokens, passwords, and authorization headers (`[REDACTED]`).

---

## 7. Error Handling Hierarchy

All application exceptions inherit from `SystemScanError`:

```
SystemScanError (exit_code=1)
├── ConfigurationError (exit_code=2)
│   ├── ConfigNotFoundError
│   ├── ConfigValidationError
│   └── ConfigMalformedError
├── DependencyError (exit_code=3)
│   ├── MissingDependencyError
│   └── IncompatibleDependencyError
├── SecurityPermissionError (exit_code=4)
├── PlatformError (exit_code=5)
│   ├── UnsupportedPlatformError
│   └── PlatformOperationError
├── ScanError (exit_code=1)
├── UpdateError (exit_code=1)
├── ReportError (exit_code=1)
└── LifecycleError (exit_code=1)
```

The centralized `ErrorHandler`:
- Maps known errors to their dedicated POSIX-friendly exit codes.
- Renders user-friendly Rich panels without alarming tracebacks.
- Captures full stack traces in the rotating log file for post-incident diagnostics.
- Traps `KeyboardInterrupt` and exits with code `130` cleanly.

---

## 8. Platform Abstraction Layer

Operating system variations are encapsulated by `PlatformInterface`:
- **Capabilities Matrix**: Each platform adapter (`WindowsPlatform`, `LinuxPlatform`, `MacOSPlatform`) advertises structured boolean capabilities (e.g. `can_inspect_windows_acls`, `can_inspect_posix_permissions`, `can_inspect_systemd`, `can_inspect_launchd`).
- **Elevation Detection**: Uniform `is_elevated()` method checks for Windows Administrator (via `ctypes.windll.shell32.IsUserAnAdmin`) or POSIX root (`os.geteuid() == 0`).
- **Diagnostic Summary**: Structured dictionaries expose operating system names, release versions, kernel builds, and hardware architecture.

---

## 9. System Intelligence & Hardware Architecture (Phase 02)

Phase 2 established the core non-invasive system inspection and hardware diagnostic engine:

```
┌────────────────────────────────────────────────────────┐
│                   CLI Presentation                     │
│  (info, hardware, processes, services, startup, monitor)│
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                  Pydantic Telemetry                    │
│   (SystemInformation, CPU, Memory, GPU, Storage, etc.) │
└─────────────┬───────────────────────────┬──────────────┘
              │                           │
┌─────────────▼─────────────┐   ┌─────────▼──────────────┐
│  modules/hardware/        │   │  modules/processes/    │
│  - cpu.py (cores, freq, %)│   │  - collector.py        │
│  - memory.py (RAM, swap)  │   │  - metadata.py (<0.1s) │
│  - gpu.py (NV/AMD/Intel)  │   │  - services.py         │
│  - storage.py (partitions)│   │  - startup.py          │
│  - firmware.py (redacted) │   └─────────┬──────────────┘
│  - devices.py (inventory) │             │
└─────────────┬─────────────┘             │
              │                           │
┌─────────────▼───────────────────────────▼──────────────┐
│                Platform Abstraction Layer              │
│  - WindowsPlatform: Registry, CIM/PowerShell, SCM      │
│  - LinuxPlatform: /etc/os-release, dmi, systemctl, lsblk│
│  - MacOSPlatform: system_profiler, launchctl, diskutil │
└────────────────────────────────────────────────────────┘
```

### Key Design Pillars:
1. **Pydantic Validation**: All collected data models validate data types, computed fields (e.g. human-readable `_formatted` bytes, GHz), and nested object hierarchies.
2. **Defensive Telemetry**: When a specific hardware metric (e.g. GPU temperature, CPU minimum frequency) is not supported by the OS or hypervisor, it is represented as `None` or omitted rather than fabricated with placeholder data.
3. **Privacy Governance**: Hardware identifiers (e.g. motherboard serial numbers) are redacted by default unless `--include-serials` or explicit configuration is active.
4. **Sub-second Process Enumeration**: Process file descriptors and network handles are omitted by default (`include_handles=False`) ensuring near-instantaneous process listings without lockups.
5. **Real-time Live Monitor**: Built on Rich `Live`, refreshing system gauges, storage bars, and top process telemetry at configurable intervals.

---

## 10. Universal Filesystem Engine Architecture (Phase 03)

The filesystem traversal subsystem is engineered as a standalone, read-only discovery engine decoupled from specific security scanner logic:

```
┌────────────────────────────────────────────────────────┐
│                   CLI Presentation                     │
│  (systemscan scan --path / --all-volumes / menu opt 12)│
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                  FilesystemScanner                     │
│  (Coordinates scan_paths, scan_all_volumes, summaries) │
└─────────────┬───────────────────────────┬──────────────┘
              │                           │
┌─────────────▼─────────────┐   ┌─────────▼──────────────┐
│    PathValidator          │   │    ExclusionManager    │
│  - Path canonicalization  │   │  - Path / subtree match│
│  - Windows long-paths     │   │  - Globs & extensions  │
│  - Root deduplication     │   │  - Size & depth bounds │
└─────────────┬─────────────┘   │  - OS safety defaults  │
              │                 └─────────┬──────────────┘
              │                           │
┌─────────────▼───────────────────────────▼──────────────┐
│              FilesystemTraversalEngine                 │
│  - Iterative DFS stack (collections.deque)             │
│  - Streaming generator (yields File/Dir Metadata)      │
│  - Cached os.scandir() stat evaluation                 │
│  - SymlinkManager (cycle checks & root boundaries)     │
│  - PermissionHandler (non-terminating error sink)      │
│  - CancellationToken (responsive cooperative abort)    │
│  - ScanStatisticsCollector (thread-safe metrics)       │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│              Platform Filesystem Providers             │
│  - Windows: Logical drive detection, system attributes │
│  - Linux: Mount parsing, pseudo/virtual FS detection   │
│  - macOS: APFS volume discovery, /Volumes management   │
└────────────────────────────────────────────────────────┘
```

### Filesystem Engine Design Principles:
1. **Iterative Streaming**: Eliminates Python `RecursionError` and prevents storing millions of files in RAM. Bounded memory consumption verified via benchmark (< 1 MB RAM delta for 5,000 files).
2. **Strict Read-Only Guarantee**: The engine performs zero write, delete, execute, or permission modification operations. Device files and named pipes are never opened.
3. **Symlink Boundary Safety**: Default policy is strictly `RECORD_NO_FOLLOW`. Safe follow mode enforces cycle detection and root boundary containment.
4. **Resilient Error Toleration**: Individual inaccessible directories or locked files are recorded in `FilesystemErrorRecord` without terminating the scan session.
5. **Deduplicated Multi-Root Traversal**: Supplying overlapping scan paths (e.g. `/home/user` and `/home/user/Downloads`) automatically prunes descendant roots to prevent redundant duplicate visits.

---

## 11. Devices & Removable Storage Subsystem (Phase 04)

Located in `src/systemscan/devices/`, this subsystem provides hardware device discovery, removable storage classification, hardware-to-filesystem correlation, real-time background monitoring, and active scan integration.

```
                          ┌───────────────────────────┐
                          │       DeviceManager       │
                          │   (Subsystem Coordinator) │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┼───────────────────────────┐
           │                            │                           │
┌──────────▼───────────┐     ┌──────────▼───────────┐    ┌──────────▼───────────┐
│    DeviceProvider    │     │   DeviceClassifier   │    │   DeviceInventory    │
│ (Platform Detection) │     │ (Heuristic Analyzer) │    │  (Registry Cache)    │
└──────────┬───────────┘     └──────────┬───────────┘    └──────────┬───────────┘
           │                            │                           │
           └────────────────────────────┼───────────────────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │       DeviceMonitor        │
                         │ (Background Diffing Loop)  │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   DeviceEventDispatcher    │
                         │   (Thread-Safe Pub/Sub)    │
                         └──────────────┬─────────────┘
                                        │
                   ┌────────────────────┴────────────────────┐
                   │                                         │
        ┌──────────▼───────────┐                  ┌──────────▼───────────┐
        │   CLI & Monitor UI   │                  │  FilesystemScanner   │
        │(systemscan devices)  │                  │ (Active Scan Hook)   │
        └──────────────────────┘                  └──────────────────────┘
```

### Device Subsystem Architectural Guarantees:
1. **100% Read-Only Safety**: The engine never mounts, unmounts, formats, modifies, or executes code from external devices.
2. **Multi-Tier Separation**: Distinguishes between physical interconnect (`BusType`), physical drive (`DeviceMetadata`), logical partition (`PartitionMetadata`), and mounted volume (`mount_points`).
3. **Serial Number Privacy**: All hardware serial numbers are masked by default (`SA****78`) to protect operator privacy.
4. **Dynamic Active Scan Injection**: Monitors newly connected media during ongoing filesystem scans; upon user authorization, roots are enqueued dynamically without scan restarts or redundant visits.

---

## 12. Malware & Virus Detection Subsystem (Phase 05)

Located in `src/systemscan/modules/malware/`, this subsystem implements a modular, evidence-based, read-only malware scanning pipeline layered directly onto Phase 3 `FilesystemScanner` streams:

```
                          ┌───────────────────────────┐
                          │  FilesystemScanner Stream │
                          └─────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   MalwareScanCoordinator   │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   MalwareDetectionEngine   │
                         └──────────────┬─────────────┘
                                        │
   ┌────────────────┬───────────────────┼───────────────────┬────────────────┐
   │                │                   │                   │                │
┌──▼──────────┐ ┌───▼───────────┐ ┌─────▼──────────┐ ┌──────▼─────────┐ ┌────▼──────────┐
│HashAnalyzer │ │SignatureScan  │ │FileFormatCheck │ │HeuristicEngine │ │EntropyAnalyzer │
│(SHA-256)    │ │(Byte Patterns)│ │(Magic Bytes)   │ │(Double Ext)    │ │(Shannon Bits)  │
└──┬──────────┘ └───┬───────────┘ └─────┬──────────┘ └──────┬─────────┘ └────┬──────────┘
   │                │                   │                   │                │
   └────────────────┴───────────────────┼───────────────────┴────────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │  Severity/Confidence Matrix│
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │      AllowlistManager      │
                         │  (False-Positive Control)  │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │     QuarantineManager      │
                         │  (Explicit Isolate/Restore)│
                         └────────────────────────────┘
```

### Detection Guarantees:
1. **Zero Execution**: Files are never executed or dynamically loaded.
2. **Streaming IO**: Processed in 64 KB chunks avoiding memory spikes.
3. **Calibrated Confidence**: Confirmed detections require exact hash or signature matches.
4. **Non-Destructive Quarantine**: Moves files to application-managed quarantine storage, removes execution bits (`0o600`), and retains full rollback manifest.

---

## 13. Storage Analyzer, Cache Scanner & Safe Cleanup Subsystem (Phase 06)

Located in `src/systemscan/modules/storage/`, this subsystem implements disk space intelligence, multi-stage duplicate detection, browser/system cache scanning, and a safety-gated cleanup engine:

```
                          ┌───────────────────────────┐
                          │   Filesystem Discovery    │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┼───────────────────────────┐
           │                            │                           │
┌──────────▼───────────┐     ┌──────────▼───────────┐    ┌──────────▼───────────┐
│   DiskUsageAnalyzer  │     │   LargeFileAnalyzer  │    │  DirectoryAnalyzer   │
│(Partitions, Capacity)│     │(Size Limit Filtering)│    │ (Space Aggregation)  │
└──────────────────────┘     └──────────────────────┘    └──────────────────────┘
           │                            │                           │
           ├────────────────────────────┼───────────────────────────┤
           │                            │                           │
┌──────────▼───────────┐     ┌──────────▼───────────┐    ┌──────────▼───────────┐
│  DuplicateDetector   │     │  ExtensionAnalyzer   │    │     AgeAnalyzer      │
│(Staged: Size->MD5->  │     │  (Count, Share %,    │    │ (30d, 90d, 180d,     │
│       SHA-256)       │     │   Largest File)      │    │    365d Dormancy)    │
└──────────────────────┘     └──────────────────────┘    └──────────────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   Cache & Temp Discovery   │
                         │(App, System, Browser Caches│
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   CleanupSafetyValidator   │
                         │ (Symlink & Document Guards)│
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │       CleanupPlanner       │
                         │ (Preview & Safety Tagging) │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │    SafeCleanupExecutor     │
                         │  (TOCTOU & Process Checks) │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │     CleanupAuditLogger     │
                         │ (Immutable JSON Records)   │
                         └────────────────────────────┘
```

### Storage Engine Guarantees:
1. **100% Read-Only Inspection**: All storage analytics, cache discoveries, and cleanup preview operations are strictly read-only.
2. **Staged Duplicate Optimization**: Progressive 3-stage duplicate pipeline (size-grouping -> 4 KB MD5 head check -> full streaming SHA-256) eliminates >98% of unnecessary hashing operations.
3. **Protected Category Exclusions**: Strict safety rules prevent cleanup candidates from touching user documents (`.docx`, `.xlsx`, `.pdf`), databases (`.sql`, `.db`), code repositories (`.git`), keys, or system directories (`System32`, `/bin`, `/usr`).
4. **Browser Runtime Protection**: Active browser processes (Chrome, Edge, Brave, Firefox) are detected, protecting cache directories while browsers are open. User bookmarks, cookies, and browsing histories are strictly preserved.
5. **Time-of-Check to Time-of-Use (TOCTOU) Validation**: Pre-deletion re-verification ensures that targets have not been altered, replaced with symlinks, or locked by active processes.
6. **Immutable Audit Trail**: All cleanup actions generate a permanent audit log stored in `cleanup_audits/<uuid>.json` recording operation IDs, reclaimed space, deleted file paths, and operator confirmation.

---

## 14. Network Security Audit & Network Intelligence Subsystem (Phase 07)

Located in `src/systemscan/network/`, this subsystem implements cross-platform network interface discovery, connection auditing, local subnet host discovery, DNS intelligence, firewall auditing, Wi-Fi security assessment, baseline drift comparison, and real-time socket monitoring:

```
                          ┌───────────────────────────┐
                          │  CLI & Interactive Menu   │
                          │   (systemscan network)    │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┼───────────────────────────┐
           │                            │                           │
┌──────────▼───────────┐     ┌──────────▼───────────┐    ┌──────────▼───────────┐
│NetworkInterfaceInspec│     │NetworkConnectionInspec│   │ LocalNetworkDiscovery│
│(Adapters, Subnets)   │     │(Sockets, Ports, PIDs)│    │ (ARP, Bounded Probes)│
└──────────────────────┘     └──────────────────────┘    └──────────────────────┘
           │                            │                           │
           ├────────────────────────────┼───────────────────────────┤
           │                            │                           │
┌──────────▼───────────┐     ┌──────────▼───────────┐    ┌──────────▼───────────┐
│DNSIntelligenceEngine │     │   FirewallAuditor    │    │WirelessSecurityInspec│
│(Resolvers, Latency)  │     │ (Profiles, Posture)  │    │(SSID, Auth, Signal)  │
└──────────────────────┘     └──────────────────────┘    └──────────────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   NetworkBaselineManager   │
                         │(Snapshots & Drift Detect)  │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │  NetworkFindingsEvaluator  │
                         │ (Standardized Rule Matrix) │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   NetworkPlatformProvider  │
                         │(Windows / Linux / macOS)   │
                         └────────────────────────────┘
```

### Network Subsystem Guarantees:
1. **100% Read-Only Safety**: The engine never alters firewall rules, network routing, DNS settings, or interface configurations.
2. **Private Network Scope Boundary**: Host discovery is restricted to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or link-local subnets. Public scanning is blocked unless explicitly authorized.
3. **Passive-First Enumeration**: Reads kernel ARP tables prior to active socket probing to minimize network traffic.
4. **Zero Exploitation**: Probes use standard non-intrusive TCP handshakes (`connect_ex`). No exploitation, packet injection, or fuzzing is performed.
5. **Credential Protection**: Wi-Fi passwords and authentication keys are never queried, captured, or stored.
6. **Persistent Baseline Drift**: Versioned JSON snapshots detect unauthorized changes in gateways, DNS resolvers, and listening ports.

---

## 15. Scan Intelligence & Performance Subsystem (Phase 08)

Located in `src/systemscan/engine/`, this subsystem implements central scan orchestration, adaptive concurrency, dynamic duration estimation (ETA), incremental scanning with caching, atomic checkpoints, pause/resume, deduplication, and historical session ledgers:

```
                          ┌───────────────────────────┐
                          │   CLI & Subcommands       │
                          │(scan, history, performance│
                          └─────────────┬─────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │  CentralScanOrchestrator  │
                          └─────────────┬─────────────┘
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         │                              │                              │
┌────────▼───────────┐        ┌─────────▼──────────┐        ┌──────────▼───────────┐
│ScanLifecycleCoord  │        │IntelligentConcurren│        │ IntelligentETAEngine │
│(Deterministic FSM) │        │(CPU/Memory/Battery)│        │(Exponential Smoothing│
└────────────────────┘        └────────────────────┘        └──────────────────────┘
         │                              │                              │
         ├──────────────────────────────┼──────────────────────────────┤
         │                              │                              │
┌────────▼───────────┐        ┌─────────▼──────────┐        ┌──────────▼───────────┐
│IncrementalScanEngin│        │ScanCheckpointManage│        │  ScanHistoryManager  │
│(fast/balanced/mode)│        │(Atomic Persistence)│        │  (Auditable Ledger)  │
└────────────────────┘        └────────────────────┘        └──────────────────────┘
```

### Scan Intelligence Subsystem Guarantees:
1. **Unified Multi-Module Coordination**: Coordinates filesystem traversal, malware checks, storage inspection, cache discovery, USB monitoring, and network security audits into a single orchestration layer.
2. **Adaptive Concurrency & Resource Safety**: Scales thread pools to host capacity and throttles worker threads by 50% when CPU load exceeds 85% or RAM exceeds 75%; clamps to 1 worker on low battery (<20%).
3. **Guards Against Fabricated ETAs**: Never produces false percentages or completion estimates while target discovery is incomplete or item totals are unknown.
4. **Resilient Fault Tolerance**: Supports cooperative pausing at processing boundaries and resilient resumption from atomically saved JSON checkpoints.
5. **Incremental Acceleration**: Avoids re-processing unchanged files using fast or balanced metadata checks (size, mtime, inode), delivering 90-98% faster repeated scan runs.
6. **Immutable Execution History**: Maintains a searchable, persistent ledger of scan runs with status, durations, findings, and volume metrics.

---

## 16. Reporting & Export Subsystem (Phase 09)

Located in `src/systemscan/reporting/`, this subsystem implements standardized multi-format report generation, executive summaries, finding normalization, privacy redaction, cryptographic integrity validation, and atomic storage:

```
                          ┌───────────────────────────┐
                          │   CLI & Subcommands       │
                          │ (systemscan report/reports│
                          └─────────────┬─────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │      ReportGenerator      │
                          └─────────────┬─────────────┘
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         │                              │                              │
┌────────▼───────────┐        ┌─────────▼──────────┐        ┌──────────▼───────────┐
│FindingNormalizer   │        │ExecutiveSummaryBldr│        │    ReportRedactor    │
│(Disparate -> Unified        │(Risk Verdicts & Rec│        │(Immutability & Masks)│
└────────────────────┘        └────────────────────┘        └──────────────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │       ReportExporter      │
                          └─────────────┬─────────────┘
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         │                              │                              │
┌────────▼───────────┐        ┌─────────▼──────────┐        ┌──────────▼───────────┐
│ JSONReportExporter │        │  CSVReportExporter │        │  TextReportExporter  │
│ (Strict UTF-8 JSON)│        │  (Spreadsheet RFC) │        │(Executive/Tech/Compac│
└────────────────────┘        └────────────────────┘        └──────────────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │   ReportStorageManager    │
                          │(Atomic Writes, SHA Manifest│
                          └────────────────────────────┘
```

### Reporting Subsystem Guarantees:
1. **Decoupled Architecture**: Reporting is completely decoupled from scanning modules; scanner engines remain read-only and independent.
2. **Schema Versioning**: Strictly validated `ScanReport` schema (v1.0) with ISO 8601 timestamps and unambiguous types.
3. **Evidence Preservation**: Technical findings preserve all original cryptographic hashes, process IDs, listening sockets, and evidence strings.
4. **Privacy & Redaction Immutability**: Sanitization operates on deep copies, preventing alteration of original forensic scan records.
5. **Cryptographic Checksum Verification**: Every saved report generates a `.sha256` manifest, enabling tamper detection via `systemscan report verify`.

---

## 17. Dependency Management & Application Self-Update Subsystem (Phase 10)

Phase 10 establishes runtime environment governance, dependency inspection, safe package installation, and an atomic 10-stage application self-update system:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   systemscan Dependency & Update Subsystem             │
├───────────────────────────────────┬────────────────────────────────────┤
│     Dependency Management         │      Application Self-Update       │
│  - DependencyRegistry             │  - UpdateChecker (HTTPS / SemVer)  │
│  - SafeDependencyInstaller        │  - UpdateVerifier (SHA-256/Safety) │
│  - EnvironmentDoctor              │  - UpdateTransactionCoordinator    │
│  - ExternalToolInspector          │  - UpdateBackupManager             │
│    (nmap, yara, ufw, nft, ps)     │  - UpdateRollbackManager           │
│  - Virtualenv Isolation Guard     │  - ConfigMigrationManager          │
│                                   │  - UpdateHistoryManager            │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 17.1 Dependency Governance & Safe Installation
- **Classification**: Dependencies are classified into `CORE`, `OPTIONAL`, `DEV`, `PLATFORM_SPECIFIC`, and `EXTERNAL_TOOL`.
- **Virtualenv Guard**: `SafeDependencyInstaller` ensures packages are only installed into active virtual environments (`sys.prefix != sys.base_prefix`), preventing corruption of global system Python.
- **Doctor Diagnostic Engine**: `EnvironmentDoctor` audits host runtime, writable directory permissions, dependencies, and external tool versions, emitting structured status tables and remediation steps.

### 17.2 10-Stage Update Transaction Lifecycle
1. `CHECKING`: Remote HTTPS query, semver calculation, downgrade detection.
2. `DOWNLOADING`: Secure download into isolated temporary workspace.
3. `VERIFYING`: Streaming SHA-256 validation, zip bomb limits (50MB/2,000 files), path traversal (zip-slip) defenses.
4. `PREPARING`: Exclusive update lock acquisition (`update.lock`) and staging directory setup.
5. `BACKING_UP`: Isolated pre-update snapshot of installed package tree with manifest.
6. `APPLYING`: Atomic extraction of verified distribution files into application root.
7. `MIGRATING`: Safe configuration schema migration with pre-migration snapshot.
8. `VALIDATING`: Package import validation and integrity checks.
9. `COMMITTING`: Release lock, write transaction audit to `update_history.json`, clean temporary assets.
10. `COMPLETED`: Successful update completion.

### 17.3 Automated Rollback & User Data Preservation
- When an update fails during application, migration, or validation, `UpdateRollbackManager` restores the original package directory from snapshot.
- User data (configuration, scan history, reports, checkpoints, logs) is preserved independently and never touched during updates or rollbacks.

---

## 18. Production QA, Security Audit & Hardening Architecture (Phase 11)

Phase 11 establishes systematic production hardening, multi-layered vulnerability defense, automated cross-platform CI matrix testing, empirical performance auditing, and dedicated regression test coverage:

```
┌────────────────────────────────────────────────────────────────────────┐
│             systemscan Production QA & Hardening Subsystem             │
├───────────────────────────────────┬────────────────────────────────────┤
│     Zero-Trust Security Guards    │     Quality Assurance Pipeline     │
│  - Zip-Slip & Traversal Checks    │  - Multi-OS Matrix CI (12 runners) │
│    (resolve() target containment) │    (Ubuntu, Win, macOS x Py 3.10+) │
│  - Symlink Isolation & Rejection  │  - 10 Dedicated Security Unit Tests│
│  - TOCTOU Cleanup Verification    │  - Empirical Benchmarking Harness  │
│    (mtime drift threshold < 2.0s) │  - Memory Delta Leak Auditing      │
│  - Subprocess shell=False vectors │  - Output Stream Channel Isolation │
│  - Network CIDR bounds (/24 max)  │    (Rich/ANSI -> stderr strictly)  │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 18.1 Zero-Trust Security Guards & Threat Mitigation
- **Zip-Slip & Path Traversal Prevention**: `systemscan.update.verifier` inspects all archive member names prior to extraction, resolving canonical targets against the extraction root to guarantee no file can escape into system directories.
- **Symlink Boundary Integrity**: Traversal engines enforce `follow_symlinks=False` by default; malware quarantine engines explicitly reject symlinks to prevent privilege escalation via link redirection.
- **TOCTOU Safe Cleanup**: Pre-deletion validation checks timestamps against preview candidate records within 2.0s tolerance. Modified or critical system paths are aborted and logged to `cleanup_audit.json`.
- **Subprocess Argument Vectoring**: All platform collectors avoid shell interpretation (`shell=False`) and enforce bounded timeouts (5–10s) to preclude command injection.
- **CIDR Subnet Clamping**: Local network audits clamp discovery ranges to `/24` (256 hosts maximum), raising exceptions on wider ranges to eliminate accidental DoS hazards.

### 18.2 Quality Assurance & Continuous Matrix Validation
- **Automated CI/CD**: `.github/workflows/ci.yml` runs full linting (`ruff`), typing (`mypy`), and test suites across Ubuntu, Windows, and macOS on Python 3.10 through 3.13.
- **Dedicated Regression Tests**: `tests/unit/test_security_hardening.py` provides 10 discrete tests targeting identified threat vectors.
- **Stream Channel Separation**: CLI logs and terminal rich formatting write strictly to `stderr`, guaranteeing clean, unpolluted JSON on `stdout` when `--format json` is requested.

---

## 19. Documentation, Packaging & Release Architecture (Phase 12)

Phase 12 establishes standardized packaging, clean distribution verification, platform installation scripts, safe uninstallation with data preservation, and comprehensive user documentation:

```
┌────────────────────────────────────────────────────────────────────────┐
│             systemscan Packaging & Release Infrastructure              │
├───────────────────────────────────┬────────────────────────────────────┤
│     Packaging & Verification      │     Installation & Governance      │
│  - PEP 517 / 621 Hatchling Build  │  - One-Command Safe Installers     │
│    (sdist and wheel py3-none-any) │    (scripts/install.sh & ps1)      │
│  - Twine Strict Artifact Check    │  - Safe Uninstallation Workflow    │
│  - Isolated Temp Venv Validation  │    (Preserves config/reports)      │
│  - Multi-OS Installation Guides   │  - GitHub CI/CD Release Automation │
│    (Linux, Windows 10/11, macOS)  │    (Artifact build & SHA-256 sums) │
│  - Standalone Executable Strategy │  - Open-Source Governance Suite    │
│    (PyInstaller vs Wheel analysis)│    (Contributing, CoC, Security)   │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 19.1 Distribution Standards & Build Verification
- **Dual Artifact Targets**: Generates standard source distributions (`systemscan-1.0.0.tar.gz`) and universal binary wheels (`systemscan-1.0.0-py3-none-any.whl`).
- **Strict Twine Validation**: Packages pass `twine check --strict` with zero description or rendering warnings.
- **Root Gitignore Anchoring**: Explicitly anchors `/reports/`, `/logs/`, and `/quarantine/` to prevent hatchling from omitting package code.
- **Isolated Venv Installation**: Every release candidate is tested via clean pip install in an isolated temporary virtual environment, verifying CLI entry point initialization and sub-second startup.

### 19.2 Safe Lifecycle & Data Preservation Architecture
- **Non-Destructive Uninstall Invariant**: `systemscan uninstall` and `scripts/uninstall.[sh|ps1]` remove only package binaries and virtual environment files by default.
- **Explicit Data Purge**: Purging user data (`--remove-data`) requires explicit user confirmation and enforces boundary checks preventing deletion of filesystem roots.

---

## 20. Final System Integration & Production Acceptance Architecture (Phase 13)

Phase 13 solidifies the end-to-end integration across all 12 prior phases, unifies multi-engine scan coordination within `CentralScanOrchestrator`, establishes end-to-end validation, and finalizes production acceptance:

```
┌────────────────────────────────────────────────────────────────────────┐
│             CentralScanOrchestrator (Phase 13 Unified Workflow)        │
├───────────────────────────────────┬────────────────────────────────────┤
│       Unified Scan Execution      │     Finding & Report Automation    │
│  - FULL / FILESYSTEM / MALWARE    │  - FindingNormalizer Integration   │
│    STORAGE / NETWORK / DEVICES    │    (Standard FindingRecord v1.0)   │
│  - Streamed Filesystem Traversal  │  - ReportGenerator Integration     │
│    (Passed to Malware & Storage)  │    (Executive & Technical Summaries│
│  - Sequential Network & Devices   │  - ReportStorageManager            │
│    Audit Phases                   │    (Atomic write + SHA-256 sum)    │
│  - Cooperative Pause/Resume       │  - Zero Destructive Actions        │
│    and Scan State Transitions     │    (Strict Read-Only by Default)   │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 20.1 Multi-Module Unified Execution Pipeline
- **Single-Pass Disk Traversal**: When executing `ScanType.FULL`, streamed file metadata from `FilesystemScanner` is piped in real-time to `MalwareDetectionEngine` (SHA-256 hash checks and signature heuristics) and storage threshold indexing (>100MB) without redundant disk re-scans.
- **Normalized Findings Model**: Every anomaly across malware, storage, network, and filesystem domains is normalized into `FindingRecord` structures with standardized severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and confidence ratings.
- **Deterministic Cryptographic Reporting**: Every scan automatically persists a structured `ScanReport` and computes a companion `.sha256` manifest file, ensuring evidentiary immutability for forensic auditing.
- **Session Reusability**: Orchestrator resets its lifecycle state to `QUEUED` at the beginning of each run session, permitting repeatable, non-colliding scan invocations within long-running processes or automated worker pools.
- **Acceptance Verdict**: Formally approved as **PRODUCTION READY (WITH DOCUMENTED LIMITATIONS)** in `docs/FINAL_ACCEPTANCE_REPORT.md`.

