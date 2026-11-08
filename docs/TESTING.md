# Testing Strategy & Quality Assurance Architecture

**Application:** Universal System Security & Intelligence CLI (`systemscan`)  
**Phase:** 11 of 13 — Production QA, Security Audit & Cross-Platform Hardening  
**Last Updated:** 2026-11-08  

---

## 1. Testing Philosophy & Quality Standards

`systemscan` enforces a rigorous, multi-layered quality assurance methodology designed to guarantee zero regressions, complete security verification, and predictable cross-platform reliability.

### Core Testing Pillars:
1. **Safety First:** Test code NEVER executes live malware, never touches live root filesystems, and never modifies user directories outside `tmp_path`.
2. **Determinism:** Tests must be idempotent, independent, and free from external network dependencies.
3. **Multi-Layered Verification:** Unit tests for discrete components, integration tests for cross-subsystem workflows, security hardening regression tests for vulnerability vectors, and automated performance benchmarks.
4. **Zero Tolerance for Type Errors & Flakes:** `ruff` and `mypy` strict type checking are mandatory gates before any test execution.

---

## 2. Test Suite Architecture

The test suite is organized under `tests/` into distinct directories and functional categories:

```
tests/
├── unit/
│   ├── test_cli.py                     # CLI commands, argument parsing, formats
│   ├── test_config.py                  # Pydantic configuration schemas, loading, persistence
│   ├── test_devices.py                 # USB and removable device inventory & monitoring
│   ├── test_filesystem.py              # File traversal, iterators, ignore rules, statistics
│   ├── test_hardware.py                # CPU, memory, GPU, disk, battery inspectors
│   ├── test_malware.py                 # YARA-style signatures, PE analysis, hashes, heuristics
│   ├── test_network.py                 # Interface discovery, socket audit, DNS, bounded scan
│   ├── test_orchestration.py          # Scan orchestrator, concurrency, checkpoints, state
│   ├── test_platform.py                # Windows/Linux/Darwin platform providers & OS info
│   ├── test_reporting.py               # Exporters (JSON, CSV, TXT), storage, validation
│   ├── test_security_hardening.py      # Phase 11 security regression tests (10 threat vectors)
│   ├── test_storage.py                 # Space analysis, duplicates, caches, safe cleanup
│   └── test_update.py                  # Dependency manager, self-update verifier & rollback
```

---

## 3. Dedicated Security Regression Test Suite (`test_security_hardening.py`)

Added in Phase 11, `tests/unit/test_security_hardening.py` provides targeted automated verification for the 10 threat scenarios identified during the security audit:

| Test Case | Target Subsystem | Threat Vector Verified | Assertion Standard |
|---|---|---|---|
| `test_zip_slip_and_path_traversal_hardening` | `update.verifier` | Zip-Slip / Path Traversal via `../` archive members | Rejects archive with `ArchiveSecurityError`; zero files extracted outside destination root. |
| `test_symlink_safety_and_quarantine_rejection` | `malware.quarantine` | Symlink redirection into sensitive system files | Refuses to quarantine symlink target; verifies `is_symlink()` check raises `MalwareError`. |
| `test_corrupted_state_recovery_resilience` | `orchestration.history` | Corrupted / malformed JSON scan history state file | Skips malformed files gracefully with warning; valid history entries preserved without crash. |
| `test_network_cidr_bounds_and_ssrf_mitigation` | `network.audit` | Denial of Service via massive CIDR ranges (`/8`, `/16`) | Rejects CIDR wider than `/24` with `NetworkAuditError`. |
| `test_subprocess_command_injection_hardening` | `update.dependency` | Command injection through shell metacharacters in package names | Escaped / validated safely; executed strictly via `shell=False` array arguments. |
| `test_unicode_and_special_character_paths` | `filesystem.traversal` | Crash on Unicode emojis, spaces, foreign glyphs in file paths | Traverses and hashes Unicode paths accurately without decoding exceptions. |
| `test_concurrent_update_lock_collision` | `update.installer` | State corruption from parallel update invocations | Second update instance fails cleanly with `LockError`; existing lock respected. |
| `test_report_overwrite_and_integrity_protection` | `reporting.exporter` | Unintended destruction of previous scan reports | Exporter prevents accidental file overwrite unless explicit `overwrite=True` is provided. |
| `test_cleanup_toctou_target_substitution` | `storage.cleanup` | File substitution race between preview and cleanup execution | Detects modified timestamp mismatch; skips file deletion with `SKIPPED_MODIFIED` audit record. |
| `test_malware_accuracy_synthetic_high_entropy_non_malicious` | `malware.engine` | False positive confirmed malware verdict on high entropy data | Entropy > 7.5 flagged as heuristic risk indicator but verdict remains `clean` without signatures. |

---

## 4. Local Execution & Verification

Developers can run checks and tests locally using the unified scripts or pytest:

### Run All Production QA Checks:
```powershell
# Unified check runner (Format check -> Lint -> Type check -> Pytest with Coverage)
python scripts/run_checks.py
```

### Run Tests with Coverage:
```powershell
pytest --cov=systemscan --cov-report=term-missing tests/
```

### Run Dedicated Security Tests:
```powershell
pytest tests/unit/test_security_hardening.py -v
```

### Run Performance Benchmarks:
```powershell
python scripts/benchmark_audit.py
```

---

## 5. Automated CI/CD Pipeline (`.github/workflows/ci.yml`)

The production CI workflow automatically executes on all pull requests and commits:
- **Matrix Build:** 12 concurrent runner configurations:
  - OS: `ubuntu-latest`, `windows-latest`, `macos-latest`
  - Python: `3.10`, `3.11`, `3.12`, `3.13`
- **Steps:**
  1. Checkout repository with full history.
  2. Set up Python environment and cache pip wheels.
  3. Install core and test dependencies (`pip install -e ".[dev]"`).
  4. Run Ruff linting and code formatting check.
  5. Run Mypy static type analysis across `src/systemscan`.
  6. Execute full Pytest test suite with code coverage export.
  7. Upload test artifacts and coverage reports.

---

## 6. Current Test Metrics (Phase 11 Status)

- **Total Unit & Integration Tests:** 246 passing tests.
- **Failures / Errors:** 0.
- **Security Hardening Coverage:** 100% of defined threat vectors verified.
- **Overall Codebase Coverage:** >71% line coverage.
- **Execution Speed:** Full test suite executes in under 8 seconds.

