# Universal System Security & Intelligence CLI — Comprehensive Threat Model

## 1. Overview & Security Objectives
The Universal System Security & Intelligence CLI (`systemscan`) operates as a dual-execution command-line security auditing and forensic inspection utility across Windows, Linux, and macOS. Because it interfaces directly with host filesystems, processes, network stacks, removable devices, and remote update repositories, it must enforce zero-trust security boundaries.

Security Objectives:
- **Zero Accidental Damage**: Never alter, delete, or overwrite user files without explicit, interactive authorization and pre-execution safety re-validation.
- **Zero Passive Execution**: Never execute scanned files, quarantined payloads, or untrusted downloaded artifacts during inspection.
- **Fail-Safe Containment**: Ensure path traversal, zip bombs, symlink loops, and malformed inputs cannot compromise the host.
- **Data Privacy & Integrity**: Prevent credential leakage in logs/reports and cryptographically verify all reports and updates.

---

## 2. Asset Inventory & Trust Boundaries

```
[External / Untrusted World]
    │  (GitHub HTTPS Releases, Public Internet IPs)
════╪════════════════════════════════════════════════════════════════════════════
    ▼  [Boundary 1: Network Ingress Guard]
[systemscan Application Runtime]
    │  (UpdateChecker, LocalNetworkDiscovery, PackageRegistry)
════╪════════════════════════════════════════════════════════════════════════════
    ▼  [Boundary 2: Storage & Filesystem Isolation Guard]
[Host Filesystem & Operating System]
    │  (User Documents, System32 / /etc, Quarantined Threats, Removable Media)
```

### Critical Assets:
1. **User Documents & App Data**: Personal files (`.docx`, `.pdf`, `.sql`, databases, keys).
2. **Operating System Integrity**: Critical system directories (`C:\Windows\System32`, `/etc`, `/usr/bin`).
3. **Application State & History**: `config.json`, `scan_history.json`, scan reports, checkpoints.
4. **Network Infrastructure**: Local network stability, preventing unauthorized scans or port flooding.
5. **Execution Environment**: Python virtual environment integrity, preventing global package pollution.

---

## 3. Attack Surfaces & Threat Vectors

1. **Malicious Filesystem Objects**:
   - Symlinks pointing to `/etc/shadow` or sensitive user documents.
   - Deep nested directories attempting call stack exhaustion.
   - Long paths and Unicode filenames causing buffer overflows or crashes.
2. **Untrusted Update Artifacts (Supply Chain)**:
   - Man-in-the-Middle spoofing of release downloads.
   - Zip-slip archive traversal (`../../evil.dll`).
   - Zip bombs (compression bombs designed to exhaust disk or memory).
   - Downgrade attacks installing vulnerable older versions.
3. **Command & Subprocess Injection**:
   - Operator or script input containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`).
4. **Network Abuse & Discovery Expansion**:
   - Scanning public IP ranges or unapproved subnets (SSRF/port scanning).
   - High-rate packet transmission causing network disruption.
5. **Malware Analysis Risks**:
   - Accidental execution of malicious binaries during inspection.
   - Toxic files escaping quarantine storage.

---

## 4. Practical Risk Register

| Risk ID | Component | Threat & Abuse Scenario | Impact | Likelihood | Severity | Implemented Mitigation | Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :---: |
| **RSK-01** | Update Verifier | **Zip-Slip / Path Traversal**: Malicious update archive extracts files outside installation directory. | High | Low | **HIGH** | Strict archive member path inspection rejects `..`, leading slashes, and drive letters. Canonical path resolution guarantees extraction stays inside `target_dir`. | **SECURED** |
| **RSK-02** | Update Verifier | **Zip Bomb / Resource Exhaustion**: Highly compressed archive expands to hundreds of gigabytes. | High | Low | **MEDIUM** | Strict threshold enforcement: maximum uncompressed size capped at 50 MB; member count capped at 2,000 files. | **SECURED** |
| **RSK-03** | Update Coordinator | **Unauthorized Downgrade**: Attacker forces installation of an older, vulnerable version. | High | Low | **MEDIUM** | Semantic version comparison rejects target versions older than current version unless explicitly authorized with `--allow-downgrade`. | **SECURED** |
| **RSK-04** | Dependency Installer | **Command Injection**: Package name containing shell tokens (e.g. `req; rm -rf /`). | Critical | Low | **CRITICAL** | Strict regex and token sanitization; direct argument array invocation without `shell=True`. | **SECURED** |
| **RSK-05** | Dependency Installer | **Host Environment Pollution**: Installing packages into global system Python, breaking OS packages. | High | Medium | **HIGH** | Virtualenv detection guard blocks global installs unless operator passes `--allow-global`. | **SECURED** |
| **RSK-06** | Cleanup Executor | **TOCTOU Target Substitution**: File replaced with symlink or sensitive document between preview and deletion. | Critical | Low | **CRITICAL** | Pre-deletion re-validation re-evaluates safety category, asserts regular file, and verifies modification timestamp matches preview within 2.0s. | **SECURED** |
| **RSK-07** | Cleanup Safety | **Accidental System Deletion**: Cleanup rule targeting temporary files matches critical system files. | Critical | Low | **CRITICAL** | Protected path fragments (`System32`, `/etc`, `/bin`, etc.) and protected extensions (`.docx`, `.kdbx`, `.sql`) are hardcoded as non-deletable. | **SECURED** |
| **RSK-08** | Malware Engine | **Accidental Malware Execution**: Scanned binary or script executed during inspection. | Critical | Low | **CRITICAL** | Inspection is purely passive (streaming SHA-256, YARA rules, byte header analysis). Quarantined files are chmodded `0o600` (execute stripped). | **SECURED** |
| **RSK-09** | Network Discovery | **SSRF / Unauthorized Scanning**: Operator scans public Internet IPs or corporate WAN. | High | Medium | **HIGH** | Strict private address space verification (RFC 1918 / loopback / link-local) rejects public IPs and subnets larger than /22 (> 1,024 hosts). | **SECURED** |
| **RSK-10** | Reporting Storage | **Report Overwriting & Tampering**: Reports overwritten or modified to conceal security findings. | Medium | Low | **MEDIUM** | Atomic writes via `.tmp` files, overwrite guard (`--overwrite` required), and automatic SHA-256 manifests (`.sha256`) with verification command. | **SECURED** |
| **RSK-11** | Application Logging | **Credential Leakage**: Passwords, tokens, or private keys logged to plaintext disk files. | High | Low | **MEDIUM** | `SensitiveDataScrubber` redacts passwords, tokens, API keys, and sensitive environment variables before writing to console or disk. | **SECURED** |
| **RSK-12** | Update Coordinator | **Concurrent Update Corruption**: Two update processes execute simultaneously, corrupting app files. | High | Low | **MEDIUM** | Exclusive filesystem lock (`update.lock`) containing PID and timestamp blocks concurrent runs; auto-cleans stale locks (> 30 min). | **SECURED** |

