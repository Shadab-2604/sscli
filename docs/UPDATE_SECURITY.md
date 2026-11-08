# Update Security & Threat Mitigations

## 1. Overview
The Self-Update System implements zero-trust security controls to defend against malicious release tampering, supply-chain attacks, path traversal, zip bombs, and concurrent update race conditions.

## 2. Threat Vector Mitigations

| Threat Vector | Mitigation Strategy | Implemented In |
| :--- | :--- | :--- |
| **Man-in-the-Middle (MITM) & Spoofing** | Strict HTTPS enforcement; insecure URLs (`http://`) are rejected immediately with `ValueError`. Release queries send explicit User-Agent headers. | `UpdateChecker.fetch_remote_releases` |
| **Tampered or Corrupted Release Binaries** | Cryptographic SHA-256 verification via streaming 64KB chunk processing. Updates are aborted immediately if hashes mismatch. | `UpdateVerifier.verify_file_hash` |
| **Path Traversal / Zip-Slip Vulnerabilities** | Archive members are thoroughly inspected prior to extraction. Members containing `..`, leading slashes (`/`, `\`), or Windows drive letters (`:`) trigger immediate abort. Absolute target path boundary checks enforce that every extracted file remains within `target_dir`. | `UpdateVerifier._inspect_zip_safety`, `extract_safe` |
| **Zip Bomb & Decompression Exhaustion** | Strict physical thresholds: maximum uncompressed archive size is limited to 50 MB (`MAX_UNCOMPRESSED_BYTES`); maximum archive member count is limited to 2,000 files (`MAX_ARCHIVE_FILE_COUNT`). | `UpdateVerifier._inspect_zip_safety`, `_inspect_tar_safety` |
| **Malicious Symlink Traversal** | Tar archive members are checked for `issym()` and `islnk()`. Any symlink referencing `..` or absolute paths (`/`) is rejected. | `UpdateVerifier._inspect_tar_safety` |
| **Accidental or Malicious Version Downgrades** | Downgrades are rejected by default unless the operator explicitly specifies `--allow-downgrade`. Prevents exploitation of known older vulnerabilities. | `UpdateTransactionCoordinator.execute_update` |
| **Concurrent Update Race Conditions** | Exclusive filesystem lock (`update.lock`) containing `PID` and timestamp is acquired before mutation. Automatically detects and resets stale locks (> 30 minutes). | `UpdateTransactionCoordinator.acquire_lock` |
| **Untrusted Code Execution During Verification** | Verification is completely passive and read-only. No archive code, hook, or setup script is ever executed during verification or inspection phases. | `UpdateVerifier` |

