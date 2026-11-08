# Security Policy

The Universal System Security & Intelligence CLI (`systemscan`) project treats application security and responsible vulnerability disclosure as top priorities.

---

## 1. Supported Versions

Security updates and critical patches are actively supported for the following versions:

| Version | Supported | Status |
|---|---|---|
| **1.0.x** | **Yes** | Active Production Release |
| `< 1.0.0` | No | Legacy Development Branches |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or potential threat vector in `systemscan`, please **DO NOT** create a public GitHub issue.

Instead, please report the vulnerability privately using one of the following methods:
1. **GitHub Security Advisories (Recommended)**: Navigate to the repository's **Security** tab, select **Advisories**, and click **Report a vulnerability**.
2. **Encrypted Security Notice**: Contact the project maintainers through official repository private channels with a description of the vulnerability, reproduction steps, and potential impact.

### What to Include in Your Report:
- Detailed description of the vulnerability (e.g., path traversal, symlink redirection, privilege escalation, command injection).
- Proof of Concept (PoC) script or minimal reproducible example.
- Affected operating systems and Python versions.
- Potential impact on host systems.

---

## 3. Vulnerability Response Timeline

- **Initial Acknowledgment**: Within 48 hours of receipt.
- **Triage & Classification**: Within 5 business days, evaluating severity against CVSS v3 standards.
- **Fix & Patch Development**: Critical and High severity issues are prioritized for rapid remediation in an isolated branch.
- **Coordinated Release & Advisory**: Patches are released with accompanying security release notes, crediting the researcher upon request.

---

## 4. Scope & Operating Model

### In Scope:
- Arbitrary code execution or command injection vectors in CLI parsing or platform providers.
- Path traversal (e.g., zip-slip) during update extraction or report generation.
- Symbolic link redirection attacks in file crawler or quarantine engines.
- TOCTOU race conditions allowing deletion of arbitrary files during safe cleanup.
- Unbounded network scanning causing denial-of-service or flooding.
- Credential or secret leakage in logs or default reports.

### Out of Scope:
- Attacks requiring existing physical root or administrative compromise of the host.
- Denial of service caused by user-configured unbounded scans when run with manual override flags.
- Social engineering attacks against operators.
- Running untrusted third-party Python code inside the active virtual environment.

