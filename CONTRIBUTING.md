# Contributing to Universal System Security & Intelligence CLI (`systemscan`)

Thank you for your interest in contributing to `systemscan`! This project is an enterprise-grade, cross-platform system security and intelligence CLI. We value code quality, security rigor, and architectural consistency.

---

## 1. Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all members of the community with respect and courtesy.

---

## 2. Development Prerequisites

- **Python**: Python 3.10 or newer (Python 3.12+ recommended).
- **Git**: For version control.
- **Operating Systems Supported for Development**: Linux (Ubuntu, Debian, Fedora, Arch, Kali), Windows 10/11, macOS (Intel & Apple Silicon).

---

## 3. Development Setup

```bash
# 1. Clone repository
git clone https://github.com/Shadab-2604/sscli.git
cd sscli

# 2. Provision isolated virtual environment
python3 -m venv .venv

# 3. Activate virtual environment
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Windows Command Prompt:
.venv\Scripts\activate.bat

# 4. Install in editable mode with development dependencies
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

---

## 4. Quality Standards & Pre-Commit Verification

Before submitting any code changes or opening a pull request, you must execute and pass all quality gates:

```bash
# Run the unified check runner (Format check -> Lint -> Type check -> Pytest with coverage)
python scripts/run_checks.py
```

Or run the individual tools manually:

```bash
# 1. Code Style & Linting
ruff check src tests

# 2. Code Formatting
ruff format --check src tests

# 3. Static Type Analysis
mypy src

# 4. Automated Test Suite with Coverage
pytest --cov=systemscan --cov-report=term-missing tests/
```

---

## 5. Branching & Commit Conventions

### Branch Naming:
- `feature/<short-description>`: New security scanner or intelligence feature.
- `fix/<issue-description>`: Bug fix or edge-case correction.
- `security/<hardening-topic>`: Vulnerability mitigation or security regression test.
- `docs/<topic>`: Documentation or guide improvements.

### Commit Messages:
Follow the Conventional Commits specification:
- `feat(malware): add heuristic PE header parsing for packed sections`
- `fix(network): handle timeout when querying inactive interfaces`
- `sec(cleanup): prevent TOCTOU file substitution during preview execution`
- `docs(install): document Arch Linux pacman dependencies`
- `test(security): add regression test for path traversal in update archive`

---

## 6. Architectural & Security Rules

1. **Non-Destructive Invariant**: Traversal, inspection, malware scanning, network auditing, and storage analysis must remain strictly read-only. Never modify, execute, or delete files during analysis.
2. **Explicit Confirmation for Deletions**: Cleanup operations require a pre-generated preview and explicit `--confirm` confirmation.
3. **No Raw Shell Invocations**: Never execute subprocesses with `shell=True`. Always pass array argument vectors and enforce bounded timeouts (2.0s–10.0s).
4. **Cross-Platform Portability**: Never hardcode file paths or `/` or `\` separators. Use `pathlib.Path` exclusively.
5. **Channel Isolation**: Console output intended for human viewing goes to `stderr` or Rich tables; stdout must remain clean for `--format json` pipelines.
6. **No Secret Leaks**: Hardware serial numbers, user home directory roots, and credentials must be redacted by default in reports and logs.

---

## 7. Submitting Pull Requests

1. Fork the repository and create your branch from `main`.
2. Ensure your changes include unit tests under `tests/unit/`.
3. Verify that `python scripts/run_checks.py` passes with 0 errors.
4. Push to your fork and submit a Pull Request using the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
5. A maintainer will review your pull request against our security threat model and test matrix.
