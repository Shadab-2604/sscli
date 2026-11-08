# Standalone Executable Evaluation & Packaging Strategy

**Application:** Universal System Security & Intelligence CLI (`systemscan`)  
**Phase:** 12 of 13 — Documentation, Packaging & Release Preparation  
**Status:** Evaluation Completed & Reference Build Specifications Documented

---

## 1. Executive Evaluation

Standalone single-binary executables (packaged via tools like **PyInstaller** or **Nuitka**) allow operators to deploy `systemscan` on systems where Python 3.10+ is not pre-installed (e.g., incident response triage systems or air-gapped forensic endpoints).

However, after architectural evaluation against production reliability, security, and maintenance constraints:
1. **Python Wheel & Virtual Environment Remains the Primary Distribution Method**: Wheel installations guarantee clean dependency resolution, complete standard library integrity, and zero friction with operating system security policies.
2. **Platform-Specific Binaries Are Mandatory**: There is no such thing as a "universal cross-platform binary". An executable built on Windows (`systemscan.exe`) cannot run on Linux or macOS. Separate artifacts must be compiled per OS and CPU architecture.
3. **Endpoint Security & Antivirus False Positives**: PyInstaller bootloader stubs frequently trigger heuristic false positives in corporate EDR / Antivirus tools (e.g., Windows Defender, CrowdStrike, SentinelOne) due to packed executable signatures. Operators must **never** be advised to disable endpoint security to run `systemscan`.

---

## 2. Comparison Matrix: Distribution Formats

| Dimension | Python Wheel (`.whl`) | PyInstaller Single-Binary | Nuitka Compiled Binary |
|---|---|---|---|
| **Primary Status** | **PRIMARY (Recommended)** | Optional / Incident Response | Experimental / High Maintenance |
| **Prerequisites** | Python 3.10+ | None (Self-contained) | None (Self-contained C binary) |
| **Cross-Platform Build** | Pure Python (`py3-none-any`) builds everywhere | Requires dedicated OS/Arch build runner | Requires C compiler per OS/Arch |
| **Artifact Size** | ~320 KB | ~35 MB – 55 MB | ~30 MB – 45 MB |
| **Startup Latency** | Instantaneous (< 0.15s) | Decompression overhead (~0.4s – 0.8s) | Native speed (< 0.1s) |
| **AV False Positives** | Zero (Standard script execution) | Moderate (Packed bootloader) | Low (Compiled C binary) |
| **Maintenance Burden** | Minimal (Standard hatchling) | High (Binary signing, runner matrix) | Very High (C-extension compatibility) |

---

## 3. Reference PyInstaller Build Recipe

For teams requiring single-binary incident response deployment, the reference build recipe is version-controlled:

### Prerequisites:
```bash
pip install pyinstaller
```

### Build Command (Windows):
```powershell
pyinstaller `
    --name systemscan `
    --onefile `
    --clean `
    --noconfirm `
    --hidden-import typer `
    --hidden-import rich `
    --hidden-import pydantic `
    --hidden-import platformdirs `
    --hidden-import psutil `
    --hidden-import cpuinfo `
    --hidden-import packaging `
    src/systemscan/__main__.py
```

### Build Command (Linux / macOS):
```bash
pyinstaller \
    --name systemscan \
    --onefile \
    --clean \
    --noconfirm \
    --hidden-import typer \
    --hidden-import rich \
    --hidden-import pydantic \
    --hidden-import platformdirs \
    --hidden-import psutil \
    --hidden-import cpuinfo \
    --hidden-import packaging \
    src/systemscan/__main__.py
```

---

## 4. Preserved Runtime Invariants in Frozen Binaries

When compiling with PyInstaller or Nuitka, `systemscan` guarantees:
1. **Application Data Resolution**: Uses `PlatformDirs` rather than `__file__`-relative assumptions for data storage (`config`, `reports`, `logs`), ensuring read/write operations succeed even when the binary extracts into temporary `_MEIxxxxxx` directories.
2. **Read-Only Code Integrity**: The bundled package filesystem is never written to; all state updates write to user data folders.
3. **No Insecure Execution Workarounds**: If an enterprise EDR flags a frozen binary, the recommended remediation is code-signing with an organizational certificate or utilizing standard virtual environment wheel installation.

