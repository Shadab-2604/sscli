"""USB and external drive diagnostics, filesystem repair, shortcut virus remediation, and file carving."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger("systemscan.devices.repair")

# Common file signatures for file carving / data recovery
FILE_SIGNATURES: list[dict[str, Any]] = [
    {"name": "JPEG Image", "header": b"\xff\xd8\xff", "trailer": b"\xff\xd9", "ext": ".jpg"},
    {
        "name": "PNG Image",
        "header": b"\x89PNG\r\n\x1a\n",
        "trailer": b"IEND\xaeB`\x82",
        "ext": ".png",
    },
    {"name": "PDF Document", "header": b"%PDF-", "trailer": b"%%EOF", "ext": ".pdf"},
    {"name": "ZIP / Office Archive", "header": b"PK\x03\x04", "trailer": None, "ext": ".zip"},
    {"name": "MP3 Audio", "header": b"ID3", "trailer": None, "ext": ".mp3"},
    {"name": "RIFF Media (WAV/AVI)", "header": b"RIFF", "trailer": None, "ext": ".riff"},
]


class StorageRepairEngine:
    """Provides filesystem diagnostics, interactive repair commands, shortcut virus cleanup, and carving."""

    @staticmethod
    def normalize_drive_target(target: str) -> str:
        """Normalize drive input to a clean Windows drive letter (e.g. 'E:') or preserve path."""
        target = target.strip()
        if target.startswith("/"):
            return target
        if platform.system() == "Windows":
            clean = target.rstrip("\\/")
            if len(clean) == 1 and clean.isalpha():
                return f"{clean.upper()}:"
            if len(clean) == 2 and clean[1] == ":" and clean[0].isalpha():
                return clean.upper()
            return target
        return target

    @classmethod
    def check_filesystem_corruption(cls, target: str) -> dict[str, Any]:
        """
        Perform a safe, read-only diagnostic check for dirty bits and filesystem errors.
        Does NOT alter or write to the filesystem.
        """
        norm_target = cls.normalize_drive_target(target)
        system_os = platform.system()
        result: dict[str, Any] = {
            "target": norm_target,
            "os": system_os,
            "is_corrupted": False,
            "dirty_bit": False,
            "details": [],
            "raw_output": "",
        }

        if system_os == "Windows":
            # 1. Query Dirty Bit via fsutil
            try:
                fsutil_cmd = ["fsutil", "dirty", "query", norm_target]
                fs_proc = subprocess.run(
                    fsutil_cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                output = fs_proc.stdout.strip()
                result["raw_output"] += f"--- fsutil dirty query ---\n{output}\n\n"
                if "access is denied" in output.lower() or "error 5" in output.lower():
                    result["details"].append(
                        f"fsutil query requires administrator privileges to inspect dirty bit on {norm_target}."
                    )
                elif "is dirty" in output.lower():
                    result["dirty_bit"] = True
                    result["is_corrupted"] = True
                    result["details"].append(
                        f"Volume dirty bit is SET on {norm_target} (indicates unclean unmount or filesystem corruption)."
                    )
                elif "is not dirty" in output.lower():
                    result["details"].append(
                        f"Volume dirty bit is NOT set on {norm_target} (volume was cleanly unmounted)."
                    )
                else:
                    result["details"].append(f"fsutil status: {output}")
            except Exception as e:
                result["details"].append(f"fsutil query notice: {e}")

            # 2. Run Read-Only chkdsk (no /F switch, so safe and read-only)
            try:
                chkdsk_cmd = ["chkdsk", norm_target]
                chk_proc = subprocess.run(
                    chkdsk_cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=45,
                )
                chk_output = chk_proc.stdout
                result["raw_output"] += f"--- chkdsk (read-only) ---\n{chk_output}\n"

                # Check indicators in chkdsk output
                lower_out = chk_output.lower()
                if (
                    "found errors" in lower_out
                    or "corrupt" in lower_out
                    or "bad sectors" in lower_out
                    or "file system errors" in lower_out
                ):
                    result["is_corrupted"] = True
                    result["details"].append(
                        "chkdsk reported active filesystem structure errors or bad sectors."
                    )
                elif (
                    "windows has scanned the file system and found no problems" in lower_out
                    or "no problems found" in lower_out
                ):
                    result["details"].append(
                        "chkdsk verified volume integrity: No filesystem errors found."
                    )
                else:
                    result["details"].append("chkdsk completed inspection.")
            except Exception as e:
                result["details"].append(f"chkdsk inspection notice: {e}")

        elif system_os == "Linux":
            # Read-only fsck (-n)
            try:
                cmd = ["fsck", "-n", norm_target]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                result["raw_output"] = proc.stdout + proc.stderr
                if proc.returncode != 0:
                    result["is_corrupted"] = True
                    result["details"].append(
                        f"fsck returned non-zero exit code ({proc.returncode}); errors detected."
                    )
                else:
                    result["details"].append("fsck verified filesystem is clean.")
            except Exception as e:
                result["details"].append(f"Linux fsck execution notice: {e}")

        elif system_os == "Darwin":
            try:
                cmd = ["diskutil", "verifyVolume", norm_target]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                result["raw_output"] = proc.stdout + proc.stderr
                if proc.returncode != 0:
                    result["is_corrupted"] = True
                    result["details"].append(
                        f"diskutil verify reported volume errors ({proc.returncode})."
                    )
                else:
                    result["details"].append("diskutil verified volume integrity.")
            except Exception as e:
                result["details"].append(f"macOS diskutil notice: {e}")

        return result

    @classmethod
    def repair_filesystem(cls, target: str, scan_bad_sectors: bool = False) -> dict[str, Any]:
        """
        Execute active filesystem repair on specified drive target.
        Runs chkdsk /f (or /r) on Windows, or fsck -y on Linux.
        """
        norm_target = cls.normalize_drive_target(target)
        system_os = platform.system()
        res: dict[str, Any] = {
            "target": norm_target,
            "success": False,
            "exit_code": -1,
            "output": "",
            "message": "",
        }

        if system_os == "Windows":
            flags = ["/r", "/x"] if scan_bad_sectors else ["/f", "/x"]
            cmd = ["chkdsk", norm_target, *flags]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                res["exit_code"] = proc.returncode
                res["output"] = proc.stdout + proc.stderr
                if proc.returncode in (0, 1):  # 0 = No errors, 1 = Errors found and fixed
                    res["success"] = True
                    res["message"] = f"chkdsk successfully repaired volume {norm_target}."
                elif proc.returncode == 2:
                    res["message"] = (
                        "chkdsk scheduled on next reboot or volume is locked by active processes."
                    )
                elif proc.returncode == 3:
                    res["message"] = (
                        "chkdsk could not lock the drive; admin privileges required or drive is busy."
                    )
                else:
                    res["message"] = f"chkdsk exited with code {proc.returncode}."
            except Exception as e:
                res["message"] = f"chkdsk invocation error: {e}"

        elif system_os == "Linux":
            cmd = ["fsck", "-y", norm_target]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                res["exit_code"] = proc.returncode
                res["output"] = proc.stdout + proc.stderr
                if proc.returncode in (0, 1):
                    res["success"] = True
                    res["message"] = f"fsck successfully repaired filesystem {norm_target}."
                else:
                    res["message"] = f"fsck exited with code {proc.returncode}."
            except Exception as e:
                res["message"] = f"fsck invocation error: {e}"

        elif system_os == "Darwin":
            cmd = ["diskutil", "repairVolume", norm_target]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                res["exit_code"] = proc.returncode
                res["output"] = proc.stdout + proc.stderr
                if proc.returncode == 0:
                    res["success"] = True
                    res["message"] = f"diskutil repairVolume succeeded on {norm_target}."
                else:
                    res["message"] = f"diskutil exited with code {proc.returncode}."
            except Exception as e:
                res["message"] = f"diskutil repair error: {e}"

        return res

    @classmethod
    def remediate_shortcut_virus_and_unhide(cls, target_path: str) -> dict[str, Any]:
        """
        Remediate USB shortcut virus infections:
        1. Strips hidden/system attributes from all files and folders (attrib -h -r -s /s /d).
        2. Detects and inventories malicious .lnk shortcuts pointing to wscript, cscript, powershell, or cmd.
        3. Identifies suspicious autorun.inf or hidden script droppers.
        """
        p = Path(target_path)
        if not p.is_dir():
            norm_target = cls.normalize_drive_target(target_path)
            p = Path(norm_target if norm_target.endswith(("\\", "/")) else f"{norm_target}\\")
        if not p.exists():
            p = Path(target_path)

        res: dict[str, Any] = {
            "target": str(p),
            "unhidden_count": 0,
            "suspicious_shortcuts": [],
            "autorun_droppers": [],
            "status": "COMPLETED",
        }

        # Step 1: Unhide all files using Windows API on Windows or POSIX permissions on Unix
        if platform.system() == "Windows":
            try:
                import ctypes

                FILE_ATTRIBUTE_NORMAL = 0x80
                for item in p.rglob("*"):
                    try:
                        if ctypes.windll.kernel32.SetFileAttributesW(
                            str(item), FILE_ATTRIBUTE_NORMAL
                        ):
                            res["unhidden_count"] += 1
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Native attribute reset note: {e}")
        else:
            try:
                for item in p.rglob("*"):
                    try:
                        os.chmod(item, 0o755)
                        res["unhidden_count"] += 1
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"POSIX chmod note: {e}")

        # Step 2: Python filesystem sweep for malicious shortcuts & hidden droppers
        try:
            for item in p.rglob("*"):
                # Safety cap
                if len(res["suspicious_shortcuts"]) > 100:
                    break

                try:
                    name_lower = item.name.lower()

                    # Check for autorun.inf
                    if name_lower == "autorun.inf":
                        res["autorun_droppers"].append(str(item))

                    # Check for malicious .lnk shortcuts
                    if item.is_file() and name_lower.endswith(".lnk"):
                        # Read first 1KB of shortcut to inspect command target
                        try:
                            with open(item, "rb") as f:
                                lnk_bytes = f.read(2048)
                            lnk_text = lnk_bytes.decode("ascii", errors="ignore").lower()
                            if any(
                                susp in lnk_text
                                for susp in (
                                    "wscript",
                                    "cscript",
                                    "powershell",
                                    "cmd.exe",
                                    "mshta",
                                    ".vbs",
                                    ".js",
                                    ".bat",
                                )
                            ):
                                res["suspicious_shortcuts"].append(str(item))
                        except Exception:
                            pass

                except (PermissionError, OSError):
                    continue

        except Exception as e:
            res["status"] = f"Partial scan: {e}"

        return res

    @classmethod
    def carve_lost_files(
        cls, target_dir_or_drive: str, max_samples: int = 50
    ) -> list[dict[str, Any]]:
        """
        Perform fast signature-based file carving across readable blocks or corrupted directories
        to locate recoverable file headers (JPG, PNG, PDF, ZIP, MP3).
        """
        p = Path(target_dir_or_drive)
        if not p.is_dir():
            norm = cls.normalize_drive_target(target_dir_or_drive)
            p = Path(norm if norm.endswith(("\\", "/")) else f"{norm}\\")
        if not p.exists():
            p = Path(target_dir_or_drive)

        recoverable_items: list[dict[str, Any]] = []

        if not p.exists():
            return recoverable_items

        try:
            # Inspect files or lost directories
            for item in p.rglob("*"):
                if len(recoverable_items) >= max_samples:
                    break
                if not item.is_file():
                    continue

                try:
                    size = item.stat().st_size
                    # Only carve files that are unassociated or potentially corrupt (e.g. .chk, .bin, .tmp, extensionless)
                    ext = item.suffix.lower()
                    if (
                        ext in (".chk", ".bin", ".tmp", ".dat", ".raw", "")
                        or size < 100 * 1024 * 1024
                    ):
                        with open(item, "rb") as f:
                            header_bytes = f.read(512)

                        for sig in FILE_SIGNATURES:
                            if header_bytes.startswith(sig["header"]):
                                recoverable_items.append(
                                    {
                                        "path": str(item),
                                        "detected_format": sig["name"],
                                        "recommended_ext": sig["ext"],
                                        "size_bytes": size,
                                    }
                                )
                                break
                except (PermissionError, OSError):
                    continue
        except Exception as e:
            logger.debug(f"Carving notice: {e}")

        return recoverable_items
