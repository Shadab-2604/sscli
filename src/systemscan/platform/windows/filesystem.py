"""Windows native filesystem, drive letters, long paths, and ACL provider."""

from __future__ import annotations

import os
from pathlib import Path

from systemscan.logging.logger import get_logger

logger = get_logger("platform.windows.filesystem")


class WindowsFilesystemProvider:
    """Windows filesystem path conventions, drive letters, UNC, and ACLs."""

    @staticmethod
    def get_standard_directories() -> dict[str, Path]:
        """Resolve standard Windows user and application directories."""
        user_profile = Path(os.environ.get("USERPROFILE", os.path.expanduser("~")))
        local_appdata = Path(os.environ.get("LOCALAPPDATA", user_profile / "AppData" / "Local"))
        appdata = Path(os.environ.get("APPDATA", user_profile / "AppData" / "Roaming"))
        temp_dir = Path(os.environ.get("TEMP", local_appdata / "Temp"))

        return {
            "profile": user_profile,
            "local_appdata": local_appdata,
            "appdata": appdata,
            "temp": temp_dir,
        }

    @staticmethod
    def normalize_long_path(path: str | Path) -> str:
        """Add Windows extended-length prefix (\\\\?\\) if path exceeds MAX_PATH (260 chars)."""
        p_str = str(path)
        if len(p_str) > 240 and not p_str.startswith(("\\\\?\\", "\\\\.\\")):
            abs_path = os.path.abspath(p_str)
            if abs_path.startswith("\\\\"):
                return "\\\\?\\UNC\\" + abs_path[2:]
            return "\\\\?\\" + abs_path
        return p_str

    @staticmethod
    def get_drive_letters() -> list[str]:
        """Enumerate all available logical Windows drive letters (e.g. C:, D:)."""
        drives: list[str] = []
        try:
            import ctypes

            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
        except Exception as e:
            logger.debug(f"Failed enumerating Windows drive bitmask: {e}")
            if os.path.exists("C:\\"):
                drives.append("C:\\")

        return drives
