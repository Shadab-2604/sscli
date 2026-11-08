"""Windows native system intelligence, registry inspection, and service enumeration."""

from __future__ import annotations

import winreg

from systemscan.logging.logger import get_logger
from systemscan.modules.models import ServiceInformation, StartupEntry

logger = get_logger("platform.windows.system")


class WindowsSystemProvider:
    """Windows-specific host inspection via Win32 APIs, Registry, and SCM."""

    @staticmethod
    def is_elevated() -> bool:
        """Check for Windows Administrator privileges."""
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def get_services(limit: int = 100) -> list[ServiceInformation]:
        """Query Windows Service Control Manager (SCM) via psutil."""
        import psutil

        services: list[ServiceInformation] = []
        try:
            for s in psutil.win_service_iter():
                try:
                    s_info = s.as_dict()
                    services.append(
                        ServiceInformation(
                            name=s_info.get("name", "Unknown"),
                            display_name=s_info.get("display_name", s_info.get("name", "")),
                            status=s_info.get("status", "unknown"),
                            startup_type=s_info.get("start_type", "unknown"),
                            description=s_info.get("description") or "",
                        )
                    )
                except Exception:
                    continue
                if len(services) >= limit:
                    break
        except Exception as e:
            logger.debug(f"Failed enumerating Windows services: {e}")

        return services

    @staticmethod
    def get_startup_entries() -> list[StartupEntry]:
        """Inspect standard Windows Registry Run keys for startup persistence."""
        entries: list[StartupEntry] = []
        keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        ]

        for hive, subkey, label in keys:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                    idx = 0
                    while True:
                        try:
                            val_name, val_data, _ = winreg.EnumValue(k, idx)
                            entries.append(
                                StartupEntry(
                                    name=val_name,
                                    command=str(val_data),
                                    source=label,
                                    scope="user" if "HKCU" in label else "system",
                                    status="enabled",
                                )
                            )
                            idx += 1
                        except OSError:
                            break
            except Exception as e:
                logger.debug(f"Could not read registry startup key {label}: {e}")

        return entries
