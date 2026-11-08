"""Windows platform adapter implementation for systemscan."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import winreg
from typing import Any

from systemscan.logging.logger import get_logger
from systemscan.modules.models import (
    DiskInformation,
    FirmwareInformation,
    GPUInformation,
    ServiceInformation,
    StartupEntry,
)
from systemscan.platform.base import (
    CapabilityStatus,
    OSType,
    PlatformCapabilities,
    PlatformInterface,
)

logger = get_logger("platform.windows")


class WindowsPlatform(PlatformInterface):
    """Windows-specific platform provider implementing native telemetry."""

    @property
    def os_type(self) -> OSType:
        return OSType.WINDOWS

    @property
    def os_name(self) -> str:
        return f"Windows {platform.release()}"

    @property
    def os_version(self) -> str:
        return platform.version()

    @property
    def architecture(self) -> str:
        return platform.machine()

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(
            can_inspect_posix_permissions=False,
            can_inspect_windows_acls=True,
            can_inspect_systemd=False,
            can_inspect_launchd=False,
            can_inspect_windows_services=True,
            can_access_raw_disks=False,
            requires_elevation_for_hardware=False,
        )

    def is_elevated(self) -> bool:
        """Check for Windows Administrator privileges."""
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def get_system_summary(self) -> dict[str, Any]:
        return {
            "os": self.os_name,
            "version": self.os_version,
            "architecture": self.architecture,
            "platform_string": platform.platform(),
            "is_admin": self.is_elevated(),
            "windows_edition": getattr(platform, "win32_edition", lambda: "Unknown")(),
        }

    def get_linux_distribution(self) -> tuple[str | None, str | None]:
        return (None, None)

    def get_firmware_info(self, include_serials: bool = False) -> FirmwareInformation:
        """Retrieve Motherboard, BIOS, and UEFI firmware from Windows Registry."""
        info = FirmwareInformation()

        # 1. Read registry hardware description
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS"
            ) as key:

                def _reg_val(name: str) -> str | None:
                    try:
                        val, _ = winreg.QueryValueEx(key, name)
                        return str(val).strip() if val else None
                    except OSError:
                        return None

                info.bios_vendor = _reg_val("BIOSVendor")
                info.bios_version = _reg_val("BIOSVersion")
                info.bios_release_date = _reg_val("BIOSReleaseDate")
                info.manufacturer = _reg_val("SystemManufacturer") or _reg_val(
                    "BaseBoardManufacturer"
                )
                info.product_model = _reg_val("SystemProductName") or _reg_val("BaseBoardProduct")

                if include_serials:
                    info.serial_number = _reg_val("SystemSerialNumber") or _reg_val(
                        "BaseBoardSerialNumber"
                    )
                else:
                    info.serial_number = "[REDACTED] (Use --include-serials to reveal)"

                info.firmware_type = "UEFI"  # Modern Windows standard
        except OSError as e:
            logger.debug(f"Could not read BIOS registry on Windows: {e}")

        return info

    def get_gpus(self) -> list[GPUInformation]:
        """Discover installed graphics adapters using PowerShell CIM queries."""
        gpus: list[GPUInformation] = []
        ps_cmd = (
            "Get-CimInstance Win32_VideoController | "
            "Select-Object Caption, Description, DriverVersion, AdapterRAM, Status | "
            "ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout)
                entries = [raw] if isinstance(raw, dict) else raw
                for entry in entries:
                    name = entry.get("Caption") or entry.get("Description") or "Unknown GPU"
                    driver = entry.get("DriverVersion")
                    ram = entry.get("AdapterRAM")
                    status = entry.get("Status") or "active"

                    # Detect vendor from name
                    vendor = "Unknown"
                    name_lower = name.lower()
                    if "nvidia" in name_lower:
                        vendor = "NVIDIA"
                    elif "amd" in name_lower or "radeon" in name_lower:
                        vendor = "AMD"
                    elif "intel" in name_lower:
                        vendor = "Intel"

                    gpus.append(
                        GPUInformation(
                            vendor=vendor,
                            model=name,
                            driver_version=str(driver) if driver else None,
                            memory_total_bytes=int(ram) if ram and ram > 0 else None,
                            status=str(status).lower(),
                        )
                    )
        except Exception as e:
            logger.debug(f"Could not query Win32_VideoController: {e}")

        return gpus

    def get_services(self, status_filter: str | None = None) -> list[ServiceInformation]:
        """Query Windows services using PowerShell CIM."""
        services: list[ServiceInformation] = []
        ps_cmd = (
            "Get-CimInstance Win32_Service | "
            "Select-Object Name, DisplayName, State, StartMode, Description | "
            "ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout)
                entries = [raw] if isinstance(raw, dict) else raw
                for entry in entries:
                    state = str(entry.get("State", "unknown")).lower()
                    if status_filter and status_filter.lower() not in (state, "all"):
                        continue

                    services.append(
                        ServiceInformation(
                            name=str(entry.get("Name", "")),
                            display_name=entry.get("DisplayName"),
                            status=state,
                            startup_type=entry.get("StartMode"),
                            description=entry.get("Description"),
                        )
                    )
        except Exception as e:
            logger.debug(f"Could not query Windows services: {e}")

        return services

    def get_startup_entries(self) -> list[StartupEntry]:
        """Enumerate startup applications from Registry Run keys and Startup directories."""
        entries: list[StartupEntry] = []

        # 1. Registry Run Keys
        reg_targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "user"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "system"),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                "system",
            ),
        ]

        for root_key, subkey, scope in reg_targets:
            try:
                with winreg.OpenKey(root_key, subkey) as key:
                    idx = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(key, idx)
                            entries.append(
                                StartupEntry(
                                    name=name,
                                    source=f"Registry ({'HKCU' if root_key == winreg.HKEY_CURRENT_USER else 'HKLM'}) Run",
                                    command=str(val),
                                    scope=scope,
                                    status="enabled",
                                )
                            )
                            idx += 1
                        except OSError:
                            break
            except OSError:
                continue

        # 2. Startup Folders
        user_startup = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        common_startup = os.path.expandvars(
            r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        )

        for folder, scope, src_name in [
            (user_startup, "user", "User Startup Folder"),
            (common_startup, "system", "Common Startup Folder"),
        ]:
            if os.path.isdir(folder):
                try:
                    for fname in os.listdir(folder):
                        if fname.lower() != "desktop.ini":
                            full_path = os.path.join(folder, fname)
                            entries.append(
                                StartupEntry(
                                    name=fname,
                                    source=src_name,
                                    command=full_path,
                                    scope=scope,
                                    status="enabled",
                                )
                            )
                except OSError:
                    pass

        return entries

    def get_physical_disks(self) -> list[DiskInformation]:
        """Query physical storage disk drives on Windows."""
        disks: list[DiskInformation] = []
        ps_cmd = (
            "Get-CimInstance Win32_DiskDrive | "
            "Select-Object DeviceID, Model, Size, MediaType, Partitions | "
            "ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout)
                entries = [raw] if isinstance(raw, dict) else raw
                for entry in entries:
                    dev_id = str(entry.get("DeviceID", "Unknown"))
                    model = entry.get("Model")
                    size = entry.get("Size")
                    media_type = str(entry.get("MediaType", "")).lower()
                    is_removable = (
                        "removable" in media_type or "external" in str(model or "").lower()
                    )

                    disks.append(
                        DiskInformation(
                            name=dev_id,
                            model=model,
                            size_bytes=int(size) if size and size > 0 else None,
                            is_removable=is_removable,
                            is_physical=True,
                            partitions=[],
                        )
                    )
        except Exception as e:
            logger.debug(f"Could not query physical disks via Win32_DiskDrive: {e}")

        return disks

    def get_capabilities_matrix(self) -> dict[str, CapabilityStatus]:
        """Return the capability evaluation matrix for Windows."""
        import shutil

        return {
            "hardware_gpu": CapabilityStatus.AVAILABLE,
            "hardware_motherboard": CapabilityStatus.AVAILABLE,
            "hardware_disks": CapabilityStatus.AVAILABLE,
            "services_inspection": CapabilityStatus.AVAILABLE,
            "startup_persistence": CapabilityStatus.AVAILABLE,
            "network_firewall": CapabilityStatus.AVAILABLE,
            "network_interfaces": CapabilityStatus.AVAILABLE,
            "network_connections": CapabilityStatus.AVAILABLE,
            "network_wifi": CapabilityStatus.AVAILABLE,
            "devices_usb": CapabilityStatus.AVAILABLE,
            "filesystem_posix_permissions": CapabilityStatus.UNSUPPORTED,
            "filesystem_windows_acls": CapabilityStatus.AVAILABLE,
            "filesystem_symlinks": (
                CapabilityStatus.AVAILABLE
                if self.is_elevated()
                else CapabilityStatus.PARTIALLY_AVAILABLE
            ),
            "malware_yara": (
                CapabilityStatus.AVAILABLE
                if shutil.which("yara")
                else CapabilityStatus.PARTIALLY_AVAILABLE
            ),
        }
