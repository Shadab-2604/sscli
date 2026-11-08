"""macOS platform adapter implementation for systemscan."""

from __future__ import annotations

import os
import platform
import plistlib
import subprocess
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

logger = get_logger("platform.macos")


class MacOSPlatform(PlatformInterface):
    """macOS-specific platform provider implementing native telemetry."""

    @property
    def os_type(self) -> OSType:
        return OSType.MACOS

    @property
    def os_name(self) -> str:
        mac_ver = platform.mac_ver()[0]
        return f"macOS {mac_ver}" if mac_ver else "macOS"

    @property
    def os_version(self) -> str:
        return platform.mac_ver()[0] or platform.release()

    @property
    def architecture(self) -> str:
        return platform.machine()

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(
            can_inspect_posix_permissions=True,
            can_inspect_windows_acls=False,
            can_inspect_systemd=False,
            can_inspect_launchd=True,
            can_inspect_windows_services=False,
            can_access_raw_disks=os.geteuid() == 0 if hasattr(os, "geteuid") else False,
            requires_elevation_for_hardware=False,
        )

    def is_elevated(self) -> bool:
        """Check for macOS root privileges."""
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def get_system_summary(self) -> dict[str, Any]:
        return {
            "os": self.os_name,
            "version": self.os_version,
            "architecture": self.architecture,
            "platform_string": platform.platform(),
            "is_root": self.is_elevated(),
        }

    def get_linux_distribution(self) -> tuple[str | None, str | None]:
        return (None, None)

    def get_firmware_info(self, include_serials: bool = False) -> FirmwareInformation:
        """Retrieve Mac hardware model and serial using system_profiler."""
        info = FirmwareInformation(
            manufacturer="Apple Inc.",
            firmware_type="Apple EFI / iBoot",
        )
        try:
            res = subprocess.run(
                ["system_profiler", "SPHardwareDataType", "-detailLevel", "mini"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if "Model Name:" in line:
                        info.product_model = line.split(":", 1)[1].strip()
                    elif "Serial Number" in line:
                        if include_serials:
                            info.serial_number = line.split(":", 1)[1].strip()
                        else:
                            info.serial_number = "[REDACTED] (Use --include-serials to reveal)"
                    elif "Boot ROM Version:" in line or "System Firmware Version:" in line:
                        info.bios_version = line.split(":", 1)[1].strip()
        except Exception as e:
            logger.debug(f"Could not query SPHardwareDataType on macOS: {e}")

        return info

    def get_gpus(self) -> list[GPUInformation]:
        """Query displays and GPU devices on macOS."""
        gpus: list[GPUInformation] = []
        try:
            res = subprocess.run(
                ["system_profiler", "SPDisplaysDataType", "-detailLevel", "mini"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                current_gpu: dict[str, str] = {}
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if "Chipset Model:" in line:
                        if current_gpu:
                            gpus.append(
                                GPUInformation(
                                    vendor=current_gpu.get("vendor", "Apple"),
                                    model=current_gpu.get("model", "Graphics Device"),
                                    status="active",
                                )
                            )
                            current_gpu = {}
                        model = line.split(":", 1)[1].strip()
                        vendor = (
                            "Apple"
                            if "Apple" in model
                            else ("NVIDIA" if "NVIDIA" in model else "AMD")
                        )
                        current_gpu = {"model": model, "vendor": vendor}
                    elif "VRAM (Total):" in line or "Total Number of Cores:" in line:
                        current_gpu["cores_or_vram"] = line.split(":", 1)[1].strip()

                if current_gpu:
                    gpus.append(
                        GPUInformation(
                            vendor=current_gpu.get("vendor", "Apple"),
                            model=current_gpu.get("model", "Graphics Device"),
                            status="active",
                        )
                    )
        except Exception as e:
            logger.debug(f"Could not query SPDisplaysDataType on macOS: {e}")

        return gpus

    def get_services(self, status_filter: str | None = None) -> list[ServiceInformation]:
        """Query launchd services on macOS."""
        services: list[ServiceInformation] = []
        try:
            res = subprocess.run(
                ["launchctl", "list"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                # Skip header: PID Status Label
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        pid, _status_code, label = parts[0], parts[1], parts[2]
                        status = "running" if pid != "-" else "stopped"
                        if status_filter and status_filter.lower() not in (status, "all"):
                            continue
                        services.append(
                            ServiceInformation(
                                name=label,
                                status=status,
                                startup_type="launchd",
                            )
                        )
        except Exception as e:
            logger.debug(f"Could not query launchctl on macOS: {e}")

        return services

    def get_startup_entries(self) -> list[StartupEntry]:
        """Discover LaunchAgents and LaunchDaemons persistence entries on macOS."""
        entries: list[StartupEntry] = []
        targets = [
            (os.path.expanduser("~/Library/LaunchAgents"), "user", "User LaunchAgent"),
            ("/Library/LaunchAgents", "system", "System LaunchAgent"),
            ("/Library/LaunchDaemons", "system", "System LaunchDaemon"),
        ]

        for folder, scope, src_name in targets:
            if os.path.isdir(folder):
                try:
                    for fname in os.listdir(folder):
                        if fname.endswith(".plist"):
                            full_path = os.path.join(folder, fname)
                            program = full_path
                            try:
                                with open(full_path, "rb") as f:
                                    plist_data = plistlib.load(f)
                                    program = plist_data.get("Program") or str(
                                        plist_data.get("ProgramArguments", full_path)
                                    )
                            except Exception:
                                pass

                            entries.append(
                                StartupEntry(
                                    name=fname,
                                    source=src_name,
                                    command=str(program),
                                    scope=scope,
                                    status="enabled",
                                )
                            )
                except OSError:
                    pass

        return entries

    def get_physical_disks(self) -> list[DiskInformation]:
        """Discover physical disks via diskutil list."""
        disks: list[DiskInformation] = []
        try:
            res = subprocess.run(
                ["diskutil", "list", "-plist"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                plist_data = plistlib.loads(res.stdout)
                for disk_id in plist_data.get("WholeDisks", []):
                    disks.append(
                        DiskInformation(
                            name=f"/dev/{disk_id}",
                            is_physical=True,
                            is_removable=False,
                            partitions=[],
                        )
                    )
        except Exception as e:
            logger.debug(f"Could not query diskutil on macOS: {e}")

        return disks

    def get_capabilities_matrix(self) -> dict[str, CapabilityStatus]:
        """Return the capability evaluation matrix for macOS (Intel & Apple Silicon)."""
        import shutil

        has_sp = bool(shutil.which("system_profiler"))
        has_alf = os.path.exists("/usr/libexec/ApplicationFirewall/socketfilterfw") or bool(
            shutil.which("pfctl")
        )

        return {
            "hardware_gpu": CapabilityStatus.AVAILABLE
            if has_sp
            else CapabilityStatus.PARTIALLY_AVAILABLE,
            "hardware_motherboard": CapabilityStatus.AVAILABLE,
            "hardware_disks": CapabilityStatus.AVAILABLE,
            "services_inspection": CapabilityStatus.AVAILABLE,
            "startup_persistence": CapabilityStatus.AVAILABLE,
            "network_firewall": CapabilityStatus.AVAILABLE
            if has_alf
            else CapabilityStatus.PARTIALLY_AVAILABLE,
            "network_interfaces": CapabilityStatus.AVAILABLE,
            "network_connections": CapabilityStatus.AVAILABLE,
            "network_wifi": CapabilityStatus.AVAILABLE
            if shutil.which("networksetup")
            else CapabilityStatus.PARTIALLY_AVAILABLE,
            "devices_usb": CapabilityStatus.AVAILABLE,
            "filesystem_posix_permissions": CapabilityStatus.AVAILABLE,
            "filesystem_windows_acls": CapabilityStatus.UNSUPPORTED,
            "filesystem_symlinks": CapabilityStatus.AVAILABLE,
            "malware_yara": (
                CapabilityStatus.AVAILABLE
                if shutil.which("yara")
                else CapabilityStatus.PARTIALLY_AVAILABLE
            ),
        }
