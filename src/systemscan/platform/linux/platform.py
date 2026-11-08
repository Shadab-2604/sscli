"""Linux platform adapter implementation for systemscan."""

from __future__ import annotations

import json
import os
import platform
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

logger = get_logger("platform.linux")


class LinuxPlatform(PlatformInterface):
    """Linux-specific platform provider implementing native telemetry."""

    @property
    def os_type(self) -> OSType:
        return OSType.LINUX

    @property
    def os_name(self) -> str:
        distro, ver = self.get_linux_distribution()
        if distro:
            return f"{distro} {ver}".strip()
        return f"Linux ({platform.release()})"

    @property
    def os_version(self) -> str:
        return platform.release()

    @property
    def architecture(self) -> str:
        return platform.machine()

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(
            can_inspect_posix_permissions=True,
            can_inspect_windows_acls=False,
            can_inspect_systemd=os.path.isdir("/run/systemd/system"),
            can_inspect_launchd=False,
            can_inspect_windows_services=False,
            can_access_raw_disks=os.geteuid() == 0 if hasattr(os, "geteuid") else False,
            requires_elevation_for_hardware=False,
        )

    def is_elevated(self) -> bool:
        """Check for Linux root privileges."""
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def get_system_summary(self) -> dict[str, Any]:
        distro, ver = self.get_linux_distribution()
        return {
            "os": self.os_name,
            "distro_name": distro or "Unknown",
            "distro_version": ver or "Unknown",
            "kernel": platform.release(),
            "architecture": self.architecture,
            "platform_string": platform.platform(),
            "is_root": self.is_elevated(),
        }

    def get_linux_distribution(self) -> tuple[str | None, str | None]:
        """Parse Linux distribution name and version from standard files."""
        # 1. /etc/os-release (freedesktop standard)
        for release_path in ("/etc/os-release", "/usr/lib/os-release"):
            if os.path.exists(release_path):
                try:
                    with open(release_path, encoding="utf-8") as f:
                        data = {}
                        for line in f:
                            line = line.strip()
                            if "=" in line and not line.startswith("#"):
                                k, v = line.split("=", 1)
                                data[k.strip()] = v.strip().strip('"').strip("'")
                        name = data.get("PRETTY_NAME") or data.get("NAME")
                        version = data.get("VERSION_ID") or data.get("VERSION", "")
                        if name:
                            return (name, version)
                except OSError:
                    pass

        # 2. Legacy release files
        if os.path.exists("/etc/debian_version"):
            try:
                with open("/etc/debian_version", encoding="utf-8") as f:
                    return ("Debian", f.read().strip())
            except OSError:
                pass

        if os.path.exists("/etc/arch-release"):
            return ("Arch Linux", "Rolling")

        return (None, None)

    def get_firmware_info(self, include_serials: bool = False) -> FirmwareInformation:
        """Read firmware and motherboard metadata from /sys/class/dmi/id."""
        info = FirmwareInformation()
        dmi_dir = "/sys/class/dmi/id"

        def _read_dmi(name: str) -> str | None:
            path = os.path.join(dmi_dir, name)
            if os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        return f.read().strip() or None
                except OSError:
                    return None
            return None

        info.bios_vendor = _read_dmi("bios_vendor")
        info.bios_version = _read_dmi("bios_version")
        info.bios_release_date = _read_dmi("bios_date")
        info.manufacturer = _read_dmi("sys_vendor") or _read_dmi("board_vendor")
        info.product_model = _read_dmi("product_name") or _read_dmi("board_name")
        info.firmware_type = "UEFI" if os.path.isdir("/sys/firmware/efi") else "BIOS"

        if include_serials:
            info.serial_number = _read_dmi("product_serial") or _read_dmi("board_serial")
        else:
            info.serial_number = "[REDACTED] (Use --include-serials to reveal)"

        return info

    def get_gpus(self) -> list[GPUInformation]:
        """Discover graphics cards using lspci or nvidia-smi."""
        gpus: list[GPUInformation] = []

        # 1. Check lspci
        try:
            res = subprocess.run(
                ["lspci", "-mm"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    # Format: Slot "Class" "Vendor" "Device" ...
                    line_lower = line.lower()
                    if (
                        "vga" in line_lower
                        or "3d controller" in line_lower
                        or "display" in line_lower
                    ):
                        parts = [p.strip().strip('"') for p in line.split('" "')]
                        vendor = parts[1] if len(parts) > 1 else "Unknown"
                        model = parts[2] if len(parts) > 2 else line
                        gpus.append(
                            GPUInformation(
                                vendor=vendor,
                                model=model,
                                status="detected",
                            )
                        )
        except Exception:
            pass

        # 2. Check NVIDIA SMI if present for real-time telemetry
        try:
            res = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=gpu_name,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                # Replace generic lspci with deep nvidia-smi info
                nv_gpus: list[GPUInformation] = []
                for line in res.stdout.strip().splitlines():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 6:
                        name, driver, mem_total, mem_used, util, temp = parts[:6]
                        nv_gpus.append(
                            GPUInformation(
                                vendor="NVIDIA",
                                model=name,
                                driver_version=driver,
                                memory_total_bytes=int(float(mem_total) * 1024 * 1024)
                                if mem_total
                                else None,
                                memory_used_bytes=int(float(mem_used) * 1024 * 1024)
                                if mem_used
                                else None,
                                utilization_percent=float(util) if util else None,
                                temperature_celsius=float(temp) if temp else None,
                                status="active",
                            )
                        )
                if nv_gpus:
                    return nv_gpus
        except Exception:
            pass

        return gpus

    def get_services(self, status_filter: str | None = None) -> list[ServiceInformation]:
        """Enumerate systemd services on Linux."""
        services: list[ServiceInformation] = []
        try:
            res = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--no-pager",
                    "--no-legend",
                ],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split(None, 4)
                    if len(parts) >= 4:
                        unit, load, active, sub = parts[:4]
                        desc = parts[4] if len(parts) > 4 else ""
                        status = "running" if sub == "running" else "stopped"

                        if status_filter and status_filter.lower() not in (status, "all"):
                            continue

                        services.append(
                            ServiceInformation(
                                name=unit,
                                display_name=desc,
                                status=status,
                                startup_type=load,
                                description=desc,
                            )
                        )
        except Exception as e:
            logger.debug(f"Could not query systemctl on Linux: {e}")

        return services

    def get_startup_entries(self) -> list[StartupEntry]:
        """Discover desktop autostart and cron persistence entries on Linux."""
        entries: list[StartupEntry] = []

        autostart_dirs = [
            (os.path.expanduser("~/.config/autostart"), "user"),
            ("/etc/xdg/autostart", "system"),
        ]

        for adir, scope in autostart_dirs:
            if os.path.isdir(adir):
                try:
                    for fname in os.listdir(adir):
                        if fname.endswith(".desktop"):
                            fpath = os.path.join(adir, fname)
                            cmd = ""
                            try:
                                with open(fpath, encoding="utf-8", errors="ignore") as f:
                                    for line in f:
                                        if line.startswith("Exec="):
                                            cmd = line.split("=", 1)[1].strip()
                                            break
                            except OSError:
                                pass
                            entries.append(
                                StartupEntry(
                                    name=fname,
                                    source=f"XDG Autostart ({scope})",
                                    command=cmd or fpath,
                                    scope=scope,
                                    status="enabled",
                                )
                            )
                except OSError:
                    pass

        # Cron checks
        try:
            res = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=3, check=False
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append(
                            StartupEntry(
                                name="User Crontab Entry",
                                source="crontab",
                                command=line,
                                scope="user",
                                status="enabled",
                            )
                        )
        except Exception:
            pass

        return entries

    def get_physical_disks(self) -> list[DiskInformation]:
        """Enumerate block storage devices using lsblk."""
        disks: list[DiskInformation] = []
        try:
            res = subprocess.run(
                ["lsblk", "-J", "-b", "-o", "NAME,MODEL,SIZE,ROTA,TYPE,MOUNTPOINT,RM"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                data = json.loads(res.stdout)
                for dev in data.get("blockdevices", []):
                    if dev.get("type") in ("disk", "loop"):
                        name = dev.get("name", "Unknown")
                        model = dev.get("model")
                        size = dev.get("size")
                        is_rm = bool(dev.get("rm"))

                        disks.append(
                            DiskInformation(
                                name=f"/dev/{name}",
                                model=model,
                                size_bytes=int(size) if size else None,
                                is_removable=is_rm,
                                is_physical=dev.get("type") == "disk",
                                partitions=[],
                            )
                        )
        except Exception as e:
            logger.debug(f"Could not execute lsblk: {e}")

        return disks

    def get_capabilities_matrix(self) -> dict[str, CapabilityStatus]:
        """Return the capability evaluation matrix for Linux (including Kali)."""
        import shutil

        has_systemd = os.path.isdir("/run/systemd/system")
        has_fw = bool(shutil.which("ufw") or shutil.which("nft") or shutil.which("iptables"))

        return {
            "hardware_gpu": CapabilityStatus.AVAILABLE
            if shutil.which("lspci")
            else CapabilityStatus.PARTIALLY_AVAILABLE,
            "hardware_motherboard": CapabilityStatus.AVAILABLE
            if os.path.exists("/sys/class/dmi/id")
            else CapabilityStatus.PERMISSION_REQUIRED,
            "hardware_disks": CapabilityStatus.AVAILABLE,
            "services_inspection": CapabilityStatus.AVAILABLE
            if has_systemd
            else CapabilityStatus.PARTIALLY_AVAILABLE,
            "startup_persistence": CapabilityStatus.AVAILABLE,
            "network_firewall": CapabilityStatus.AVAILABLE
            if has_fw
            else CapabilityStatus.PARTIALLY_AVAILABLE,
            "network_interfaces": CapabilityStatus.AVAILABLE,
            "network_connections": CapabilityStatus.AVAILABLE,
            "network_wifi": CapabilityStatus.AVAILABLE
            if os.path.exists("/proc/net/wireless")
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
