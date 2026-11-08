"""Linux native system intelligence, distribution parsing, and service inspection."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.modules.models import ServiceInformation, StartupEntry

logger = get_logger("platform.linux.system")


class LinuxSystemProvider:
    """Linux-specific host telemetry, /etc/os-release parsing, and systemd inspection."""

    @staticmethod
    def get_distribution() -> tuple[str | None, str | None]:
        """Parse Linux distribution name and version from standard release files."""
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            p = Path(path)
            if p.exists():
                try:
                    data: dict[str, str] = {}
                    for line in p.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            data[k.strip()] = v.strip().strip('"').strip("'")
                    name = data.get("NAME") or data.get("PRETTY_NAME")
                    ver = data.get("VERSION_ID") or data.get("VERSION")
                    return name, ver
                except Exception as e:
                    logger.debug(f"Failed parsing {path}: {e}")

        # Fallback to debian_version / redhat-release
        for f, name in [("/etc/debian_version", "Debian"), ("/etc/redhat-release", "RedHat")]:
            p = Path(f)
            if p.exists():
                try:
                    return name, p.read_text(encoding="utf-8").strip()
                except Exception:
                    pass

        return None, None

    @staticmethod
    def is_elevated() -> bool:
        """Check for root privileges via euid."""
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    @staticmethod
    def get_systemd_services(limit: int = 100) -> list[ServiceInformation]:
        """Query active systemd units via systemctl CLI without shell interpretation."""
        if not os.path.isdir("/run/systemd/system"):
            return []

        services: list[ServiceInformation] = []
        try:
            res = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--no-pager",
                    "--plain",
                    "--no-legend",
                ],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            for line in res.stdout.splitlines()[:limit]:
                parts = line.split(maxsplit=4)
                if len(parts) >= 4 and parts[0].endswith(".service"):
                    services.append(
                        ServiceInformation(
                            name=parts[0].replace(".service", ""),
                            display_name=parts[4] if len(parts) > 4 else parts[0],
                            status=parts[3],
                            startup_type=parts[1],
                            description=parts[4] if len(parts) > 4 else "",
                        )
                    )
        except Exception as e:
            logger.debug(f"Failed querying systemctl: {e}")

        return services

    @staticmethod
    def get_startup_entries() -> list[StartupEntry]:
        """Inspect XDG autostart directories and cron persistence."""
        entries: list[StartupEntry] = []
        autostart_dirs = [
            Path("/etc/xdg/autostart"),
            Path(os.path.expanduser("~/.config/autostart")),
        ]
        for d in autostart_dirs:
            if d.exists() and d.is_dir():
                try:
                    for f in d.glob("*.desktop"):
                        entries.append(
                            StartupEntry(
                                name=f.stem,
                                command=str(f),
                                source=str(d),
                                scope="user" if "/home/" in str(d) or ".config" in str(d) else "system",
                                status="enabled",
                            )
                        )
                except Exception as e:
                    logger.debug(f"Error reading autostart dir {d}: {e}")
        return entries
