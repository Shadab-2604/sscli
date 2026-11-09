"""macOS native system intelligence, LaunchAgents, LaunchDaemons, and architecture provider."""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.modules.models import ServiceInformation, StartupEntry

logger = get_logger("platform.macos.system")


class MacOSSystemProvider:
    """macOS-specific host inspection via sysctl, launchctl, and plist inspection."""

    @staticmethod
    def is_apple_silicon() -> bool:
        """Check if running natively or under Rosetta on Apple Silicon (arm64)."""
        return platform.machine().lower() in ("arm64", "aarch64")

    @staticmethod
    def is_elevated() -> bool:
        """Check for macOS root privileges."""
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    @staticmethod
    def get_services(limit: int = 100) -> list[ServiceInformation]:
        """Query active launchd services via launchctl list."""
        services: list[ServiceInformation] = []
        try:
            res = subprocess.run(
                ["launchctl", "list"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            for line in res.stdout.splitlines()[1:limit]:
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    status = "running" if parts[0].isdigit() and int(parts[0]) > 0 else "stopped"
                    services.append(
                        ServiceInformation(
                            name=name,
                            display_name=name,
                            status=status,
                            startup_type="launchd",
                        )
                    )
        except Exception as e:
            logger.debug(f"launchctl list error: {e}")

        return services

    @staticmethod
    def get_startup_entries() -> list[StartupEntry]:
        """Inspect user and system LaunchAgents and LaunchDaemons."""
        entries: list[StartupEntry] = []
        launch_dirs = [
            Path(os.path.expanduser("~/Library/LaunchAgents")),
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]

        for d in launch_dirs:
            if d.exists() and d.is_dir():
                try:
                    for f in d.glob("*.plist"):
                        entries.append(
                            StartupEntry(
                                name=f.stem,
                                command=str(f),
                                source=str(d),
                                scope="user"
                                if "~/Library" in str(d) or "Users" in str(d)
                                else "system",
                                status="enabled",
                            )
                        )
                except Exception as e:
                    logger.debug(f"Error enumerating plist in {d}: {e}")

        return entries
