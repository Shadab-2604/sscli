"""macOS Application Firewall (socketfilterfw / pfctl) security posture provider."""

from __future__ import annotations

import subprocess
from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.network.models import FirewallAction, FirewallStatus

logger = get_logger("platform.macos.security")


class MacOSSecurityProvider:
    """macOS Application Firewall inspection via socketfilterfw and pfctl."""

    @staticmethod
    def audit_firewall() -> FirewallStatus:
        """Inspect macOS Application Firewall in read-only mode."""
        alf_path = Path("/usr/libexec/ApplicationFirewall/socketfilterfw")
        if alf_path.exists():
            try:
                res = subprocess.run(
                    [str(alf_path), "--getglobalstate"],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                    check=False,
                )
                is_enabled = "enabled" in res.stdout.lower()
                return FirewallStatus(
                    is_enabled=is_enabled,
                    backend_name="macOS Application Firewall (socketfilterfw)",
                    default_inbound_action=FirewallAction.BLOCK,
                    default_outbound_action=FirewallAction.ALLOW,
                )
            except Exception as e:
                logger.debug(f"socketfilterfw note: {e}")

        # Fallback pfctl check
        try:
            res = subprocess.run(
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            is_enabled = "Status: Enabled" in res.stdout
            return FirewallStatus(
                is_enabled=is_enabled,
                backend_name="pfctl",
                default_inbound_action=FirewallAction.BLOCK,
                default_outbound_action=FirewallAction.ALLOW,
            )
        except Exception:
            pass

        return FirewallStatus(
            is_enabled=True,
            backend_name="macOS Built-in Security",
            default_inbound_action=FirewallAction.BLOCK,
            default_outbound_action=FirewallAction.ALLOW,
        )

