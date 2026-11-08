"""Linux firewall, nftables, iptables, and UFW security posture provider."""

from __future__ import annotations

import shutil
import subprocess

from systemscan.logging.logger import get_logger
from systemscan.network.models import FirewallAction, FirewallStatus

logger = get_logger("platform.linux.security")


class LinuxSecurityProvider:
    """Linux firewall inspection across UFW, nftables, and iptables."""

    @staticmethod
    def audit_firewall() -> FirewallStatus:
        """Inspect host Linux firewall state in read-only mode."""
        # 1. Try UFW
        if shutil.which("ufw"):
            try:
                res = subprocess.run(
                    ["ufw", "status"],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                    check=False,
                )
                is_active = "Status: active" in res.stdout
                return FirewallStatus(
                    is_enabled=is_active,
                    backend_name="UFW",
                    default_inbound_action=FirewallAction.BLOCK,
                    default_outbound_action=FirewallAction.ALLOW,
                )
            except Exception as e:
                logger.debug(f"ufw check note: {e}")

        # 2. Try nftables
        if shutil.which("nft"):
            try:
                res = subprocess.run(
                    ["nft", "list", "ruleset"],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                    check=False,
                )
                if res.returncode == 0:
                    is_active = len(res.stdout.strip()) > 0
                    return FirewallStatus(
                        is_enabled=is_active,
                        backend_name="nftables",
                        default_inbound_action=FirewallAction.BLOCK,
                        default_outbound_action=FirewallAction.ALLOW,
                    )
            except Exception as e:
                logger.debug(f"nftables check note: {e}")

        # 3. Try iptables
        if shutil.which("iptables"):
            try:
                res = subprocess.run(
                    ["iptables", "-L", "-n"],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                    check=False,
                )
                if res.returncode == 0:
                    is_active = "Chain INPUT" in res.stdout
                    return FirewallStatus(
                        is_enabled=is_active,
                        backend_name="iptables",
                        default_inbound_action=FirewallAction.BLOCK,
                        default_outbound_action=FirewallAction.ALLOW,
                    )
            except Exception as e:
                logger.debug(f"iptables check note: {e}")

        return FirewallStatus(
            is_enabled=False,
            backend_name="None Detected",
            warnings=["No active Linux firewall backend (UFW, nftables, iptables) detected."],
        )

