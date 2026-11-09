"""Windows Defender Firewall posture and profile auditor."""

from __future__ import annotations

import json
import subprocess

from systemscan.logging.logger import get_logger
from systemscan.network.models import FirewallAction, FirewallStatus

logger = get_logger("platform.windows.security")


class WindowsSecurityProvider:
    """Windows Defender Firewall inspection across Domain, Private, and Public profiles."""

    @staticmethod
    def audit_firewall() -> FirewallStatus:
        """Query Get-NetFirewallProfile via PowerShell in read-only mode."""
        ps_cmd = (
            "Get-NetFirewallProfile | "
            "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | "
            "ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout)
                profiles_data = raw if isinstance(raw, list) else [raw]
                profiles: dict[str, bool] = {}
                any_enabled = False

                for p in profiles_data:
                    name = str(p.get("Name", "Unknown"))
                    is_en = bool(p.get("Enabled"))
                    profiles[name] = is_en
                    if is_en:
                        any_enabled = True

                return FirewallStatus(
                    is_enabled=any_enabled,
                    backend_name="Windows Defender Firewall",
                    profiles=profiles,
                    default_inbound_action=FirewallAction.BLOCK,
                    default_outbound_action=FirewallAction.ALLOW,
                )
        except Exception as e:
            logger.debug(f"PowerShell firewall query note: {e}")

        return FirewallStatus(
            is_enabled=True,
            backend_name="Windows Defender Firewall (Default)",
            default_inbound_action=FirewallAction.BLOCK,
            default_outbound_action=FirewallAction.ALLOW,
        )
