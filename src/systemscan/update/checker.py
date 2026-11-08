"""Remote release discovery, version comparison, and update plan synthesis."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from packaging.version import InvalidVersion, Version

from systemscan.config.schema import SystemScanConfig
from systemscan.logging.logger import get_logger
from systemscan.update.models import ReleaseChannel, ReleaseInfo, UpdatePlan
from systemscan.version import __version__

logger = get_logger("update.checker")


class UpdateChecker:
    """Discovers published updates from remote repository releases and validates compatibility."""

    def __init__(
        self,
        update_source: str | None = None,
        channel: ReleaseChannel | None = None,
        timeout: float = 5.0,
        config: SystemScanConfig | None = None,
    ) -> None:
        if config:
            self.update_source = update_source or config.updates.update_source
            self.channel: ReleaseChannel = channel or ReleaseChannel(config.updates.channel.value)
        else:
            self.update_source = (
                update_source or "https://api.github.com/repos/Shadab-2604/sscli/releases"
            )
            self.channel = channel or ReleaseChannel.STABLE
        self.timeout = timeout

    def fetch_remote_releases(self) -> list[dict[str, Any]]:
        """Query release metadata over HTTPS."""
        if not self.update_source.startswith("https://"):
            raise ValueError(
                f"Insecure update source rejected. HTTPS is mandatory: '{self.update_source}'"
            )

        req = urllib.request.Request(
            self.update_source,
            headers={
                "User-Agent": f"systemscan-updater/{__version__}",
                "Accept": "application/vnd.github.v3+json, application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    raise urllib.error.HTTPError(
                        req.full_url, resp.status, f"HTTP {resp.status}", resp.headers, None
                    )
                payload = resp.read().decode("utf-8")
                data = json.loads(payload)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    return [data]
                return []
        except urllib.error.URLError as e:
            logger.warning(f"Failed to query remote update source '{self.update_source}': {e}")
            raise ConnectionError(f"Unable to reach update service: {e}") from e
        except json.JSONDecodeError as e:
            logger.error(f"Malformed release metadata received from '{self.update_source}': {e}")
            raise ValueError(f"Invalid JSON response from update endpoint: {e}") from e

    def parse_release_info(self, raw_release: dict[str, Any]) -> ReleaseInfo | None:
        """Parse raw GitHub/JSON release payload into typed ReleaseInfo contract."""
        tag = raw_release.get("tag_name", "").lstrip("v")
        if not tag:
            return None

        # Determine release channel
        is_prerelease = raw_release.get("prerelease", False)
        body = raw_release.get("body", "")
        if is_prerelease or "beta" in tag.lower() or "rc" in tag.lower():
            channel = ReleaseChannel.BETA
        elif "dev" in tag.lower() or "alpha" in tag.lower():
            channel = ReleaseChannel.DEV
        else:
            channel = ReleaseChannel.STABLE

        # Find distribution archive in release assets (.zip or .whl)
        assets = raw_release.get("assets", [])
        download_url = ""
        asset_name = ""
        asset_size = 0

        for a in assets:
            name = a.get("name", "")
            if name.endswith(".zip") or name.endswith(".whl") or name.endswith(".tar.gz"):
                download_url = a.get("browser_download_url", "")
                asset_name = name
                asset_size = a.get("size", 0)
                break

        if not download_url:
            # Fallback to zipball/tarball
            download_url = raw_release.get(
                "zipball_url", f"{self.update_source}/archive/v{tag}.zip"
            )
            asset_name = f"systemscan-{tag}.zip"

        # Check for published SHA-256 in release body or assets
        sha256 = ""
        for line in body.splitlines():
            line_clean = line.strip()
            if "sha256" in line_clean.lower() and ":" in line_clean:
                parts = line_clean.split(":")
                candidate = parts[-1].strip().lower()
                if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                    sha256 = candidate
                    break

        if not sha256:
            sha256 = "0" * 64

        pub_str = raw_release.get("published_at", "")
        try:
            rel_date = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            rel_date = datetime.now(timezone.utc)

        return ReleaseInfo(
            version=tag,
            release_date=rel_date,
            channel=channel,
            download_url=download_url,
            sha256=sha256,
            min_python_version="3.10",
            release_notes=body[:500],
            asset_name=asset_name,
            asset_size_bytes=asset_size,
        )

    def check_for_updates(
        self, allow_downgrade: bool = False
    ) -> tuple[ReleaseInfo | None, UpdatePlan]:
        """Check remote source for compatible releases and compute an UpdatePlan."""
        try:
            releases_raw = self.fetch_remote_releases()
        except Exception as e:
            logger.warning(f"Could not check for updates: {e}")
            plan = UpdatePlan(
                current_version=__version__,
                target_version=__version__,
                channel=self.channel,
                is_update_available=False,
                compatibility_reason=f"Update check failed: {e}",
            )
            return None, plan

        valid_releases: list[ReleaseInfo] = []

        for r in releases_raw:
            info = self.parse_release_info(r)
            if not info:
                continue
            # Filter channel
            if self.channel == ReleaseChannel.STABLE and info.channel != ReleaseChannel.STABLE:
                continue
            valid_releases.append(info)

        if not valid_releases:
            plan = UpdatePlan(
                current_version=__version__,
                target_version=__version__,
                channel=self.channel,
                is_update_available=False,
                compatibility_reason="No published releases found for configured channel.",
            )
            return None, plan

        # Sort newest version first
        def version_key(rel: ReleaseInfo) -> Version:
            try:
                return Version(rel.version)
            except InvalidVersion:
                return Version("0.0.0")

        valid_releases.sort(key=version_key, reverse=True)
        latest_release = valid_releases[0]

        curr_v = Version(__version__)
        target_v = version_key(latest_release)

        is_newer = target_v > curr_v
        is_older = target_v < curr_v

        # Check Python compatibility
        min_py = Version(latest_release.min_python_version)
        curr_py = Version(f"{sys.version_info.major}.{sys.version_info.minor}")
        is_py_compat = curr_py >= min_py

        compat_reason = "Host environment and Python version are compatible."
        if not is_py_compat:
            compat_reason = f"Requires Python >= {latest_release.min_python_version}; host is running {curr_py}."

        is_available = is_newer or (is_older and allow_downgrade)

        plan = UpdatePlan(
            current_version=__version__,
            target_version=latest_release.version,
            channel=self.channel,
            is_update_available=is_available,
            is_downgrade=is_older,
            is_compatible=is_py_compat,
            compatibility_reason=compat_reason,
            files_to_replace=["systemscan/*"],
            dependency_changes=[],
        )

        return latest_release, plan

    def fetch_latest_release(self, channel: ReleaseChannel | None = None) -> ReleaseInfo | None:
        """Fetch the newest ReleaseInfo for the specified channel."""
        if channel:
            self.channel = channel
        rel, _ = self.check_for_updates(allow_downgrade=True)
        return rel

    def create_update_plan(
        self,
        channel: ReleaseChannel | None = None,
        allow_downgrade: bool = False,
    ) -> UpdatePlan:
        """Generate an UpdatePlan comparing current vs target release."""
        if channel:
            self.channel = channel
        _, plan = self.check_for_updates(allow_downgrade=allow_downgrade)
        return plan

    @staticmethod
    def _parse_version(version_str: str) -> tuple[int, ...]:
        """Parse a version string into an integer tuple for safe comparison."""
        clean = version_str.lstrip("v").strip()
        parts: list[int] = []
        for p in clean.split("."):
            try:
                parts.append(int(p.split("-")[0]))
            except ValueError:
                parts.append(0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
