"""Discovery of supported web browser installations and dedicated cache directories."""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psutil

from systemscan.modules.storage.models import BrowserCacheRecord

logger = logging.getLogger("systemscan.storage.browser_cache")

# Process names associated with browsers
BROWSER_PROCESSES = {
    "chrome": ["chrome.exe", "chrome", "google-chrome", "google-chrome-stable"],
    "edge": ["msedge.exe", "msedge", "microsoft-edge"],
    "firefox": ["firefox.exe", "firefox"],
    "brave": ["brave.exe", "brave", "brave-browser"],
}


class BrowserCacheAnalyzer:
    """Discovers browser cache directories while strictly protecting bookmarks, cookies, and history."""

    @classmethod
    def discover_browser_caches(cls) -> list[BrowserCacheRecord]:
        """Discover cache folders across Chrome, Edge, Firefox, and Brave on current OS."""
        records: list[BrowserCacheRecord] = []
        running_procs = cls._get_running_browser_processes()

        if sys.platform.startswith("win"):
            records.extend(cls._discover_windows_browsers(running_procs))
        elif sys.platform.startswith("darwin"):
            records.extend(cls._discover_macos_browsers(running_procs))
        else:
            records.extend(cls._discover_linux_browsers(running_procs))

        return records

    @classmethod
    def _get_running_browser_processes(cls) -> set[str]:
        """Identify which browsers currently have active running processes."""
        running = set()
        for p in psutil.process_iter(attrs=["name"]):
            try:
                pname = (p.info.get("name") or "").lower()
                for browser_key, bin_names in BROWSER_PROCESSES.items():
                    if pname in bin_names:
                        running.add(browser_key)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return running

    @classmethod
    def _inspect_cache_dir(
        cls, browser_name: str, profile: str, cache_path: Path, is_running: bool
    ) -> BrowserCacheRecord | None:
        """Measure size and file count inside a specific cache folder."""
        if not cache_path.exists() or not cache_path.is_dir():
            return None

        total_bytes = 0
        file_count = 0
        latest_mod: datetime | None = None

        try:
            for root, _, files in os.walk(cache_path):
                for f in files:
                    fp = Path(root) / f
                    try:
                        st = fp.stat()
                        total_bytes += st.st_size
                        file_count += 1
                        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                        if latest_mod is None or mtime > latest_mod:
                            latest_mod = mtime
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            return None

        return BrowserCacheRecord(
            browser_name=browser_name,
            profile_name=profile,
            cache_path=str(cache_path),
            size_bytes=total_bytes,
            file_count=file_count,
            last_modified=latest_mod,
            is_browser_running=is_running,
        )

    @classmethod
    def _discover_windows_browsers(cls, running_procs: set[str]) -> list[BrowserCacheRecord]:
        records = []
        local_app_data = os.environ.get("LOCALAPPDATA")
        app_data = os.environ.get("APPDATA")

        if local_app_data:
            lad = Path(local_app_data)
            # Chrome
            chrome_cache = (
                lad / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "Cache_Data"
            )
            rec = cls._inspect_cache_dir(
                "Google Chrome", "Default", chrome_cache, "chrome" in running_procs
            )
            if rec:
                records.append(rec)

            # Edge
            edge_cache = (
                lad / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache" / "Cache_Data"
            )
            rec_edge = cls._inspect_cache_dir(
                "Microsoft Edge", "Default", edge_cache, "edge" in running_procs
            )
            if rec_edge:
                records.append(rec_edge)

            # Brave
            brave_cache = (
                lad
                / "BraveSoftware"
                / "Brave-Browser"
                / "User Data"
                / "Default"
                / "Cache"
                / "Cache_Data"
            )
            rec_brave = cls._inspect_cache_dir(
                "Brave", "Default", brave_cache, "brave" in running_procs
            )
            if rec_brave:
                records.append(rec_brave)

        if app_data:
            # Firefox profile caches
            ff_dir = Path(app_data) / "Mozilla" / "Firefox" / "Profiles"
            if ff_dir.exists():
                for prof in ff_dir.iterdir():
                    cache_folder = prof / "cache2"
                    rec_ff = cls._inspect_cache_dir(
                        "Mozilla Firefox", prof.name, cache_folder, "firefox" in running_procs
                    )
                    if rec_ff:
                        records.append(rec_ff)

        return records

    @classmethod
    def _discover_linux_browsers(cls, running_procs: set[str]) -> list[BrowserCacheRecord]:
        records = []
        home = Path.home()
        cache_dir = home / ".cache"

        # Chrome
        rec_chrome = cls._inspect_cache_dir(
            "Google Chrome",
            "Default",
            cache_dir / "google-chrome" / "Default" / "Cache",
            "chrome" in running_procs,
        )
        if rec_chrome:
            records.append(rec_chrome)

        # Chromium
        rec_chromium = cls._inspect_cache_dir(
            "Chromium",
            "Default",
            cache_dir / "chromium" / "Default" / "Cache",
            "chrome" in running_procs,
        )
        if rec_chromium:
            records.append(rec_chromium)

        # Firefox
        rec_ff = cls._inspect_cache_dir(
            "Mozilla Firefox",
            "Default",
            cache_dir / "mozilla" / "firefox",
            "firefox" in running_procs,
        )
        if rec_ff:
            records.append(rec_ff)

        return records

    @classmethod
    def _discover_macos_browsers(cls, running_procs: set[str]) -> list[BrowserCacheRecord]:
        records = []
        cache_dir = Path.home() / "Library" / "Caches"

        # Chrome
        rec_chrome = cls._inspect_cache_dir(
            "Google Chrome",
            "Default",
            cache_dir / "Google" / "Chrome" / "Default" / "Cache",
            "chrome" in running_procs,
        )
        if rec_chrome:
            records.append(rec_chrome)

        # Edge
        rec_edge = cls._inspect_cache_dir(
            "Microsoft Edge",
            "Default",
            cache_dir / "Microsoft Edge" / "Default" / "Cache",
            "edge" in running_procs,
        )
        if rec_edge:
            records.append(rec_edge)

        # Firefox
        rec_ff = cls._inspect_cache_dir(
            "Mozilla Firefox",
            "Default",
            cache_dir / "Firefox" / "Profiles",
            "firefox" in running_procs,
        )
        if rec_ff:
            records.append(rec_ff)

        return records
