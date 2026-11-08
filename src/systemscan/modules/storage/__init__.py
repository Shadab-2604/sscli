"""Public exports for storage intelligence, cache scanning, and safe cleanup."""

from __future__ import annotations

from systemscan.modules.storage.age_analyzer import AgeAnalyzer
from systemscan.modules.storage.cache.browser_cache import BrowserCacheAnalyzer
from systemscan.modules.storage.cache.discovery import CacheDiscoveryEngine
from systemscan.modules.storage.cleanup.audit import CleanupAuditLogger
from systemscan.modules.storage.cleanup.executor import SafeCleanupExecutor
from systemscan.modules.storage.cleanup.planner import CleanupPlanner
from systemscan.modules.storage.cleanup.safety import CleanupSafetyValidator
from systemscan.modules.storage.directory_analyzer import DirectoryAnalyzer
from systemscan.modules.storage.disk_usage import DiskUsageAnalyzer
from systemscan.modules.storage.duplicate_detector import DuplicateDetector
from systemscan.modules.storage.extension_analyzer import ExtensionAnalyzer
from systemscan.modules.storage.hidden_storage import HiddenStorageAnalyzer
from systemscan.modules.storage.large_files import LargeFileAnalyzer
from systemscan.modules.storage.models import (
    BrowserCacheRecord,
    CleanupAuditRecord,
    CleanupCandidate,
    CleanupPreview,
    CleanupSafetyCategory,
    DiskVolumeOverview,
    DuplicateGroup,
    ExtensionStat,
    LargeDirectoryRecord,
    LargeFileRecord,
    StorageCategory,
    format_bytes,
)

__all__ = [
    "AgeAnalyzer",
    "BrowserCacheRecord",
    "BrowserCacheAnalyzer",
    "CacheDiscoveryEngine",
    "CleanupAuditLogger",
    "CleanupAuditRecord",
    "CleanupCandidate",
    "CleanupPlanner",
    "CleanupPreview",
    "CleanupSafetyCategory",
    "CleanupSafetyValidator",
    "DirectoryAnalyzer",
    "DiskUsageAnalyzer",
    "DiskVolumeOverview",
    "DuplicateDetector",
    "DuplicateGroup",
    "ExtensionAnalyzer",
    "ExtensionStat",
    "HiddenStorageAnalyzer",
    "LargeDirectoryRecord",
    "LargeFileAnalyzer",
    "LargeFileRecord",
    "SafeCleanupExecutor",
    "StorageCategory",
    "format_bytes",
]
