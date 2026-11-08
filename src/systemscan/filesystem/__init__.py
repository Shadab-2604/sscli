"""Filesystem discovery, traversal, metadata, and safety module for systemscan."""

from __future__ import annotations

from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.discovery import FilesystemDiscovery
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.errors import (
    FilesystemAccessDeniedError,
    FilesystemError,
    PathValidationError,
    ScanCancelledError,
    SymlinkRecursionError,
)
from systemscan.filesystem.exclusions import ExclusionManager
from systemscan.filesystem.metadata import MetadataCollector
from systemscan.filesystem.models import (
    DirectoryMetadata,
    ErrorCategory,
    ExclusionConfig,
    FileMetadata,
    FilesystemErrorRecord,
    FilesystemRootInfo,
    FileType,
    ScanConfig,
    ScanStatistics,
    ScanStatus,
    ScanSummary,
    SymlinkPolicy,
)
from systemscan.filesystem.path_validator import PathValidator
from systemscan.filesystem.permissions import PermissionHandler
from systemscan.filesystem.statistics import ScanStatisticsCollector
from systemscan.filesystem.symlinks import SymlinkManager

__all__ = [
    "CancellationToken",
    "DirectoryMetadata",
    "ErrorCategory",
    "ExclusionConfig",
    "ExclusionManager",
    "FileMetadata",
    "FileType",
    "FilesystemAccessDeniedError",
    "FilesystemDiscovery",
    "FilesystemError",
    "FilesystemErrorRecord",
    "FilesystemRootInfo",
    "FilesystemScanner",
    "MetadataCollector",
    "PathValidationError",
    "PathValidator",
    "PermissionHandler",
    "ScanCancelledError",
    "ScanConfig",
    "ScanStatistics",
    "ScanStatisticsCollector",
    "ScanStatus",
    "ScanSummary",
    "SymlinkManager",
    "SymlinkPolicy",
    "SymlinkRecursionError",
]
