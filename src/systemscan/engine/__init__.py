"""Scan Intelligence & Performance Engine.

Provides unified scan orchestration, dynamic ETA estimation, real-time progress
tracking, adaptive concurrency control, incremental scanning, persistent checkpoints,
pause/resume, deduplication, and scan history.
"""

from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.concurrency import IntelligentConcurrencyManager
from systemscan.engine.deduplication import ScanDeduplicationManager
from systemscan.engine.eta import IntelligentETAEngine
from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.incremental import IncrementalScanEngine
from systemscan.engine.lifecycle import (
    ALLOWED_TRANSITIONS,
    InvalidScanStateTransitionError,
    ScanLifecycleCoordinator,
)
from systemscan.engine.models import (
    ConcurrencyMode,
    FileScanRecord,
    IncrementalVerificationMode,
    ResourceUsageSnapshot,
    ScanCheckpoint,
    ScanHistoryRecord,
    ScanProgressEvent,
    ScanState,
    ScanType,
)
from systemscan.engine.orchestrator import CentralScanOrchestrator
from systemscan.engine.pause_resume import ScanPauseResumeController
from systemscan.engine.progress import ProgressEventDispatcher
from systemscan.engine.resource_monitor import SystemResourceMonitor

__all__ = [
    "ALLOWED_TRANSITIONS",
    "CentralScanOrchestrator",
    "ConcurrencyMode",
    "FileScanRecord",
    "IncrementalScanEngine",
    "IncrementalVerificationMode",
    "IntelligentConcurrencyManager",
    "IntelligentETAEngine",
    "InvalidScanStateTransitionError",
    "ProgressEventDispatcher",
    "ResourceUsageSnapshot",
    "ScanCheckpoint",
    "ScanCheckpointManager",
    "ScanDeduplicationManager",
    "ScanHistoryManager",
    "ScanHistoryRecord",
    "ScanLifecycleCoordinator",
    "ScanPauseResumeController",
    "ScanProgressEvent",
    "ScanState",
    "ScanType",
    "SystemResourceMonitor",
]
