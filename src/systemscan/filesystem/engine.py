"""High-level filesystem scanning coordinator and public subsystem interface."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime
from pathlib import Path

from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.discovery import FilesystemDiscovery
from systemscan.filesystem.errors import ScanCancelledError
from systemscan.filesystem.models import (
    DirectoryMetadata,
    FileMetadata,
    FilesystemErrorRecord,
    ScanConfig,
    ScanStatus,
    ScanSummary,
)
from systemscan.filesystem.statistics import ScanStatisticsCollector
from systemscan.filesystem.traversal import FilesystemTraversalEngine
from systemscan.logging.logger import get_logger

logger = get_logger("filesystem.engine")


class FilesystemScanner:
    """Universal high-level coordinator for filesystem discovery and traversal."""

    def __init__(self) -> None:
        self.discovery = FilesystemDiscovery()

    def stream_scan(
        self,
        config: ScanConfig,
        cancellation_token: CancellationToken | None = None,
        statistics: ScanStatisticsCollector | None = None,
        error_sink: list[FilesystemErrorRecord] | None = None,
    ) -> Iterator[FileMetadata | DirectoryMetadata]:
        """Low-level generator yielding items one-by-one as traversal discovers them."""
        engine = FilesystemTraversalEngine(config)
        return engine.traverse(
            cancellation_token=cancellation_token,
            statistics=statistics,
            error_sink=error_sink,
        )

    def scan_paths(
        self,
        roots: Sequence[str | Path],
        config: ScanConfig | None = None,
        on_item: Callable[[FileMetadata | DirectoryMetadata], None] | None = None,
        on_progress: Callable[[ScanStatisticsCollector], None] | None = None,
        cancellation_token: CancellationToken | None = None,
        dynamic_roots_provider: Callable[[], list[str]] | None = None,
    ) -> ScanSummary:
        """Execute a full filesystem scan across one or more user-specified paths."""
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.now()
        token = cancellation_token or CancellationToken()
        stats = ScanStatisticsCollector()
        errors: list[FilesystemErrorRecord] = []

        scanned_roots: list[str] = [str(r) for r in roots]
        mode = "custom_path" if len(roots) == 1 else "multi_path"

        scan_cfg = config or ScanConfig(roots=scanned_roots)
        scan_cfg.roots = list(scanned_roots)

        logger.debug(
            f"Starting filesystem scan [{scan_id}] across {len(scanned_roots)} roots: {scanned_roots}"
        )
        status = ScanStatus.RUNNING

        try:
            processed_roots: set[str] = set()
            roots_to_process = list(scanned_roots)
            item_count = 0

            while roots_to_process and not token.is_cancelled:
                current_root = roots_to_process.pop(0)
                norm_root = str(Path(current_root).resolve())
                if norm_root in processed_roots:
                    continue
                processed_roots.add(norm_root)

                single_root_cfg = scan_cfg.model_copy()
                single_root_cfg.roots = [current_root]
                engine = FilesystemTraversalEngine(single_root_cfg)

                for item in engine.traverse(
                    cancellation_token=token,
                    statistics=stats,
                    error_sink=errors,
                ):
                    item_count += 1
                    if on_item:
                        on_item(item)

                    if on_progress and (item_count % 100 == 0):
                        on_progress(stats)

                    # Check dynamic roots provider
                    if dynamic_roots_provider and (item_count % 50 == 0):
                        new_dyn = dynamic_roots_provider()
                        for nr in new_dyn:
                            norm_nr = str(Path(nr).resolve())
                            if norm_nr not in processed_roots and nr not in roots_to_process:
                                roots_to_process.append(nr)
                                scanned_roots.append(nr)
                                logger.info(
                                    f"Dynamically added new scan root during active scan: {nr}"
                                )

                # Check after finishing each root as well
                if dynamic_roots_provider:
                    new_dyn = dynamic_roots_provider()
                    for nr in new_dyn:
                        norm_nr = str(Path(nr).resolve())
                        if norm_nr not in processed_roots and nr not in roots_to_process:
                            roots_to_process.append(nr)
                            scanned_roots.append(nr)
                            logger.info(f"Dynamically added new scan root during active scan: {nr}")

            if token.is_cancelled:
                status = ScanStatus.CANCELLED
                stats.finish()
                logger.warning(f"Filesystem scan [{scan_id}] was cancelled by operator.")
            else:
                status = ScanStatus.COMPLETED
                logger.debug(
                    f"Filesystem scan [{scan_id}] completed successfully: {stats.snapshot().files_scanned} files scanned"
                )

        except ScanCancelledError:
            status = ScanStatus.CANCELLED
            stats.finish()
            logger.warning(f"Filesystem scan [{scan_id}] was cancelled by operator.")

        except Exception as e:
            status = ScanStatus.FAILED
            stats.finish()
            logger.error(f"Filesystem scan [{scan_id}] failed: {e}", exc_info=True)
            errors.append(
                FilesystemErrorRecord(
                    path="general",
                    category="io_error",  # type: ignore[arg-type]
                    message=str(e),
                    operation="scan",
                )
            )

        end_time = datetime.now()
        final_stats = stats.snapshot()

        return ScanSummary(
            scan_id=scan_id,
            started_at=start_time,
            completed_at=end_time,
            status=status,
            scan_mode=mode,
            roots=scanned_roots,
            statistics=final_stats,
            errors=errors,
            exclusions_applied=scan_cfg.exclusions.exclude_paths
            + scan_cfg.exclusions.exclude_globs,
        )

    def scan_all_volumes(
        self,
        config: ScanConfig | None = None,
        on_item: Callable[[FileMetadata | DirectoryMetadata], None] | None = None,
        on_progress: Callable[[ScanStatisticsCollector], None] | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> ScanSummary:
        """Discover and scan all accessible mounted storage volumes and filesystem roots."""
        accessible_roots = self.discovery.discover_accessible_roots()
        root_strs = [str(r) for r in accessible_roots]

        if not root_strs:
            root_strs = ["/"] if Path("/").exists() else ["C:\\"]

        scan_cfg = config or ScanConfig(roots=root_strs)
        scan_cfg.roots = root_strs

        summary = self.scan_paths(
            roots=root_strs,
            config=scan_cfg,
            on_item=on_item,
            on_progress=on_progress,
            cancellation_token=cancellation_token,
        )
        summary.scan_mode = "all_volumes"
        return summary
