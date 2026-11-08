"""Recursive, iterative filesystem traversal engine with streaming generators."""

from __future__ import annotations

import os
import sys
from collections import deque
from collections.abc import Iterator
from pathlib import Path

from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.exclusions import ExclusionManager
from systemscan.filesystem.metadata import MetadataCollector
from systemscan.filesystem.models import (
    DirectoryMetadata,
    FileMetadata,
    FilesystemErrorRecord,
    FileType,
    ScanConfig,
    SymlinkPolicy,
)
from systemscan.filesystem.path_validator import PathValidator
from systemscan.filesystem.permissions import PermissionHandler
from systemscan.filesystem.statistics import ScanStatisticsCollector
from systemscan.filesystem.symlinks import SymlinkManager


class FilesystemTraversalEngine:
    """Iterative streaming filesystem traversal engine designed for deep and large volume scans."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.exclusion_mgr = ExclusionManager(config.exclusions)
        self.symlink_mgr = SymlinkManager(config.symlink_policy)

    def traverse(
        self,
        cancellation_token: CancellationToken | None = None,
        statistics: ScanStatisticsCollector | None = None,
        error_sink: list[FilesystemErrorRecord] | None = None,
    ) -> Iterator[FileMetadata | DirectoryMetadata]:
        """Stream metadata objects for all reachable files and directories under configured roots.

        Yields FileMetadata and DirectoryMetadata instances iteratively without buffering.
        """
        token = cancellation_token or CancellationToken()
        stats = statistics or ScanStatisticsCollector()
        errors = error_sink if error_sink is not None else []

        stats.start()
        self.symlink_mgr.reset()

        # 1. Deduplicate and validate roots
        try:
            validated_roots = PathValidator.deduplicate_roots(self.config.roots)
        except Exception as e:
            err = PermissionHandler.classify_error("roots", e, "validate")
            errors.append(err)
            stats.record_io_error()
            stats.finish()
            return

        if not validated_roots:
            stats.finish()
            return

        for current_root in validated_roots:
            token.raise_if_cancelled()
            stats.set_current_path(str(current_root))

            # 2. Check if current_root is an individual file
            if current_root.is_file():
                try:
                    st = current_root.stat(follow_symlinks=False)
                    is_hidden = MetadataCollector.is_entry_hidden(current_root.name, st)
                    file_meta = MetadataCollector.collect_file_metadata(
                        current_root, stat_result=st
                    )
                    stats.record_file_discovered(
                        size_bytes=file_meta.size_bytes,
                        is_hidden=is_hidden,
                        is_symlink=file_meta.is_symlink,
                        file_type=file_meta.file_type,
                    )
                    stats.record_file_scanned()
                    yield file_meta
                except OSError as e:
                    err = PermissionHandler.classify_error(current_root, e, "stat")
                    errors.append(err)
                    stats.record_permission_error()
                continue

            # 3. Directory traversal using iterative DFS via deque stack
            # Stack elements: (directory_path, depth, device_id)
            root_dev = None
            try:
                root_dev = getattr(current_root.stat(follow_symlinks=False), "st_dev", None)
            except OSError:
                pass

            stack: deque[tuple[Path, int, int | None]] = deque([(current_root, 0, root_dev)])
            stats.record_directory_discovered(
                is_hidden=MetadataCollector.is_entry_hidden(current_root.name)
            )

            while stack:
                token.raise_if_cancelled()

                dir_path, depth, parent_dev = stack.pop()
                dir_str = str(dir_path)
                stats.set_current_path(dir_str)

                # Check depth exclusion
                if self.config.max_depth is not None and depth > self.config.max_depth:
                    stats.record_skipped()
                    continue

                # Check directory exclusion
                is_ex, reason = self.exclusion_mgr.is_excluded(
                    dir_path,
                    name=dir_path.name,
                    is_dir=True,
                    depth=depth,
                    is_hidden=MetadataCollector.is_entry_hidden(dir_path.name),
                    max_depth=self.config.max_depth,
                )
                if is_ex:
                    stats.record_excluded()
                    continue

                # Yield directory metadata
                dir_meta = MetadataCollector.collect_directory_metadata(dir_path, depth=depth)
                stats.record_directory_scanned(depth)
                yield dir_meta

                # Enumerate directory contents using os.scandir
                subdirs_to_push: list[tuple[Path, int, int | None]] = []

                try:
                    with os.scandir(dir_path) as entries:
                        for entry in entries:
                            token.raise_if_cancelled()

                            try:
                                entry_name = entry.name
                                is_symlink = entry.is_symlink()
                                st = entry.stat(follow_symlinks=False)
                                is_hidden = MetadataCollector.is_entry_hidden(entry_name, st)

                                # Handle symlink policy
                                if is_symlink:
                                    stats.record_file_discovered(
                                        size_bytes=st.st_size,
                                        is_hidden=is_hidden,
                                        is_symlink=True,
                                        file_type=FileType.SYMLINK,
                                    )
                                    if SymlinkManager.is_broken_link(entry.path):
                                        stats.record_broken_link()

                                    if self.config.symlink_policy == SymlinkPolicy.IGNORE:
                                        stats.record_skipped()
                                        continue
                                    elif (
                                        self.config.symlink_policy == SymlinkPolicy.RECORD_NO_FOLLOW
                                    ):
                                        file_meta = MetadataCollector.collect_file_metadata(
                                            entry, stat_result=st, relative_to=current_root
                                        )
                                        stats.record_file_scanned()
                                        yield file_meta
                                        continue
                                    elif self.config.symlink_policy == SymlinkPolicy.FOLLOW_SAFE:
                                        p_entry = Path(entry.path)
                                        can_follow, reason = self.symlink_mgr.should_traverse(
                                            p_entry, validated_roots
                                        )
                                        if can_follow:
                                            # Push followed directory target onto stack
                                            real_target = p_entry.resolve()
                                            subdirs_to_push.append(
                                                (real_target, depth + 1, parent_dev)
                                            )
                                            stats.record_directory_discovered(is_hidden=is_hidden)
                                            continue
                                        else:
                                            # Cannot follow; record as symlink file
                                            file_meta = MetadataCollector.collect_file_metadata(
                                                entry, stat_result=st, relative_to=current_root
                                            )
                                            stats.record_file_scanned()
                                            yield file_meta
                                            continue

                                # Directory entry
                                if entry.is_dir(follow_symlinks=False):
                                    stats.record_directory_discovered(is_hidden=is_hidden)

                                    # Check boundary if staying on same filesystem
                                    if self.config.stay_on_filesystem:
                                        if sys.platform == "win32":
                                            if (
                                                Path(entry.path).drive.lower()
                                                != current_root.drive.lower()
                                            ):
                                                stats.record_skipped()
                                                continue
                                        else:
                                            entry_dev = getattr(st, "st_dev", None)
                                            if (
                                                root_dev is not None
                                                and entry_dev is not None
                                                and entry_dev != 0
                                                and root_dev != 0
                                                and entry_dev != root_dev
                                            ):
                                                stats.record_skipped()
                                                continue

                                    # Filter hidden directories if hidden exclusion enabled
                                    if self.config.exclusions.exclude_hidden and is_hidden:
                                        stats.record_excluded()
                                        continue

                                    entry_dev = getattr(st, "st_dev", None)
                                    subdirs_to_push.append((Path(entry.path), depth + 1, entry_dev))
                                    continue

                                # Regular file or special entry
                                file_type = MetadataCollector.classify_file_type(
                                    st.st_mode, is_symlink=False
                                )
                                stats.record_file_discovered(
                                    size_bytes=st.st_size,
                                    is_hidden=is_hidden,
                                    is_symlink=False,
                                    file_type=file_type,
                                )

                                # Filter exclusions
                                is_file_ex, _ = self.exclusion_mgr.is_excluded(
                                    entry.path,
                                    name=entry_name,
                                    is_dir=False,
                                    size_bytes=st.st_size,
                                    depth=depth,
                                    is_hidden=is_hidden,
                                    max_depth=self.config.max_depth,
                                )
                                if is_file_ex:
                                    stats.record_excluded()
                                    continue

                                file_meta = MetadataCollector.collect_file_metadata(
                                    entry, stat_result=st, relative_to=current_root
                                )
                                stats.record_file_scanned()
                                yield file_meta

                            except OSError as entry_err:
                                err = PermissionHandler.classify_error(
                                    entry.path, entry_err, "stat"
                                )
                                errors.append(err)
                                if PermissionHandler.is_access_denied(entry_err):
                                    stats.record_permission_error()
                                else:
                                    stats.record_io_error()

                except OSError as dir_err:
                    err = PermissionHandler.classify_error(dir_path, dir_err, "scandir")
                    errors.append(err)
                    if PermissionHandler.is_access_denied(dir_err):
                        stats.record_permission_error()
                    else:
                        stats.record_io_error()
                    continue

                # Push discovered subdirectories (reverse order preserves natural alphabetical order in LIFO stack)
                for item in reversed(subdirs_to_push):
                    stack.append(item)

        stats.finish()
