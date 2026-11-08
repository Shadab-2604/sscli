"""High-performance filesystem metadata collection and entry classification."""

from __future__ import annotations

import os
import stat
import sys
from datetime import datetime
from pathlib import Path

from systemscan.filesystem.models import DirectoryMetadata, FileMetadata, FileType


class MetadataCollector:
    """Extracts typed metadata from directory entries and filesystem nodes."""

    @classmethod
    def collect_file_metadata(
        cls,
        entry: os.DirEntry[str] | Path,
        stat_result: os.stat_result | None = None,
        relative_to: Path | None = None,
    ) -> FileMetadata:
        """Extract typed metadata for a regular or special file entry."""
        if isinstance(entry, Path):
            path_str = str(entry.resolve())
            name = entry.name
            st = stat_result or entry.stat(follow_symlinks=False)
            is_symlink = entry.is_symlink()
        else:
            path_str = entry.path
            name = entry.name
            # In Python, entry.stat() utilizes cached stat values from FindFirstFile / getdents
            st = stat_result or entry.stat(follow_symlinks=False)
            is_symlink = entry.is_symlink()

        mode = st.st_mode
        file_type = cls.classify_file_type(mode, is_symlink=is_symlink)

        # Timestamps
        ctime = cls._safe_timestamp(getattr(st, "st_ctime", None))
        mtime = cls._safe_timestamp(getattr(st, "st_mtime", None))
        atime = cls._safe_timestamp(getattr(st, "st_atime", None))

        # Permissions & flags
        perm_str = stat.filemode(mode)
        is_exec = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        is_readonly = not bool(mode & stat.S_IWUSR)

        # Hidden detection
        is_hidden = cls.is_entry_hidden(name, st)

        # Inode & Device
        inode = getattr(st, "st_ino", None)
        dev_id = getattr(st, "st_dev", None)

        # Owner / Group (POSIX)
        owner, group = cls._get_owner_group(st)

        # Symlink target
        symlink_target = None
        if is_symlink:
            try:
                symlink_target = os.readlink(path_str)
            except OSError:
                symlink_target = None

        # Relative path
        rel_path = None
        if relative_to is not None:
            try:
                rel_path = str(Path(path_str).relative_to(relative_to))
            except ValueError:
                rel_path = None

        return FileMetadata(
            path=path_str,
            name=name,
            extension=Path(name).suffix.lower(),
            size_bytes=st.st_size if file_type != FileType.DIRECTORY else 0,
            created_time=ctime,
            modified_time=mtime,
            accessed_time=atime,
            inode=inode,
            permissions_mode=mode,
            permissions_str=perm_str,
            owner=owner,
            group=group,
            is_hidden=is_hidden,
            is_executable=is_exec,
            is_readonly=is_readonly,
            is_symlink=is_symlink,
            symlink_target=symlink_target,
            file_type=file_type,
            device_id=dev_id,
            relative_path=rel_path,
        )

    @classmethod
    def collect_directory_metadata(
        cls,
        path: Path | str,
        depth: int = 0,
        stat_result: os.stat_result | None = None,
        child_count: int | None = None,
    ) -> DirectoryMetadata:
        """Extract typed metadata for a directory node."""
        p = Path(path).resolve()
        path_str = str(p)
        name = p.name or str(p)

        try:
            st = stat_result or p.stat(follow_symlinks=False)
            mode: int | None = st.st_mode
            perm_str = stat.filemode(mode) if mode is not None else ""
            ctime = cls._safe_timestamp(getattr(st, "st_ctime", None))
            mtime = cls._safe_timestamp(getattr(st, "st_mtime", None))
            owner, group = cls._get_owner_group(st)
            is_hidden = cls.is_entry_hidden(name, st)
        except OSError:
            mode = None
            perm_str = ""
            ctime = None
            mtime = None
            owner, group = None, None
            is_hidden = name.startswith(".")

        parent_str = str(p.parent) if p.parent != p else None

        return DirectoryMetadata(
            path=path_str,
            name=name,
            parent_path=parent_str,
            created_time=ctime,
            modified_time=mtime,
            permissions_mode=mode,
            permissions_str=perm_str,
            owner=owner,
            group=group,
            is_hidden=is_hidden,
            depth=depth,
            child_count=child_count,
        )

    @staticmethod
    def classify_file_type(st_mode: int, is_symlink: bool = False) -> FileType:
        """Classify filesystem entry type safely using stat bits without opening content."""
        if is_symlink or stat.S_ISLNK(st_mode):
            return FileType.SYMLINK
        if stat.S_ISREG(st_mode):
            return FileType.REGULAR_FILE
        if stat.S_ISDIR(st_mode):
            return FileType.DIRECTORY
        if stat.S_ISSOCK(st_mode):
            return FileType.SOCKET
        if stat.S_ISFIFO(st_mode):
            return FileType.FIFO
        if stat.S_ISBLK(st_mode):
            return FileType.BLOCK_DEVICE
        if stat.S_ISCHR(st_mode):
            return FileType.CHARACTER_DEVICE
        return FileType.OTHER

    @staticmethod
    def is_entry_hidden(name: str, st: os.stat_result | None = None) -> bool:
        """Determine whether an entry is marked as hidden across Linux, Windows, or macOS."""
        # 1. Unix / macOS dot prefix convention
        if name.startswith(".") and name not in (".", ".."):
            return True

        # 2. Windows FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM
        if sys.platform == "win32" and st is not None:
            attrs = getattr(st, "st_file_attributes", 0)
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            if attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
                return True

        return False

    @staticmethod
    def _safe_timestamp(ts: float | None) -> datetime | None:
        """Convert a float epoch timestamp to datetime safely."""
        if ts is None or ts <= 0:
            return None
        try:
            return datetime.fromtimestamp(ts)
        except (ValueError, OSError, OverflowError):
            return None

    @staticmethod
    def _get_owner_group(st: os.stat_result) -> tuple[str | None, str | None]:
        """Resolve owner and group identifiers on POSIX systems."""
        if sys.platform == "win32":
            return None, None

        owner_name = None
        group_name = None
        try:
            import pwd

            uid = getattr(st, "st_uid", None)
            if uid is not None:
                owner_name = pwd.getpwuid(uid).pw_name
        except Exception:
            owner_name = str(getattr(st, "st_uid", ""))

        try:
            import grp

            gid = getattr(st, "st_gid", None)
            if gid is not None:
                group_name = grp.getgrgid(gid).gr_name
        except Exception:
            group_name = str(getattr(st, "st_gid", ""))

        return owner_name, group_name
