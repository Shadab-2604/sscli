"""Permission handling, error classification, and access evaluation."""

from __future__ import annotations

import errno
import sys
from datetime import datetime
from pathlib import Path

from systemscan.filesystem.models import ErrorCategory, FilesystemErrorRecord


class PermissionHandler:
    """Classifies filesystem access exceptions and formats diagnostic error records."""

    @staticmethod
    def classify_error(
        path: Path | str,
        exc: Exception,
        operation: str = "scandir",
    ) -> FilesystemErrorRecord:
        """Classify a filesystem exception into a structured FilesystemErrorRecord."""
        path_str = str(path)
        msg = str(exc) or exc.__class__.__name__

        category = ErrorCategory.IO_ERROR
        retry_appropriate = False

        if isinstance(exc, PermissionError):
            category = ErrorCategory.PERMISSION_DENIED
        elif isinstance(exc, FileNotFoundError):
            category = ErrorCategory.NOT_FOUND
        elif isinstance(exc, OSError):
            err_no = getattr(exc, "errno", None)
            win_err = getattr(exc, "winerror", None)

            # WinError 5 = ERROR_ACCESS_DENIED, WinError 32 = ERROR_SHARING_VIOLATION (file locked)
            if win_err in (5, 65):  # Access denied / Network access denied
                category = ErrorCategory.PERMISSION_DENIED
            elif win_err in (32, 33):  # Sharing violation / Lock violation
                category = ErrorCategory.FILE_LOCKED
                retry_appropriate = True
            elif err_no in (errno.EACCES, errno.EPERM):
                category = ErrorCategory.PERMISSION_DENIED
            elif err_no == errno.ENOENT:
                category = ErrorCategory.NOT_FOUND
            elif err_no == errno.ENAMETOOLONG or (win_err and win_err == 206):
                category = ErrorCategory.PATH_TOO_LONG
            elif err_no in (errno.ELOOP,):
                category = ErrorCategory.SYMLINK_LOOP
            elif err_no in (errno.EBUSY, errno.ETXTBSY):
                category = ErrorCategory.FILE_LOCKED
                retry_appropriate = True
            elif err_no in (errno.EOPNOTSUPP, errno.ENOSYS):
                category = ErrorCategory.UNSUPPORTED
            else:
                category = ErrorCategory.IO_ERROR

        return FilesystemErrorRecord(
            path=path_str,
            category=category,
            message=msg,
            timestamp=datetime.now(),
            operation=operation,
            retry_appropriate=retry_appropriate,
        )

    @staticmethod
    def is_access_denied(exc: Exception) -> bool:
        """Check whether an exception represents an OS access-denied or permission failure."""
        if isinstance(exc, PermissionError):
            return True
        if isinstance(exc, OSError):
            if getattr(exc, "errno", None) in (errno.EACCES, errno.EPERM):
                return True
            if sys.platform == "win32" and getattr(exc, "winerror", None) in (5, 65):
                return True
        return False
