"""Safety checks and rule validation protecting system-critical and user data from cleanup."""

from __future__ import annotations

from pathlib import Path

from systemscan.modules.storage.models import CleanupSafetyCategory

# Protected path fragments (case-insensitive substring checks)
PROTECTED_PATH_FRAGMENTS = [
    # Critical Windows paths
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\winsxs",
    "\\program files",
    "\\program files (x86)",
    "\\users\\default",
    # User document / critical data folders
    "\\documents",
    "\\desktop",
    "\\pictures",
    "\\videos",
    "\\music",
    "\\onedrive",
    # Critical POSIX paths
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/boot",
    "/root",
    # Critical databases / repositories
    "/.git",
    "/.svn",
    "/.hg",
]

# Protected extensions never eligible for automatic deletion
PROTECTED_EXTENSIONS = {
    ".docx",
    ".xlsx",
    ".pptx",
    ".pdf",
    ".txt",
    ".rtf",
    ".odt",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".raw",
    ".psd",
    ".mp3",
    ".wav",
    ".flac",
    ".mp4",
    ".mkv",
    ".avi",
    ".sql",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".mdb",
    ".key",
    ".pem",
    ".crt",
    ".kdbx",
}


class CleanupSafetyValidator:
    """Validates files against protection rules to prevent accidental data loss."""

    @classmethod
    def evaluate_safety(
        cls,
        file_path: str | Path,
        check_locked: bool = True,
    ) -> tuple[CleanupSafetyCategory, str]:
        """
        Evaluate a candidate file.
        Returns: (CleanupSafetyCategory, rationale)
        """
        raw_p = Path(file_path)
        # 1. Symlink Safety: Symlinks are NEVER deleted directly to prevent target hijacking
        if raw_p.is_symlink():
            return (
                CleanupSafetyCategory.PROTECTED,
                "Symbolic link rejected to prevent directory traversal",
            )

        p = raw_p.resolve()
        path_str = str(p)
        path_lower = path_str.lower()

        # 2. Protected Extensions: User documents, databases, keys
        ext = p.suffix.lower()
        if ext in PROTECTED_EXTENSIONS:
            return (
                CleanupSafetyCategory.PROTECTED,
                f"User document or database format protected: '{ext}'",
            )

        # 3. Protected System / User Root Paths
        for frag in PROTECTED_PATH_FRAGMENTS:
            if frag in path_lower:
                return (
                    CleanupSafetyCategory.PROTECTED,
                    f"Protected system or user directory hierarchy: '{frag}'",
                )

        # 4. Check if file is currently open / locked (only when executing or specifically requested)
        if check_locked and cls.is_file_locked(p):
            return (
                CleanupSafetyCategory.REQUIRES_REVIEW,
                "File is currently opened or locked by an active process",
            )

        return (
            CleanupSafetyCategory.SAFE_CANDIDATE,
            "Verified safe disposable cache or temporary artifact",
        )

    @classmethod
    def is_file_locked(cls, p: Path) -> bool:
        """Attempt non-destructive read lock check."""
        if not p.exists():
            return False
        try:
            # On Windows, try appending/opening read-write with exclusive share
            with open(p, "a+b"):
                pass
            return False
        except (PermissionError, OSError):
            return True
