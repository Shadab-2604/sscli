"""Cryptographic checksum validation and archive security inspection."""

from __future__ import annotations

import hashlib
import tarfile
import zipfile
from pathlib import Path

from systemscan.logging.logger import get_logger

logger = get_logger("update.verifier")

MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_ARCHIVE_FILE_COUNT = 2000


class UpdateSecurityError(Exception):
    """Raised when an update artifact violates security constraints or integrity checks."""


ArchiveSecurityError = UpdateSecurityError


class UpdateVerifier:
    """Validates downloaded update archives, checksums, and safety boundaries."""

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Compute SHA-256 digest of an update file using streaming chunks."""
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def verify_file_hash(cls, file_path: Path, expected_sha256: str) -> tuple[bool, str]:
        """Verify file matches expected SHA-256 digest returning (valid, message)."""
        if not file_path.exists():
            return False, f"File not found: '{file_path}'"
        if expected_sha256 == "0" * 64:
            return True, "No SHA-256 published; skipped verification."
        actual = cls.compute_sha256(file_path)
        if actual.lower() != expected_sha256.lower():
            return False, f"Checksum mismatch: expected {expected_sha256}, got {actual}"
        return True, "SHA-256 checksum verified successfully."

    @classmethod
    def verify_checksum(cls, file_path: Path, expected_sha256: str) -> bool:
        """Verify file matches expected SHA-256 digest."""
        ok, _ = cls.verify_file_hash(file_path, expected_sha256)
        return ok

    @classmethod
    def verify_archive_safety(cls, archive_path: Path) -> tuple[bool, str]:
        """Verify archive safety returning (safe, message)."""
        try:
            cls.inspect_archive_safety(archive_path)
            return True, "Archive passed all security and structural safety checks."
        except Exception as e:
            return False, str(e)

    @classmethod
    def inspect_archive_safety(cls, archive_path: Path) -> None:
        """Inspect archive for path traversal (zip slips), zip bombs, and prohibited file types."""
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive file not found: {archive_path}")

        ext = archive_path.name.lower()
        if ext.endswith(".zip") or ext.endswith(".whl"):
            cls._inspect_zip_safety(archive_path)
        elif ext.endswith(".tar.gz") or ext.endswith(".tgz") or ext.endswith(".tar"):
            cls._inspect_tar_safety(archive_path)
        else:
            raise UpdateSecurityError(f"Unsupported archive format: '{archive_path.name}'.")

    @classmethod
    def _inspect_zip_safety(cls, zip_path: Path) -> None:
        """Verify zip archive members do not attempt path traversal or resource exhaustion."""
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_ARCHIVE_FILE_COUNT:
                    raise UpdateSecurityError(
                        f"Zip bomb protection: member count ({len(infolist)}) exceeds limit ({MAX_ARCHIVE_FILE_COUNT})."
                    )

                total_uncompressed = sum(info.file_size for info in infolist)
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    raise UpdateSecurityError(
                        f"Zip bomb protection: uncompressed size ({total_uncompressed} bytes) exceeds limit ({MAX_UNCOMPRESSED_BYTES} bytes)."
                    )

                for info in infolist:
                    filename = info.filename
                    # Path traversal check
                    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
                        raise UpdateSecurityError(
                            f"Path traversal detected in archive member: '{filename}'"
                        )
                    if ":" in filename and not filename.startswith("."):
                        raise UpdateSecurityError(
                            f"Prohibited drive letter syntax in archive member: '{filename}'"
                        )
        except zipfile.BadZipFile as e:
            raise UpdateSecurityError(f"Corrupted or invalid zip archive: {e}") from e

    @classmethod
    def _inspect_tar_safety(cls, tar_path: Path) -> None:
        """Verify tarball members do not attempt path traversal or resource exhaustion."""
        try:
            with tarfile.open(tar_path, "r:*") as tf:
                members = tf.getmembers()
                if len(members) > MAX_ARCHIVE_FILE_COUNT:
                    raise UpdateSecurityError(
                        f"Archive bomb protection: member count ({len(members)}) exceeds limit ({MAX_ARCHIVE_FILE_COUNT})."
                    )

                total_uncompressed = sum(m.size for m in members)
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    raise UpdateSecurityError(
                        f"Archive bomb protection: uncompressed size ({total_uncompressed} bytes) exceeds limit ({MAX_UNCOMPRESSED_BYTES} bytes)."
                    )

                for m in members:
                    if ".." in m.name or m.name.startswith("/") or m.name.startswith("\\"):
                        raise UpdateSecurityError(
                            f"Path traversal detected in tar member: '{m.name}'"
                        )
                    if m.issym() or m.islnk():
                        # Symlink safety check: link target cannot contain '..'
                        if ".." in m.linkname or m.linkname.startswith("/"):
                            raise UpdateSecurityError(
                                f"Unsafe symlink in archive member: '{m.name}' -> '{m.linkname}'"
                            )
        except tarfile.TarError as e:
            raise UpdateSecurityError(f"Corrupted or invalid tar archive: {e}") from e

    @classmethod
    def extract_safe(cls, archive_path: Path, target_dir: Path) -> tuple[bool, str]:
        """Safely extract verified archive into target directory, enforcing path boundaries."""
        try:
            cls.inspect_archive_safety(archive_path)
            target_dir.mkdir(parents=True, exist_ok=True)
            resolved_target = target_dir.resolve()

            ext = archive_path.name.lower()
            if ext.endswith(".zip") or ext.endswith(".whl"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for member in zf.infolist():
                        member_path = (target_dir / member.filename).resolve()
                        if not str(member_path).startswith(str(resolved_target)):
                            raise UpdateSecurityError(
                                f"Attempted zip-slip extraction: '{member.filename}'"
                            )
                    zf.extractall(target_dir)
            elif ext.endswith(".tar.gz") or ext.endswith(".tgz") or ext.endswith(".tar"):
                with tarfile.open(archive_path, "r:*") as tf:
                    for m in tf.getmembers():
                        m_path = (target_dir / m.name).resolve()
                        if not str(m_path).startswith(str(resolved_target)):
                            raise UpdateSecurityError(f"Attempted tar-slip extraction: '{m.name}'")
                    tf.extractall(target_dir)
            else:
                return False, f"Unsupported archive format: {archive_path.name}"
            return True, f"Successfully extracted '{archive_path.name}' to '{target_dir}'."
        except Exception as e:
            return False, f"Extraction failed: {e}"
