"""Path validation, normalization, and root deduplication routines."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path

from systemscan.filesystem.errors import PathValidationError


class PathValidator:
    """Validates, canonicalizes, and deduplicates filesystem target paths."""

    @staticmethod
    def validate_path(raw_path: str | Path, must_exist: bool = True) -> Path:
        """Validate, sanitize, and resolve a user-supplied filesystem path.

        Raises PathValidationError on malformed syntax, nonexistent targets, or permission errors.
        """
        if isinstance(raw_path, str):
            clean_str = raw_path.strip()
            if not clean_str:
                raise PathValidationError("Supplied path cannot be empty.")
            # Remove enclosing quotes if passed from shell
            if (clean_str.startswith('"') and clean_str.endswith('"')) or (
                clean_str.startswith("'") and clean_str.endswith("'")
            ):
                clean_str = clean_str[1:-1].strip()
            target = Path(clean_str)
        else:
            target = raw_path

        # Handle Windows long-path prefix if present
        target_str = str(target)
        if sys.platform == "win32" and target_str.startswith(r"\\?\\"):
            target = Path(target_str[4:])

        try:
            # Resolve canonical absolute path
            resolved = target.resolve()
        except (ValueError, OSError) as e:
            raise PathValidationError(f"Invalid path syntax '{target}': {e}") from e

        if must_exist and not resolved.exists():
            raise PathValidationError(f"Target filesystem path does not exist: {resolved}")

        return resolved

    @classmethod
    def deduplicate_roots(cls, roots: Sequence[str | Path]) -> list[Path]:
        """Validate all supplied paths and prune child paths covered by parent roots.

        Prevents duplicate traversal when user passes both '/a' and '/a/b'.
        """
        validated_paths: list[Path] = []
        for r in roots:
            try:
                val = cls.validate_path(r, must_exist=True)
                if val not in validated_paths:
                    validated_paths.append(val)
            except PathValidationError:
                # Re-raise to fail early on invalid paths
                raise

        if not validated_paths:
            return []

        # Sort paths by depth (number of parts) so parents come before children
        sorted_paths = sorted(validated_paths, key=lambda p: len(p.parts))
        pruned_roots: list[Path] = []

        for candidate in sorted_paths:
            # Check if candidate is a sub-path of any already approved root
            is_redundant = False
            for approved in pruned_roots:
                if approved == candidate:
                    is_redundant = True
                    break
                try:
                    # If candidate is relative to approved, candidate is a child of approved
                    candidate.relative_to(approved)
                    is_redundant = True
                    break
                except ValueError:
                    # Not a descendant
                    pass

            if not is_redundant:
                pruned_roots.append(candidate)

        return pruned_roots

    @staticmethod
    def is_accessible(path: Path) -> bool:
        """Check whether current process has basic read and traverse access to path."""
        try:
            return os.access(path, os.R_OK)
        except OSError:
            return False
