"""Report file storage, retrieval, retention pruning, and atomic persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from systemscan.logging.logger import get_logger
from systemscan.reporting.formats.csv_export import CSVReportExporter
from systemscan.reporting.formats.json_export import JSONReportExporter
from systemscan.reporting.formats.txt_export import TextReportExporter
from systemscan.reporting.models import ReportFormat, ScanReport
from systemscan.reporting.validator import ReportValidator
from systemscan.utils.paths import AppPaths

logger = get_logger("reporting.storage")


class ReportStorageManager:
    """Manages persistent report files, safe naming, atomic writes, and retention policies."""

    def __init__(self, storage_dir: Path | None = None) -> None:
        self.storage_dir = storage_dir or AppPaths().report_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _generate_filename(self, report: ScanReport, fmt: ReportFormat) -> str:
        """Create a safe, deterministic filename for a report."""
        clean_rep_id = "".join(
            c for c in report.metadata.report_id if c.isalnum() or c in ("-", "_")
        )
        clean_scan_id = "".join(
            c for c in report.metadata.scan_id if c.isalnum() or c in ("-", "_")
        )
        stype = report.metadata.scan_type.value.lower()
        return f"{clean_rep_id}_{clean_scan_id}_{stype}.{fmt.value}"

    def save_report(
        self,
        report: ScanReport,
        fmt: ReportFormat = ReportFormat.JSON,
        custom_path: Path | None = None,
        overwrite: bool = False,
        generate_checksum: bool = True,
        txt_style: str = "technical",
    ) -> Path:
        """Atomically persist a report file to disk with integrity validation."""
        # Validate report data contract before saving
        ReportValidator.assert_valid(report)

        target_path: Path
        if custom_path:
            target_path = custom_path.resolve()
            if target_path.is_dir():
                target_path = target_path / self._generate_filename(report, fmt)
        else:
            target_path = self.storage_dir / self._generate_filename(report, fmt)

        if target_path.exists() and not overwrite:
            raise FileExistsError(
                f"Report export destination already exists: '{target_path}'. "
                "Specify overwrite=True or pass the --overwrite flag to replace."
            )

        # Dispatch atomic write by format
        if fmt == ReportFormat.JSON:
            saved_path = JSONReportExporter.export_to_file(report, target_path)
        elif fmt == ReportFormat.CSV:
            saved_path = CSVReportExporter.export_to_file(report, target_path)
        elif fmt == ReportFormat.TXT:
            saved_path = TextReportExporter.export_to_file(report, target_path, style=txt_style)
        else:
            raise ValueError(f"Unsupported report export format: {fmt}")

        if generate_checksum:
            try:
                ReportValidator.create_checksum_manifest(saved_path)
            except Exception as e:
                logger.warning(f"Failed to generate checksum manifest for '{saved_path}': {e}")

        logger.info(f"Saved {fmt.value.upper()} report to '{saved_path}'")
        return saved_path

    def list_reports(self) -> list[dict[str, Any]]:
        """List all saved report files in storage directory."""
        if not self.storage_dir.exists():
            return []

        entries: list[dict[str, Any]] = []
        for p in self.storage_dir.iterdir():
            if not p.is_file() or p.suffix == ".tmp" or p.name.endswith(".sha256"):
                continue

            stat = p.stat()
            fmt = p.suffix.lstrip(".").lower()
            rep_id = p.stem.split("_")[0] if "_" in p.stem else p.stem

            entries.append(
                {
                    "report_id": rep_id,
                    "filename": p.name,
                    "path": str(p),
                    "format": fmt,
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                }
            )

        # Sort newest first
        return sorted(entries, key=lambda x: x["created_at"], reverse=True)

    def find_report_file(self, report_id: str) -> Path | None:
        """Locate file matching a given report ID in storage directory."""
        clean_id = report_id.strip()
        for p in self.storage_dir.iterdir():
            if not p.is_file() or p.name.endswith(".sha256") or p.suffix == ".tmp":
                continue
            if clean_id in p.name:
                return p
        return None

    def load_report(self, report_id_or_path: str | Path) -> ScanReport | None:
        """Load and validate a JSON report file."""
        target: Path | None
        if isinstance(report_id_or_path, Path) or (
            "/" in str(report_id_or_path) or "\\" in str(report_id_or_path)
        ):
            target = Path(report_id_or_path)
        else:
            target = self.find_report_file(str(report_id_or_path))

        if not target or not target.exists():
            return None

        if target.suffix.lower() != ".json":
            logger.warning(
                f"File '{target}' is not a JSON report. Cannot load as ScanReport model."
            )
            return None

        try:
            return JSONReportExporter.load_from_file(target)
        except Exception as e:
            logger.error(f"Failed to parse report file '{target}': {e}")
            return None

    def delete_report(self, report_id: str, confirm: bool = False) -> bool:
        """Delete a report file and its checksum manifest. Requires explicit confirmation."""
        if not confirm:
            raise PermissionError(
                "Explicit confirmation (confirm=True) is required to delete report files."
            )

        file_path = self.find_report_file(report_id)
        if not file_path or not file_path.exists():
            return False

        try:
            manifest = file_path.with_suffix(file_path.suffix + ".sha256")
            if manifest.exists():
                manifest.unlink()
            file_path.unlink()
            logger.info(f"Deleted report file '{file_path}'")
            return True
        except OSError as e:
            logger.error(f"Failed to delete report '{report_id}': {e}")
            return False

    def verify_report(self, report_id: str) -> tuple[bool, str]:
        """Verify integrity of a report file against its checksum manifest."""
        file_path = self.find_report_file(report_id)
        if not file_path:
            return False, f"Report file with ID '{report_id}' not found."

        manifest = file_path.with_suffix(file_path.suffix + ".sha256")
        if not manifest.exists():
            return (
                False,
                f"Checksum manifest '{manifest.name}' missing. Integrity cannot be verified.",
            )

        is_valid = ReportValidator.verify_checksum_manifest(file_path)
        if is_valid:
            return True, f"Report '{file_path.name}' matches cryptographic SHA-256 manifest."
        return (
            False,
            f"Report '{file_path.name}' MISMATCH with SHA-256 manifest. Possible tampering or corruption.",
        )

    def prune_retention(self, retention_days: int = 90) -> int:
        """Remove report files older than specified retention window."""
        if retention_days <= 0 or not self.storage_dir.exists():
            return 0

        cutoff = datetime.now(timezone.utc).timestamp() - (retention_days * 86400.0)
        pruned_count = 0

        for p in list(self.storage_dir.iterdir()):
            if not p.is_file() or p.suffix == ".tmp":
                continue
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
                    manifest = p.with_suffix(p.suffix + ".sha256")
                    if manifest.exists():
                        manifest.unlink()
                    pruned_count += 1
            except OSError as e:
                logger.debug(f"Error pruning report '{p}': {e}")

        if pruned_count > 0:
            logger.info(
                f"Pruned {pruned_count} historical report file(s) older than {retention_days} days."
            )
        return pruned_count
