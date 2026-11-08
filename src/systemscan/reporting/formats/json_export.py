"""JSON format report exporter and deserialization validator."""

from __future__ import annotations

import json
from pathlib import Path

from systemscan.reporting.models import ScanReport


class JSONReportExporter:
    """Serializes ScanReport to standardized UTF-8 JSON and validates round-trip parsing."""

    @classmethod
    def export_to_string(cls, report: ScanReport, indent: int = 2) -> str:
        """Serialize report to UTF-8 formatted JSON string with ISO-8601 timestamps."""
        return report.model_dump_json(indent=indent)

    @classmethod
    def export_to_file(cls, report: ScanReport, output_path: Path, indent: int = 2) -> Path:
        """Write serialized JSON report to destination path atomically."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = output_path.with_suffix(".tmp")
        payload = cls.export_to_string(report, indent=indent)
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(output_path)
        return output_path

    @classmethod
    def load_from_string(cls, json_str: str) -> ScanReport:
        """Parse and validate JSON string into a ScanReport instance."""
        data = json.loads(json_str)
        return ScanReport.model_validate(data)

    @classmethod
    def load_from_file(cls, file_path: Path) -> ScanReport:
        """Read and validate JSON report file from disk."""
        content = file_path.read_text(encoding="utf-8")
        return cls.load_from_string(content)
