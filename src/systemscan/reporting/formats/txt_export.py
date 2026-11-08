"""Plain text format report exporter with template style selection."""

from __future__ import annotations

from pathlib import Path

from systemscan.reporting.models import ScanReport
from systemscan.reporting.templates.compact import CompactTemplate
from systemscan.reporting.templates.executive import ExecutiveTemplate
from systemscan.reporting.templates.technical import TechnicalTemplate


class TextReportExporter:
    """Exports human-readable text reports formatted via executive, technical, or compact templates."""

    @classmethod
    def export_to_string(cls, report: ScanReport, style: str = "technical") -> str:
        """Render report string according to selected style template."""
        style_norm = style.lower().strip()
        if style_norm == "executive":
            return ExecutiveTemplate.render(report)
        if style_norm == "compact":
            return CompactTemplate.render(report)
        return TechnicalTemplate.render(report)

    @classmethod
    def export_to_file(
        cls, report: ScanReport, output_path: Path, style: str = "technical"
    ) -> Path:
        """Write formatted text report to destination path atomically."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = output_path.with_suffix(".tmp")
        payload = cls.export_to_string(report, style=style)
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(output_path)
        return output_path
