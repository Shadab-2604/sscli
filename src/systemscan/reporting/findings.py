"""Standardization and classification engine for multi-module security findings."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from systemscan.reporting.models import (
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
)


class FindingNormalizer:
    """Normalizes findings from malware, network, storage, and filesystem scanners into unified records."""

    @staticmethod
    def map_severity(raw_sev: Any) -> FindingSeverity:
        """Map heterogeneous severity representations to standardized FindingSeverity."""
        if isinstance(raw_sev, FindingSeverity):
            return raw_sev
        val = str(raw_sev).strip().upper()
        if "CRIT" in val:
            return FindingSeverity.CRITICAL
        if "HIGH" in val:
            return FindingSeverity.HIGH
        if "MED" in val:
            return FindingSeverity.MEDIUM
        if "LOW" in val:
            return FindingSeverity.LOW
        return FindingSeverity.INFO

    @staticmethod
    def map_confidence(raw_conf: Any) -> FindingConfidence:
        """Map heterogeneous confidence representations to standardized FindingConfidence."""
        if isinstance(raw_conf, FindingConfidence):
            return raw_conf
        val = str(raw_conf).strip().upper()
        if "CONFIRM" in val:
            return FindingConfidence.CONFIRMED
        if "HIGH" in val:
            return FindingConfidence.HIGH
        if "MED" in val:
            return FindingConfidence.MEDIUM
        if "LOW" in val:
            return FindingConfidence.LOW
        return FindingConfidence.UNKNOWN

    @classmethod
    def from_malware_finding(cls, item: Any) -> FindingRecord:
        """Convert a Phase 5 DetectionFinding to a standardized FindingRecord."""
        fid = getattr(item, "finding_id", f"mal-{uuid.uuid4().hex[:8]}")
        title = getattr(item, "threat_name", None) or getattr(
            item, "rule_id", "Malware Signature Detected"
        )
        cat = str(getattr(item, "category", "MALWARE"))
        sev = cls.map_severity(getattr(item, "severity", FindingSeverity.HIGH))
        conf = cls.map_confidence(getattr(item, "confidence", FindingConfidence.HIGH))
        desc = getattr(item, "description", "Suspicious or malicious file identified.")
        evidence = getattr(item, "evidence", "")
        target = getattr(item, "file_path", "unknown")
        detected_at = getattr(item, "detected_at", datetime.now(timezone.utc))
        remediation = getattr(item, "recommended_action", "Quarantine or isolate suspicious file.")

        return FindingRecord(
            finding_id=fid,
            title=str(title),
            category=cat,
            severity=sev,
            confidence=conf,
            description=desc,
            evidence=str(evidence),
            target=target,
            detected_at=detected_at,
            source_module="malware",
            remediation=remediation,
        )

    @classmethod
    def from_network_finding(cls, item: Any) -> FindingRecord:
        """Convert a Phase 7 NetworkFinding to a standardized FindingRecord."""
        fid = getattr(item, "finding_id", f"net-{uuid.uuid4().hex[:8]}")
        title = getattr(item, "title", "Network Security Finding")
        cat = str(getattr(item, "category", "NETWORK"))
        sev = cls.map_severity(getattr(item, "severity", FindingSeverity.MEDIUM))
        conf = cls.map_confidence(getattr(item, "confidence", FindingConfidence.HIGH))
        desc = getattr(item, "description", "")
        evidence = getattr(item, "evidence", "")
        target = getattr(item, "affected_target", "network")
        detected_at = getattr(item, "timestamp", datetime.now(timezone.utc))
        remediation = getattr(item, "remediation", None)
        source = getattr(item, "source_module", "network")

        return FindingRecord(
            finding_id=fid,
            title=title,
            category=cat,
            severity=sev,
            confidence=conf,
            description=desc,
            evidence=str(evidence),
            target=target,
            detected_at=detected_at,
            source_module=source,
            remediation=remediation,
        )

    @classmethod
    def create_custom_finding(
        cls,
        title: str,
        category: str,
        severity: FindingSeverity | str,
        confidence: FindingConfidence | str,
        description: str,
        evidence: str,
        target: str,
        source_module: str,
        remediation: str | None = None,
        finding_id: str | None = None,
        detected_at: datetime | None = None,
    ) -> FindingRecord:
        """Create a validated FindingRecord directly."""
        return FindingRecord(
            finding_id=finding_id or f"fnd-{uuid.uuid4().hex[:8]}",
            title=title,
            category=category.upper(),
            severity=cls.map_severity(severity),
            confidence=cls.map_confidence(confidence),
            description=description,
            evidence=evidence,
            target=target,
            detected_at=detected_at or datetime.now(timezone.utc),
            source_module=source_module,
            remediation=remediation,
        )
