"""Sensitive data sanitization and privacy controls for exported reports."""

from __future__ import annotations

import copy
import re
from typing import Any

from pydantic import BaseModel, Field

from systemscan.reporting.models import ScanReport


class RedactionPolicy(BaseModel):
    """Configurable data masking rules for report exports."""

    redact_usernames: bool = Field(default=True, description="Mask user account names")
    redact_user_paths: bool = Field(
        default=True, description="Mask personal user directories (/home/user, C:\\Users\\user)"
    )
    redact_mac_addresses: bool = Field(
        default=True, description="Mask hardware MAC addresses in network telemetry"
    )
    redact_internal_ips: bool = Field(
        default=True, description="Mask private IPv4 and IPv6 addresses"
    )
    redact_serials: bool = Field(default=True, description="Mask BIOS and hardware serial numbers")
    redact_secrets: bool = Field(
        default=True, description="Mask tokens, passwords, and sensitive arguments"
    )


class ReportRedactor:
    """Sanitizes sensitive information from reports without modifying original scan results."""

    # Regex patterns
    MAC_PATTERN = re.compile(r"([0-9a-fA-F]{2}(?::|-)){5}[0-9a-fA-F]{2}")
    IPV4_PRIVATE_PATTERN = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )
    USER_PATH_POSIX_PATTERN = re.compile(r"/home/([a-zA-Z0-9_\-\.]+)")
    USER_PATH_WIN_PATTERN = re.compile(r"[a-zA-Z]:\\Users\\([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)
    USER_PATH_MAC_PATTERN = re.compile(r"/Users/([a-zA-Z0-9_\-\.]+)")
    SECRET_PATTERN = re.compile(
        r"(?i)(password|passwd|token|api[_-]?key|secret|bearer)\s*[:=]\s*([^\s,;]+)"
    )

    def __init__(self, policy: RedactionPolicy | None = None) -> None:
        self.policy = policy or RedactionPolicy()

    def sanitize_text(self, text: str) -> str:
        """Apply all active redaction regex rules to a text string."""
        if not text:
            return text

        result = text

        # 1. Mask secrets
        if self.policy.redact_secrets:
            result = self.SECRET_PATTERN.sub(r"\1=[REDACTED_SECRET]", result)

        # 2. Mask User Paths & Usernames
        if self.policy.redact_user_paths:
            result = self.USER_PATH_POSIX_PATTERN.sub(r"/home/[USER]", result)
            result = self.USER_PATH_WIN_PATTERN.sub(r"C:\\Users\\[USER]", result)
            result = self.USER_PATH_MAC_PATTERN.sub(r"/Users/[USER]", result)

        # 3. Mask MAC Addresses (keep last octet for device disambiguation)
        if self.policy.redact_mac_addresses:
            result = self.MAC_PATTERN.sub(
                lambda m: (
                    f"XX:XX:XX:XX:XX:{m.group(0).split(':')[-1] if ':' in m.group(0) else m.group(0).split('-')[-1]}"
                ),
                result,
            )

        # 4. Mask Private IP Addresses (preserve subnet prefix where useful)
        if self.policy.redact_internal_ips:
            result = self.IPV4_PRIVATE_PATTERN.sub(r"[PRIVATE_IP]", result)

        # 5. Mask Serials
        if self.policy.redact_serials:
            result = re.sub(
                r"(?i)(serial(?:_number)?\s*[:=]\s*)([A-Za-z0-9\-]{5,})",
                r"\1[REDACTED_SERIAL]",
                result,
            )

        return result

    def sanitize_data(self, data: Any) -> Any:
        """Recursively sanitize text inside nested dicts, lists, and primitives."""
        if isinstance(data, str):
            return self.sanitize_text(data)
        if isinstance(data, dict):
            return {k: self.sanitize_data(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.sanitize_data(v) for v in data]
        return data

    def redact_report(self, report: ScanReport) -> ScanReport:
        """Produce a new sanitized ScanReport without altering the source report."""
        # Deep copy to guarantee immutability of the original report
        redacted = copy.deepcopy(report)

        applied_policies: list[str] = []
        if self.policy.redact_usernames:
            applied_policies.append("usernames")
        if self.policy.redact_user_paths:
            applied_policies.append("user_paths")
        if self.policy.redact_mac_addresses:
            applied_policies.append("mac_addresses")
        if self.policy.redact_internal_ips:
            applied_policies.append("internal_ips")
        if self.policy.redact_serials:
            applied_policies.append("serials")
        if self.policy.redact_secrets:
            applied_policies.append("secrets")

        redacted.metadata.is_redacted = True
        redacted.metadata.redaction_policy = applied_policies

        # Sanitize System Information
        if self.policy.redact_usernames:
            redacted.system_info.hostname = "[REDACTED_HOST]"
        if self.policy.redact_internal_ips:
            if redacted.system_info.primary_ip:
                redacted.system_info.primary_ip = "[PRIVATE_IP]"
            if redacted.system_info.default_gateway:
                redacted.system_info.default_gateway = "[PRIVATE_IP]"

        # Sanitize Executive Summary
        redacted.executive_summary.system_identifier = self.sanitize_text(
            redacted.executive_summary.system_identifier
        )
        redacted.executive_summary.critical_observations = [
            self.sanitize_text(o) for o in redacted.executive_summary.critical_observations
        ]
        redacted.executive_summary.high_priority_recommendations = [
            self.sanitize_text(r) for r in redacted.executive_summary.high_priority_recommendations
        ]

        # Sanitize Findings
        for f in redacted.findings:
            f.title = self.sanitize_text(f.title)
            f.description = self.sanitize_text(f.description)
            f.evidence = self.sanitize_text(f.evidence)
            f.target = self.sanitize_text(f.target)
            if f.remediation:
                f.remediation = self.sanitize_text(f.remediation)

        # Sanitize Errors
        for e in redacted.errors:
            e.message = self.sanitize_text(e.message)
            if e.target:
                e.target = self.sanitize_text(e.target)

        # Sanitize Modules Data
        redacted.modules_data = self.sanitize_data(redacted.modules_data)

        return redacted
