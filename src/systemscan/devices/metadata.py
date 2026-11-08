"""Hardware and volume metadata extraction and redaction helpers."""

from __future__ import annotations

from systemscan.devices.models import DeviceMetadata


def redact_serial_number(serial: str | None) -> str:
    """Mask serial numbers for privacy and security standards."""
    if not serial:
        return "[NOT AVAILABLE]"
    s = str(serial).strip()
    if len(s) <= 4:
        return "****"
    return f"{s[:2]}****{s[-2:]}"


def sanitize_device_metadata(dev: DeviceMetadata, redact_serial: bool = True) -> DeviceMetadata:
    """Return a sanitized copy of DeviceMetadata with redacted serial numbers if requested."""
    if not redact_serial:
        return dev

    redacted_serial = redact_serial_number(dev.serial_number) if dev.serial_number else None
    sanitized = dev.model_copy(update={"serial_number": redacted_serial})
    return sanitized
