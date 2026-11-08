"""Formatting utilities for units, durations, and byte representations."""

from __future__ import annotations


def format_bytes(num_bytes: int | float | None) -> str:
    """Convert bytes into human-readable B, KB, MB, GB, TB format."""
    if num_bytes is None:
        return "N/A"
    if num_bytes < 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(num_bytes)
    idx = 0
    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1

    if idx == 0:
        return f"{int(value)} {units[idx]}"
    return f"{value:.2f} {units[idx]}"


def format_duration(seconds: float | int | None) -> str:
    """Convert seconds into human-readable duration (e.g. '3d 4h 12m 30s')."""
    if seconds is None:
        return "N/A"
    sec = int(seconds)
    if sec < 0:
        return "0s"

    days, remainder = divmod(sec, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    parts: list[str] = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)


def format_percentage(value: float | None) -> str:
    """Format float into percentage string with 1 decimal."""
    if value is None:
        return "N/A"
    return f"{value:.1f}%"


def format_mhz(mhz: float | int | None) -> str:
    """Format clock frequency in MHz or GHz."""
    if mhz is None or mhz <= 0:
        return "N/A"
    if mhz >= 1000:
        return f"{mhz / 1000:.2f} GHz"
    return f"{mhz:.0f} MHz"


def format_celsius(temp: float | None) -> str:
    """Format temperature in Celsius."""
    if temp is None:
        return "N/A"
    return f"{temp:.1f} °C"
