"""macOS native device provider integrating diskutil and system_profiler storage discovery."""

from __future__ import annotations

from systemscan.devices.providers.macos import MacOSDeviceProvider

__all__ = ["MacOSDeviceProvider"]
