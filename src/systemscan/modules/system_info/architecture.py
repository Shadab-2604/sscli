"""Architecture inspection module for systemscan."""

from __future__ import annotations

import platform
import struct
import sys
from typing import Any


def collect_architecture_summary() -> dict[str, Any]:
    """Collect architecture, pointer bitness, and byte-order information."""
    is_64bit = struct.calcsize("P") * 8 == 64
    return {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "architecture_tuple": platform.architecture(),
        "pointer_bitness": 64 if is_64bit else 32,
        "byte_order": sys.byteorder,
        "is_64bit": is_64bit,
    }
