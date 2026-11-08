"""Process, service, and startup persistence inspection package for systemscan."""

from systemscan.modules.processes.collector import (
    collect_process_summary,
    collect_processes,
)
from systemscan.modules.processes.metadata import extract_process_info
from systemscan.modules.processes.services import collect_services
from systemscan.modules.processes.startup import collect_startup_entries

__all__ = [
    "collect_process_summary",
    "collect_processes",
    "collect_services",
    "collect_startup_entries",
    "extract_process_info",
]
