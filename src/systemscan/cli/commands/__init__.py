"""CLI commands package for systemscan."""

from systemscan.cli.commands.cache import app as cache_cmd
from systemscan.cli.commands.cleanup import app as cleanup_cmd
from systemscan.cli.commands.config import app as config_cmd
from systemscan.cli.commands.dependencies import app as dependencies_cmd
from systemscan.cli.commands.devices import app as devices_cmd
from systemscan.cli.commands.doctor import app as doctor_cmd
from systemscan.cli.commands.hardware import app as hardware_cmd
from systemscan.cli.commands.history import app as history_cmd
from systemscan.cli.commands.info import app as info_cmd
from systemscan.cli.commands.malware import app as malware_cmd
from systemscan.cli.commands.monitor import app as monitor_cmd
from systemscan.cli.commands.network import app as network_cmd
from systemscan.cli.commands.performance import app as performance_cmd
from systemscan.cli.commands.processes import app as processes_cmd
from systemscan.cli.commands.reports import app as reports_cmd
from systemscan.cli.commands.scan import app as scan_cmd
from systemscan.cli.commands.services import app as services_cmd
from systemscan.cli.commands.startup import app as startup_cmd
from systemscan.cli.commands.storage import app as storage_cmd
from systemscan.cli.commands.uninstall import app as uninstall_cmd
from systemscan.cli.commands.update import app as update_cmd

__all__ = [
    "cache_cmd",
    "cleanup_cmd",
    "config_cmd",
    "dependencies_cmd",
    "devices_cmd",
    "doctor_cmd",
    "hardware_cmd",
    "history_cmd",
    "info_cmd",
    "malware_cmd",
    "monitor_cmd",
    "network_cmd",
    "performance_cmd",
    "processes_cmd",
    "reports_cmd",
    "scan_cmd",
    "services_cmd",
    "startup_cmd",
    "storage_cmd",
    "uninstall_cmd",
    "update_cmd",
]
