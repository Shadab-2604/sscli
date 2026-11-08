"""System intelligence and host inspection package for systemscan."""

from systemscan.modules.system_info.architecture import (
    collect_architecture_summary,
)
from systemscan.modules.system_info.collector import (
    SystemInfoCollector,
    collect_system_information,
)
from systemscan.modules.system_info.environment import (
    collect_application_environment,
    collect_execution_environment,
    collect_safe_environment_vars,
)
from systemscan.modules.system_info.network_interfaces import (
    collect_network_interfaces,
)
from systemscan.modules.system_info.operating_system import (
    collect_operating_system_info,
    detect_active_shell,
)

__all__ = [
    "SystemInfoCollector",
    "collect_application_environment",
    "collect_architecture_summary",
    "collect_execution_environment",
    "collect_network_interfaces",
    "collect_operating_system_info",
    "collect_safe_environment_vars",
    "collect_system_information",
    "detect_active_shell",
]
