"""Unit tests for System Information modules and collectors."""

from systemscan.modules.models import OperatingSystemModel, SystemInformation
from systemscan.modules.system_info.architecture import collect_architecture_summary
from systemscan.modules.system_info.collector import collect_system_information
from systemscan.modules.system_info.environment import (
    collect_application_environment,
    collect_execution_environment,
)
from systemscan.modules.system_info.network_interfaces import (
    collect_network_interfaces,
)
from systemscan.modules.system_info.operating_system import (
    collect_operating_system_info,
)


def test_collect_operating_system_info() -> None:
    os_info = collect_operating_system_info()
    assert isinstance(os_info, OperatingSystemModel)
    assert len(os_info.name) > 0
    assert len(os_info.hostname) > 0
    assert len(os_info.machine_arch) > 0
    assert os_info.uptime_seconds >= 0
    assert len(os_info.uptime_formatted) > 0


def test_collect_architecture_summary() -> None:
    arch = collect_architecture_summary()
    assert "machine" in arch
    assert "pointer_bitness" in arch
    assert arch["pointer_bitness"] in (32, 64)
    assert isinstance(arch["is_64bit"], bool)


def test_collect_execution_environment() -> None:
    env = collect_execution_environment()
    assert len(env.username) > 0
    assert len(env.python_executable) > 0
    assert isinstance(env.is_elevated, bool)
    assert isinstance(env.safe_environment_vars, dict)

    # Verify secrets are excluded
    for k in env.safe_environment_vars.keys():
        assert "SECRET" not in k.upper()
        assert "TOKEN" not in k.upper()
        assert "PASSWORD" not in k.upper()


def test_collect_application_environment() -> None:
    app_env = collect_application_environment()
    assert len(app_env.version) > 0
    assert len(app_env.install_type) > 0
    assert len(app_env.config_dir) > 0


def test_collect_network_interfaces() -> None:
    ifaces = collect_network_interfaces()
    assert isinstance(ifaces, list)
    if ifaces:
        iface = ifaces[0]
        assert len(iface.name) > 0
        assert isinstance(iface.is_up, bool)


def test_collect_system_information_json() -> None:
    sys_info = collect_system_information(include_serials=False)
    assert isinstance(sys_info, SystemInformation)
    # Test JSON serialization round-trip
    json_str = sys_info.model_dump_json()
    assert len(json_str) > 0
    assert sys_info.os.name in json_str
    assert "cpu" in json_str
    assert "memory" in json_str
