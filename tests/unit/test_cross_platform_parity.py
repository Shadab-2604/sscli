"""Unit tests validating true cross-platform parity and capability taxonomy.

Validates parity across:
1. Kali Linux
2. Windows 10
3. Windows 11
4. macOS Intel
5. macOS Apple Silicon
"""

from unittest.mock import patch

from systemscan.platform.base import CapabilityStatus
from systemscan.platform.detection import (
    detect_platform_name,
    is_apple_silicon,
    is_kali_linux,
)
from systemscan.platform.linux import (
    LinuxDeviceProvider,
    LinuxFilesystemProvider,
    LinuxNetworkProvider,
    LinuxPlatform,
    LinuxSecurityProvider,
    LinuxSystemProvider,
)
from systemscan.platform.macos import (
    MacOSDeviceProvider,
    MacOSFilesystemProvider,
    MacOSNetworkProvider,
    MacOSPlatform,
    MacOSSecurityProvider,
    MacOSSystemProvider,
)
from systemscan.platform.windows import (
    WindowsDeviceProvider,
    WindowsFilesystemProvider,
    WindowsNetworkProvider,
    WindowsPlatform,
    WindowsSecurityProvider,
    WindowsSystemProvider,
)

EXPECTED_CAPABILITIES = {
    "hardware_gpu",
    "hardware_motherboard",
    "hardware_disks",
    "services_inspection",
    "startup_persistence",
    "network_firewall",
    "network_interfaces",
    "network_connections",
    "network_wifi",
    "devices_usb",
    "filesystem_posix_permissions",
    "filesystem_windows_acls",
    "filesystem_symlinks",
    "malware_yara",
}


def test_platform_capabilities_matrix_completeness() -> None:
    """Ensure all platforms return the exact set of 14 capability dimensions."""
    platforms = [LinuxPlatform(), WindowsPlatform(), MacOSPlatform()]
    for plat in platforms:
        matrix = plat.get_capabilities_matrix()
        assert set(matrix.keys()) == EXPECTED_CAPABILITIES
        for cap, status in matrix.items():
            assert isinstance(status, CapabilityStatus), f"{cap} returned invalid status type"
            assert plat.get_capability_status(cap) == status

    # Querying nonexistent capability returns UNSUPPORTED
    assert plat.get_capability_status("nonexistent_feature") == CapabilityStatus.UNSUPPORTED


def test_platform_specific_expected_capabilities() -> None:
    """Validate platform-specific capability expectations."""
    lin = LinuxPlatform()
    assert lin.get_capability_status("filesystem_posix_permissions") == CapabilityStatus.AVAILABLE
    assert lin.get_capability_status("filesystem_windows_acls") == CapabilityStatus.UNSUPPORTED

    win = WindowsPlatform()
    assert win.get_capability_status("filesystem_windows_acls") == CapabilityStatus.AVAILABLE
    assert win.get_capability_status("filesystem_posix_permissions") == CapabilityStatus.UNSUPPORTED

    mac = MacOSPlatform()
    assert mac.get_capability_status("filesystem_posix_permissions") == CapabilityStatus.AVAILABLE
    assert mac.get_capability_status("filesystem_windows_acls") == CapabilityStatus.UNSUPPORTED


def test_kali_detection() -> None:
    """Test detection logic for Kali Linux environments."""
    kali_release = """NAME="Kali GNU/Linux"
ID=kali
VERSION="2024.1"
PRETTY_NAME="Kali GNU/Linux Rolling"
"""
    with patch("sys.platform", "linux"):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=kali_release):
                assert is_kali_linux() is True
                assert detect_platform_name(detailed=True) == "Kali Linux"


def test_windows_version_detection() -> None:
    """Test platform detection distinguishes Windows 10 vs Windows 11."""
    with patch("sys.platform", "win32"):
        # Windows 11 build (22000+)
        with patch("platform.version", return_value="10.0.22631"):
            assert detect_platform_name(detailed=True) == "Windows 11"

        # Windows 10 build (< 22000)
        with patch("platform.version", return_value="10.0.19045"):
            assert detect_platform_name(detailed=True) == "Windows 10"


def test_macos_architecture_detection() -> None:
    """Test platform detection distinguishes macOS Intel vs Apple Silicon."""
    with patch("sys.platform", "darwin"):
        with patch("platform.machine", return_value="arm64"):
            assert is_apple_silicon() is True
            assert detect_platform_name(detailed=True) == "macOS Apple Silicon"

        with patch("platform.machine", return_value="x86_64"):
            assert is_apple_silicon() is False
            assert detect_platform_name(detailed=True) == "macOS Intel"


def test_linux_subproviders() -> None:
    """Test modular Linux subproviders can be instantiated and executed safely."""
    sys_prov = LinuxSystemProvider()
    assert isinstance(sys_prov.is_elevated(), bool)
    assert isinstance(sys_prov.get_systemd_services(), list)
    assert isinstance(sys_prov.get_startup_entries(), list)

    fs_prov = LinuxFilesystemProvider()
    assert fs_prov.is_pseudo_filesystem("/proc") is True
    assert fs_prov.is_pseudo_filesystem("/home/user") is False
    xdg = fs_prov.get_xdg_directories()
    assert "config" in xdg and "cache" in xdg

    sec_prov = LinuxSecurityProvider()
    fw = sec_prov.audit_firewall()
    assert hasattr(fw, "is_enabled")

    dev_prov = LinuxDeviceProvider()
    assert hasattr(dev_prov, "discover_devices")

    net_prov = LinuxNetworkProvider()
    assert hasattr(net_prov, "get_default_gateway")


def test_windows_subproviders() -> None:
    """Test modular Windows subproviders can be instantiated and executed safely."""
    sys_prov = WindowsSystemProvider()
    assert isinstance(sys_prov.is_elevated(), bool)
    assert isinstance(sys_prov.get_startup_entries(), list)

    fs_prov = WindowsFilesystemProvider()
    norm = fs_prov.normalize_long_path(r"C:\test\path")
    assert "C:" in norm
    assert isinstance(fs_prov.get_drive_letters(), list)

    sec_prov = WindowsSecurityProvider()
    fw = sec_prov.audit_firewall()
    assert hasattr(fw, "is_enabled")

    dev_prov = WindowsDeviceProvider()
    assert hasattr(dev_prov, "discover_devices")

    net_prov = WindowsNetworkProvider()
    assert hasattr(net_prov, "get_default_gateway")


def test_macos_subproviders() -> None:
    """Test modular macOS subproviders can be instantiated and executed safely."""
    sys_prov = MacOSSystemProvider()
    assert isinstance(sys_prov.is_elevated(), bool)
    assert isinstance(sys_prov.get_startup_entries(), list)

    fs_prov = MacOSFilesystemProvider()
    dirs = fs_prov.get_standard_directories()
    assert "library" in dirs
    assert isinstance(fs_prov.get_volumes(), list)

    sec_prov = MacOSSecurityProvider()
    fw = sec_prov.audit_firewall()
    assert hasattr(fw, "is_enabled")

    dev_prov = MacOSDeviceProvider()
    assert hasattr(dev_prov, "discover_devices")

    net_prov = MacOSNetworkProvider()
    assert hasattr(net_prov, "get_default_gateway")
