"""Unit tests for platform detection and abstraction."""

from systemscan.platform import (
    LinuxPlatform,
    MacOSPlatform,
    OSType,
    WindowsPlatform,
    detect_installation_type,
    detect_platform,
)


def test_platform_contracts() -> None:
    # Test current host platform instantiation
    plat = detect_platform()
    assert plat.os_type in (OSType.WINDOWS, OSType.LINUX, OSType.MACOS)
    assert len(plat.architecture) > 0
    assert len(plat.os_name) > 0
    summary = plat.get_system_summary()
    assert isinstance(summary, dict)
    assert "os" in summary
    assert "architecture" in summary


def test_windows_platform_mock() -> None:
    win = WindowsPlatform()
    assert win.os_type == OSType.WINDOWS
    assert win.capabilities.can_inspect_windows_acls is True
    assert win.capabilities.can_inspect_posix_permissions is False


def test_linux_platform_mock() -> None:
    lin = LinuxPlatform()
    assert lin.os_type == OSType.LINUX
    assert lin.capabilities.can_inspect_posix_permissions is True
    assert lin.capabilities.can_inspect_windows_acls is False


def test_macos_platform_mock() -> None:
    mac = MacOSPlatform()
    assert mac.os_type == OSType.MACOS
    assert mac.capabilities.can_inspect_launchd is True


def test_detect_installation_type() -> None:
    install_type = detect_installation_type()
    assert isinstance(install_type, str)
    assert len(install_type) > 0
