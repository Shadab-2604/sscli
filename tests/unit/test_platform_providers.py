"""Unit tests for platform providers (Linux, Windows, macOS) and distribution parsing."""

from unittest.mock import mock_open, patch

from systemscan.platform.detector import detect_installation_type, detect_platform
from systemscan.platform.linux import LinuxPlatform
from systemscan.platform.macos import MacOSPlatform
from systemscan.platform.windows import WindowsPlatform


def test_linux_os_release_kali_mock() -> None:
    kali_os_release = """NAME="Kali GNU/Linux"
VERSION="2024.1"
ID=kali
VERSION_ID="2024.1"
PRETTY_NAME="Kali GNU/Linux Rolling"
"""
    plat = LinuxPlatform()
    with patch("os.path.exists", side_effect=lambda p: p == "/etc/os-release"):
        with patch("builtins.open", mock_open(read_data=kali_os_release)):
            distro, ver = plat.get_linux_distribution()
            assert distro == "Kali GNU/Linux Rolling"
            assert ver == "2024.1"


def test_linux_os_release_ubuntu_mock() -> None:
    ubuntu_os_release = """NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
VERSION_ID="24.04"
PRETTY_NAME="Ubuntu 24.04 LTS"
"""
    plat = LinuxPlatform()
    with patch("os.path.exists", side_effect=lambda p: p == "/etc/os-release"):
        with patch("builtins.open", mock_open(read_data=ubuntu_os_release)):
            distro, ver = plat.get_linux_distribution()
            assert distro == "Ubuntu 24.04 LTS"
            assert ver == "24.04"


def test_linux_os_release_arch_mock() -> None:
    plat = LinuxPlatform()

    def mock_exists(p: str) -> bool:
        return p == "/etc/arch-release"

    with patch("os.path.exists", side_effect=mock_exists):
        distro, ver = plat.get_linux_distribution()
        assert distro == "Arch Linux"
        assert ver == "Rolling"


def test_windows_firmware_mock() -> None:
    win = WindowsPlatform()
    assert win.os_type.value == "windows"
    assert win.capabilities.can_inspect_windows_services is True
    # Verify fallback returns FirmwareInformation model
    fw = win.get_firmware_info(include_serials=False)
    assert fw is not None


def test_macos_provider_mock() -> None:
    mac = MacOSPlatform()
    assert mac.os_type.value == "macos"
    assert mac.capabilities.can_inspect_launchd is True
    fw = mac.get_firmware_info(include_serials=False)
    assert fw is not None
    assert fw.manufacturer == "Apple Inc."


def test_platform_detector() -> None:
    plat = detect_platform()
    assert plat is not None
    assert plat.os_type in ("windows", "linux", "macos")

    install_type = detect_installation_type()
    assert len(install_type) > 0
