"""Unit tests for storage diagnostics, corruption checks, shortcut virus remediation, and file carving."""

from __future__ import annotations

from pathlib import Path

from systemscan.devices.repair import StorageRepairEngine


def test_normalize_drive_target():
    """Verify drive letter normalization."""
    assert StorageRepairEngine.normalize_drive_target("e") in ("E:", "e")
    assert StorageRepairEngine.normalize_drive_target("E:\\") in ("E:", "E:\\")
    assert StorageRepairEngine.normalize_drive_target("/dev/sdb1") == "/dev/sdb1"


def test_remediate_shortcut_virus(tmp_path: Path):
    """Verify shortcut virus remediation detects malicious lnk shortcuts and autorun droppers."""
    drive = tmp_path / "usb_drive"
    drive.mkdir()

    # Normal doc
    normal_doc = drive / "homework.docx"
    normal_doc.write_bytes(b"PK\x03\x04normal doc")

    # Autorun dropper
    autorun = drive / "autorun.inf"
    autorun.write_text("[autorun]\nopen=wscript.exe malware.vbs")

    # Malicious shortcut
    malicious_lnk = drive / "Documents.lnk"
    malicious_lnk.write_bytes(b"\x4c\x00\x00\x00powershell.exe -w hidden -c malware.vbs")

    res = StorageRepairEngine.remediate_shortcut_virus_and_unhide(str(drive))
    assert str(autorun) in res["autorun_droppers"]
    assert str(malicious_lnk) in res["suspicious_shortcuts"]


def test_file_carving(tmp_path: Path):
    """Verify file carving finds JPEG and PNG file signatures in raw/orphaned files."""
    corrupt_dir = tmp_path / "lost_data"
    corrupt_dir.mkdir()

    # Create dummy lost files with real headers
    jpg_file = corrupt_dir / "FILE0001.chk"
    jpg_file.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 100)

    png_file = corrupt_dir / "FILE0002.dat"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 50)

    carved = StorageRepairEngine.carve_lost_files(str(corrupt_dir))
    formats = [c["detected_format"] for c in carved]
    assert "JPEG Image" in formats
    assert "PNG Image" in formats
