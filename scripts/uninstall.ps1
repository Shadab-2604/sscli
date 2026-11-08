<#
.SYNOPSIS
    Universal System Security & Intelligence CLI (systemscan) - Safe Uninstaller for Windows
.DESCRIPTION
    Safely removes the virtual environment or package files, with explicit preservation of
    user configuration, reports, and scan history by default.
.PARAMETER VenvDir
    Directory path of the virtual environment to remove (default: .venv).
.PARAMETER RemoveData
    Switch to permanently delete configuration, reports, and history.
.PARAMETER DryRun
    Simulates uninstallation actions without modifying the filesystem.
.PARAMETER Yes
    Bypasses interactive confirmation.
.EXAMPLE
    .\scripts\uninstall.ps1
.EXAMPLE
    .\scripts\uninstall.ps1 -DryRun
.EXAMPLE
    .\scripts\uninstall.ps1 -RemoveData
#>

[CmdletBinding()]
param (
    [string]$VenvDir = ".venv",
    [switch]$RemoveData,
    [switch]$DryRun,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"

Write-Host "=== SystemScan Safe Uninstaller (Windows) ===" -ForegroundColor Cyan

$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$targetVenvPath = Join-Path $repoRoot $VenvDir

$roamingData = [System.IO.Path]::Combine($env:APPDATA, "systemscan")
$localCache = [System.IO.Path]::Combine($env:LOCALAPPDATA, "systemscan")

Write-Host "Target Environment: $targetVenvPath" -ForegroundColor White
if ($RemoveData) {
    Write-Host "Data Removal:       PURGE ALL APPLICATION DATA" -ForegroundColor Red
} else {
    Write-Host "Data Removal:       PRESERVE CONFIGURATION & REPORTS" -ForegroundColor Green
}

if ($DryRun) {
    Write-Host ""
    Write-Host "[DRY-RUN] Uninstallation Plan:" -ForegroundColor Yellow
    if (Test-Path $targetVenvPath) {
        Write-Host "  • Would delete virtual environment: $targetVenvPath"
    } else {
        Write-Host "  • Virtual environment not found (skipped): $targetVenvPath"
    }
    if ($RemoveData) {
        Write-Host "  • Would delete roaming data: $roamingData"
        Write-Host "  • Would delete local cache:  $localCache"
    } else {
        Write-Host "  • Preserving configuration & reports at: $roamingData"
    }
    exit 0
}

# Interactive confirmation
if (-not $Yes) {
    Write-Host ""
    if ($RemoveData) {
        $prompt = "Are you sure you want to uninstall systemscan AND permanently delete all reports, config, and scan history? (y/N)"
    } else {
        $prompt = "Proceed with removing the virtual environment '$VenvDir'? (Configuration and reports will be preserved) (y/N)"
    }
    $resp = Read-Host -Prompt $prompt
    if ($resp -notmatch "^[yY](es)?$") {
        Write-Host "Uninstallation cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# 1. Remove virtual environment
if (Test-Path $targetVenvPath) {
    Write-Host "Removing virtual environment: $targetVenvPath..." -ForegroundColor White
    Remove-Item -Path $targetVenvPath -Recurse -Force
    Write-Host "Virtual environment removed." -ForegroundColor Green
} else {
    Write-Host "Virtual environment not found at $targetVenvPath (skipping)." -ForegroundColor Gray
}

# 2. Optionally remove user data
if ($RemoveData) {
    Write-Host ""
    Write-Host "Purging application data directories..." -ForegroundColor Red
    foreach ($d in @($roamingData, $localCache)) {
        if (Test-Path $d) {
            # Safety checks: Never delete root or system drive
            $resolved = (Get-Item $d).FullName
            if ($resolved -ne $env:SystemDrive -and $resolved -ne $env:USERPROFILE) {
                Remove-Item -Path $resolved -Recurse -Force
                Write-Host "  Deleted: $resolved" -ForegroundColor Red
            }
        }
    }
    Write-Host "Application data successfully removed." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "User configuration, scan history, and reports preserved at:" -ForegroundColor Green
    Write-Host "  $roamingData" -ForegroundColor White
}

Write-Host ""
Write-Host "SystemScan uninstallation completed." -ForegroundColor Green

