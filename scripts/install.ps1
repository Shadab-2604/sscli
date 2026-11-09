<#
.SYNOPSIS
    Universal System Security & Intelligence CLI (systemscan) - Safe Installer for Windows
.DESCRIPTION
    Validates Python 3.10+, provisions an isolated virtual environment, installs systemscan,
    configures global command execution, and validates CLI entry point availability.
.PARAMETER VenvDir
    Directory path for the isolated virtual environment (default: .venv).
.PARAMETER Global
    Configures global command shim so 'systemscan' can be run from ANY terminal without activating venv.
.PARAMETER DryRun
    Simulates pre-flight validation without modifying the filesystem.
.EXAMPLE
    .\scripts\install.ps1
.EXAMPLE
    .\scripts\install.ps1 -Global
#>

[CmdletBinding()]
param (
    [string]$VenvDir = ".venv",
    [switch]$Global,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

Write-Host "=== SystemScan Safe Installer (Windows) ===" -ForegroundColor Cyan
Write-Host "Starting installation pre-flight checks..."

# 1. Detect OS & Architecture
$osInfo = Get-CimInstance Win32_OperatingSystem
$arch = $env:PROCESSOR_ARCHITECTURE
Write-Host "Detected Platform: Windows ($arch) - $($osInfo.Caption)" -ForegroundColor White

# 2. Administrator Warning (Non-Root Philosophy)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "[!] Note: Running as Administrator is not required for installation." -ForegroundColor Yellow
    Write-Host "    SystemScan installs safely into user-scoped environments." -ForegroundColor Yellow
}

# 3. Discover Python 3.10+ Executable
$pythonCandidates = @("py", "python", "python3")
$selectedPython = $null
$selectedVersion = $null

foreach ($cand in $pythonCandidates) {
    try {
        $verOutput = & $cand -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>$null
        if ($verOutput) {
            $major, $minor = $verOutput.Trim().Split('.')
            if ([int]$major -ge 3 -and [int]$minor -ge 10) {
                $selectedPython = $cand
                $selectedVersion = (& $cand -V 2>$null).Trim()
                break
            }
        }
    } catch {
        # Candidate not present, continue search
    }
}

if (-not $selectedPython) {
    Write-Host "[ERROR] Python 3.10 or newer was not detected in PATH." -ForegroundColor Red
    Write-Host "Remediation:" -ForegroundColor Yellow
    Write-Host "  1. Download Python 3.12+ from https://www.python.org/downloads/windows/"
    Write-Host "  2. Ensure 'Add Python to PATH' is checked during installation."
    Write-Host "  3. Alternatively via winget: winget install Python.Python.3.12"
    exit 1
}

Write-Host "Using Python:     $selectedVersion ($selectedPython)" -ForegroundColor Green

# 4. Dry-run Mode
if ($DryRun) {
    Write-Host ""
    Write-Host "[DRY-RUN] Pre-flight checks passed successfully." -ForegroundColor Yellow
    Write-Host "Planned Actions:"
    Write-Host "  1. Create virtual environment at: $VenvDir"
    Write-Host "  2. Upgrade pip inside virtual environment"
    Write-Host "  3. Install systemscan package in editable mode"
    Write-Host "  4. Register global systemscan command in user PATH"
    exit 0
}

# 5. Provision Virtual Environment
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$targetVenvPath = Join-Path $repoRoot $VenvDir

if (Test-Path $targetVenvPath) {
    Write-Host "Virtual environment already exists at: $targetVenvPath" -ForegroundColor White
} else {
    Write-Host "Creating isolated virtual environment at: $targetVenvPath..." -ForegroundColor White
    & $selectedPython -m venv $targetVenvPath
}

$venvPython = Join-Path $targetVenvPath "Scripts\python.exe"
$venvSystemscan = Join-Path $targetVenvPath "Scripts\systemscan.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "[ERROR] Failed to locate virtual environment python at: $venvPython" -ForegroundColor Red
    exit 1
}

# 6. Install Package
Write-Host "Upgrading pip and installing SystemScan with dependencies..." -ForegroundColor White
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -e $repoRoot --quiet

# 7. Global Command Registration
$globalInstalled = $false
$targetShimDir = $null

# Check candidates on existing PATH
$pathDirs = $env:PATH -split ';'
$preferredDirs = @(
    "$env:LOCALAPPDATA\Python\bin",
    "$env:USERPROFILE\.local\bin",
    "$env:APPDATA\Python\Scripts"
)

foreach ($dir in $preferredDirs) {
    if ($pathDirs -contains $dir -or (Test-Path $dir)) {
        $targetShimDir = $dir
        break
    }
}

if (-not $targetShimDir) {
    $targetShimDir = "$env:LOCALAPPDATA\Python\bin"
}

if (-not (Test-Path $targetShimDir)) {
    New-Item -ItemType Directory -Path $targetShimDir -Force | Out-Null
}

$shimPath = Join-Path $targetShimDir "systemscan.cmd"
$shimContent = @"
@echo off
setlocal
if exist "$venvPython" (
    "$venvPython" -m systemscan %*
) else (
    python -m systemscan %*
)
endlocal
"@

Set-Content -Path $shimPath -Value $shimContent -Force
Write-Host "Global command shim registered at: $shimPath" -ForegroundColor Green

# Check if targetShimDir is in PATH
if ($env:PATH -split ';' -contains $targetShimDir) {
    $globalInstalled = $true
} else {
    Write-Host "[!] Note: '$targetShimDir' is not yet in your active PATH." -ForegroundColor Yellow
    Write-Host "    To run 'systemscan' from ANY terminal without activating venv, add it to your user PATH:" -ForegroundColor Yellow
    Write-Host "    [Environment]::SetEnvironmentVariable('PATH', [Environment]::GetEnvironmentVariable('PATH', 'User') + ';$targetShimDir', 'User')" -ForegroundColor Cyan
}

# 8. Verification
if (Test-Path $venvSystemscan) {
    Write-Host ""
    Write-Host "=== Installation Successful! ===" -ForegroundColor Green
    & $venvSystemscan version
    Write-Host ""
    Write-Host "You can now run 'systemscan' directly from any terminal:" -ForegroundColor White
    Write-Host "  systemscan            (Launches the interactive terminal dashboard)" -ForegroundColor Cyan
    Write-Host "  systemscan doctor     (Diagnoses dependencies & platform matrix)" -ForegroundColor Cyan
    Write-Host "  systemscan scan .     (Performs read-only filesystem inspection)" -ForegroundColor Cyan
} else {
    Write-Host "[ERROR] 'systemscan.exe' was not created in $targetVenvPath\Scripts." -ForegroundColor Red
    exit 1
}
