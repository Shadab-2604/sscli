[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

if (Test-Path $venvPython) {
    & $venvPython -m systemscan @RemainingArgs
} else {
    & python -m systemscan @RemainingArgs
}

