param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = 'Stop'
$hasArgs = $Args -and $Args.Count -gt 0
if (-not $hasArgs) {
    Write-Host "====================================="
    Write-Host "  SysNet Scout Launcher (PowerShell)"
    Write-Host "====================================="
    Write-Host ""
    Write-Host "Try one of these:"
    Write-Host "  .\scout.cmd info --json"
    Write-Host "  .\scout.cmd scan-hosts --cidr 192.168.1.0/24 --json"
    Write-Host "  .\scout.cmd scan-ports --host 192.168.1.1 --profile web --fingerprint --hints"
    Write-Host "  .\scout.cmd risk-trend --reports reports/ports_day1.json reports/ports_day2.json --json"
    Write-Host ""
    exit 0
}
$uv = Join-Path $env:USERPROFILE '.local\bin\uv.exe'

if (-not (Test-Path $uv)) {
    Write-Error "uv.exe not found at $uv. Install uv first: irm https://astral.sh/uv/install.ps1 | iex"
    exit 1
}

$env:PYTHONPATH = 'src'
& $uv run --python 3.12 -m sysnet_scout @Args
exit $LASTEXITCODE
