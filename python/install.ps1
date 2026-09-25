$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv not found. Install it: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
}

Write-Host "Creating virtual environment..."
uv venv .venv

Write-Host "Installing dependencies..."
uv pip install --python .venv\Scripts\python.exe -r requirements.txt

Write-Host ""
Write-Host "Done. Activate with:"
Write-Host "  .venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "Then run:"
Write-Host "  python esolve.py --help"
