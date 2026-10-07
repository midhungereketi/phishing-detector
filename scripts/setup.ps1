$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        & py -3.12 -m venv .venv
    } else {
        & python -m venv .venv
    }
    if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.12, then run setup again.' }
}
& .\.venv\Scripts\python.exe -m pip install -r backend\requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
& npm.cmd ci
if ($LASTEXITCODE -ne 0) { throw 'Node dependency installation failed.' }
Write-Host 'Setup complete. Run npm run dev. To retrain: .\.venv\Scripts\python.exe -m backend.train --download'
