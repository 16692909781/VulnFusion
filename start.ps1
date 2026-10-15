[CmdletBinding()]
param([ValidateRange(1, 65535)][int]$Port = 8090)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { $pythonPath = 'python' }
$settingsPath = Join-Path $PSScriptRoot '.env'
if (-not (Test-Path -LiteralPath $settingsPath)) {
    throw 'Missing .env. Copy .env.example to .env and configure the Kali connection first.'
}
& $pythonPath -m uvicorn backend.app:app --env-file $settingsPath --host 127.0.0.1 --port $Port
exit $LASTEXITCODE
