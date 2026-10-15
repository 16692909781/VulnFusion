[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    & python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create Python environment.' }
}
& $pythonPath -m pip install -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Could not install Agent dependencies.' }
& $pythonPath (Join-Path $PSScriptRoot 'configure.py') --write
if ($LASTEXITCODE -ne 0) { throw 'Could not generate client configuration.' }
Write-Host 'Copy the generated MCP entry into your Agent settings, then reconnect the MCP server.'
