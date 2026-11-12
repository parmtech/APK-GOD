$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (Get-Command py -ErrorAction SilentlyContinue) {
    py -3.12 -m venv .venv
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    python -m venv .venv
} else {
    throw "Install Python 3.12, then run this script again."
}
if ($LASTEXITCODE -ne 0) { throw "Python environment creation failed." }
$ApkGodPython = Join-Path $PWD ".venv\Scripts\python.exe"
& $ApkGodPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip setup failed." }
& $ApkGodPython -m pip install ".[analysis,runtime]"
if ($LASTEXITCODE -ne 0) { throw "APK-GOD dependency setup failed." }
& $ApkGodPython -m apk_god doctor
Write-Host "Start APK-GOD with scripts\start.ps1. Native symbolic analysis is an optional extra; Linux or WSL is recommended."
