$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (Test-Path ".venv\Scripts\python.exe") {
    & ".venv\Scripts\python.exe" -m apk_god serve
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 -m apk_god serve
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    python -m apk_god serve
} else {
    throw "Install Python 3.10 or newer, then run this script again."
}
