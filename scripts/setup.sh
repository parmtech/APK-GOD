#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install '.[full]'
.venv/bin/python -m apk_god doctor
printf '\nStart APK-GOD with: .venv/bin/python -m apk_god serve\n'
