#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
if [ -x .venv/bin/python ]; then
    exec .venv/bin/python -m apk_god serve
fi
exec python3 -m apk_god serve
