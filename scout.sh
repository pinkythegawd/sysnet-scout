#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$#" -eq 0 ]; then
  echo "====================================="
  echo "  SysNet Scout Launcher (Unix)"
  echo "====================================="
  echo
  echo "Try one of these:"
  echo "  ./scout.sh info --json"
  echo "  ./scout.sh scan-hosts --cidr 192.168.1.0/24 --json"
  echo "  ./scout.sh scan-ports --host 192.168.1.1 --profile web --fingerprint --hints"
  echo "  ./scout.sh risk-trend --reports reports/ports_day1.json reports/ports_day2.json --json"
  echo
  exit 0
fi

if command -v uv >/dev/null 2>&1; then
  UV_EXE="$(command -v uv)"
else
  UV_EXE="$HOME/.local/bin/uv"
fi

if [ ! -x "$UV_EXE" ]; then
  echo "uv not found. Run ./install.sh first."
  exit 1
fi

PYTHONPATH=src exec "$UV_EXE" run --python 3.12 -m sysnet_scout "$@"
