#!/usr/bin/env sh
set -eu

# SysNet Scout one-click installer for Linux and Termux.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================="
echo "  SysNet Scout Linux Installer"
echo "  by pinkythegawd (MikePinku)"
echo "====================================="
echo

install_uv() {
  echo "[1/4] uv was not found. Installing uv..."

  if command -v curl >/dev/null 2>&1; then
    sh -c "$(curl -LsSf https://astral.sh/uv/install.sh)"
  elif command -v wget >/dev/null 2>&1; then
    sh -c "$(wget -qO- https://astral.sh/uv/install.sh)"
  else
    echo "[ERROR] curl or wget is required to install uv."
    exit 1
  fi
}

if command -v uv >/dev/null 2>&1; then
  UV_EXE="$(command -v uv)"
  echo "[1/4] uv is already installed."
else
  install_uv
  UV_EXE="$HOME/.local/bin/uv"
  if [ ! -x "$UV_EXE" ]; then
    echo "[ERROR] uv install completed but executable was not found at $UV_EXE"
    echo "Open a new terminal and run ./install.sh again."
    exit 1
  fi
fi

echo "[2/4] Installing Python 3.12 (managed by uv)..."
"$UV_EXE" python install 3.12

echo "[3/4] Syncing project environment..."
"$UV_EXE" sync --python 3.12

echo "[4/4] Running quick self-test..."
PYTHONPATH=src "$UV_EXE" run --python 3.12 -m sysnet_scout info --json >/dev/null

echo
echo "[SUCCESS] SysNet Scout is ready."
echo
echo "Mission control commands:"
echo "  ./scout.sh info --json"
echo "  ./scout.sh scan-hosts --cidr 192.168.1.0/24 --json"
echo "  ./scout.sh scan-ports --host 192.168.1.1 --profile web --fingerprint --hints"
echo "  ./scout.sh risk-trend --reports reports/ports_day1.json reports/ports_day2.json --json"
echo
