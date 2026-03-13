#!/usr/bin/env sh
set -eu

# Termux helper for SysNet Scout.
# This script installs required Termux packages and optionally enables storage access.

if [ -z "${PREFIX:-}" ] || [ ! -d "$PREFIX" ] || ! printf '%s' "$PREFIX" | grep -qi "com.termux"; then
  echo "This helper is intended to run inside Termux."
  echo "If you are on Linux desktop/server, use ./install.sh directly."
  exit 1
fi

echo "====================================="
echo "  SysNet Scout Termux Setup"
echo "  by pinkythegawd (MikePinku)"
echo "====================================="
echo

echo "[1/5] Updating package index..."
pkg update -y

echo "[2/5] Installing required packages..."
pkg install -y curl wget

echo "[3/5] Optional storage permission..."
if command -v termux-setup-storage >/dev/null 2>&1; then
  echo "Granting shared storage permission (you may see a prompt)."
  termux-setup-storage || true
else
  echo "termux-setup-storage command not found, skipping."
fi

echo "[4/5] Ensuring installer scripts are executable..."
chmod +x ./install.sh ./scout.sh

echo "[5/5] Running project installer..."
./install.sh

echo
echo "[SUCCESS] Termux setup complete."
echo "Use:"
echo "  ./scout.sh info --json"
echo "  ./scout.sh scan-ports --host 192.168.1.1 --profile web --fingerprint --hints"
echo "  ./scout.sh risk-trend --reports reports/ports_day1.json reports/ports_day2.json --json"
