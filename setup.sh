#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="$ROOT_DIR/requirements.txt"

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

echo "[Setup] Verifying Python 3 availability..."
if ! command_exists python3; then
  echo "Error: python3 is not installed. Please install Python 3 (e.g. 'sudo dnf install python3') and re-run." >&2
  exit 1
fi

# ensure pip
if ! python3 -m pip --version >/dev/null 2>&1; then
  echo "[Setup] pip not detected, attempting to bootstrap with ensurepip..."
  python3 -m ensurepip --upgrade >/dev/null 2>&1 || {
    echo "Error: Failed to bootstrap pip. Consider installing python3-pip via 'sudo dnf install python3-pip'." >&2
    exit 1
  }
fi

# upgrade pip
PIP_INSTALL=(python3 -m pip install)
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  if python3 -m pip help install 2>&1 | grep -q "--break-system-packages"; then
    PIP_INSTALL+=(--break-system-packages)
  fi
fi

run_pip_install() {
  local args=("$@")
  if ! "${PIP_INSTALL[@]}" "${args[@]}"; then
    echo "Error: pip failed to install packages. If you see an 'externally-managed-environment' message, try running this script inside a virtual environment or rerun with elevated privileges." >&2
    exit 1
  fi
}

echo "[Setup] Upgrading pip to the latest version..."
run_pip_install --upgrade pip

if [[ -f "$REQ_FILE" && -s "$REQ_FILE" ]]; then
  echo "[Setup] Installing Python requirements from $REQ_FILE..."
  run_pip_install -r "$REQ_FILE"
else
  echo "[Setup] No requirements.txt found or file is empty. Skipping dependency installation."
fi

echo "[Setup] Completed."
