#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="$ROOT_DIR/requirements.txt"

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

rpm_installed() {
  rpm -q "$1" >/dev/null 2>&1
}

echo "[Setup] Verifying Python 3 availability..."
if ! command_exists python3; then
  echo "Error: python3 is not installed. Please install Python 3 (e.g. 'sudo dnf install python3') and re-run." >&2
  exit 1
fi

# Ensure pip is available
if ! python3 -m pip --version >/dev/null 2>&1; then
  echo "[Setup] pip not detected, attempting to bootstrap with ensurepip..."
  if ! python3 -m ensurepip --upgrade >/dev/null 2>&1; then
    echo "Error: Failed to bootstrap pip. Consider installing python3-pip via 'sudo dnf install python3-pip'." >&2
    exit 1
  fi
fi

# Build a safe pip install command
PIP_INSTALL=(python3 -m pip install --disable-pip-version-check)
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  # Prefer user installs to avoid noisy "Defaulting to user" messages.
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    PIP_INSTALL+=(--user)
  fi
  # Only append --break-system-packages if pip supports it (Fedora/EME-friendly)
  if python3 -m pip help install 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_INSTALL+=(--break-system-packages)
  fi
fi

# Silence pip unless there is actionable output.
PIP_INSTALL+=(--quiet)

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  export PIP_ROOT_USER_ACTION=ignore
fi

run_pip_install() {
  local args=("$@")
  if ! "${PIP_INSTALL[@]}" "${args[@]}"; then
    echo "Error: pip failed to install packages. If you see an 'externally-managed-environment' message, run inside a virtual environment or rerun with elevated privileges." >&2
    exit 1
  fi
}

echo "[Setup] Upgrading pip to the latest version..."
run_pip_install --upgrade pip >/dev/null
echo "[Setup] pip is up to date."

echo "[Setup] Upgrading build helpers (setuptools, wheel)..."
run_pip_install --upgrade setuptools wheel >/dev/null
echo "[Setup] Build helpers are up to date."

if [[ -f "$REQ_FILE" && -s "$REQ_FILE" ]]; then
  echo "[Setup] Installing Python requirements from $REQ_FILE..."
  run_pip_install -r "$REQ_FILE"
  echo "[Setup] Python requirements are up to date."
else
  echo "[Setup] No requirements.txt found or file is empty. Skipping dependency installation."
fi

if command_exists dnf; then
  FEDORA_DEPS=(python3-devel gcc libffi-devel openssl-devel)
  missing=()
  for pkg in "${FEDORA_DEPS[@]}"; do
    if ! rpm_installed "$pkg"; then
      missing+=("$pkg")
    fi
  done
  if (( ${#missing[@]} )); then
    echo "[Setup] Fedora detected. Missing system packages were found:"
    echo "        sudo dnf install ${missing[*]}"
  fi
fi

echo "[Setup] Completed."
