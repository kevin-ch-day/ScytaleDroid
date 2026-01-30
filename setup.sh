#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="$ROOT_DIR/requirements.txt"
SETUP_STATE_DIR="$ROOT_DIR/.setup"
REQ_HASH_FILE="$SETUP_STATE_DIR/requirements.sha256"
ANDROID_TOOLS_LIB="$ROOT_DIR/scripts/lib/android_tools.sh"

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

ensure_adb() {
  if command_exists adb; then
    echo "[Setup] adb is available."
    return 0
  fi
  if command_exists dnf; then
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
      echo "Error: adb not found. Re-run as sudo ./setup.sh to install android-tools." >&2
      exit 1
    fi
    echo "[Setup] adb not found. Installing android-tools..."
    sudo dnf install -y android-tools >/dev/null 2>&1 || true
    if ! command_exists adb; then
      echo "Error: adb still missing after install. Please install android-tools manually and re-run." >&2
      exit 1
    fi
    echo "[Setup] adb installed."
    return 0
  fi
  echo "Error: adb not found and no supported package manager detected. Please install adb and re-run." >&2
  exit 1
}

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

requirements_hash() {
  if command_exists sha256sum; then
    sha256sum "$REQ_FILE" | awk '{print $1}'
  else
    REQ_FILE="$REQ_FILE" python3 - <<'PY'
import hashlib
from pathlib import Path
import os
path = Path(os.environ["REQ_FILE"]).resolve()
data = path.read_bytes()
print(hashlib.sha256(data).hexdigest())
PY
  fi
}

requirements_changed() {
  if [[ ! -f "$REQ_FILE" || ! -s "$REQ_FILE" ]]; then
    return 1
  fi
  local current
  current="$(requirements_hash)"
  if [[ ! -f "$REQ_HASH_FILE" ]]; then
    return 0
  fi
  local previous
  previous="$(cat "$REQ_HASH_FILE" 2>/dev/null || true)"
  [[ "$current" != "$previous" ]]
}

echo "[Setup] Upgrading pip to the latest version..."
run_pip_install --upgrade pip >/dev/null
echo "[Setup] pip is up to date."

echo "[Setup] Upgrading build helpers (setuptools, wheel)..."
run_pip_install --upgrade setuptools wheel >/dev/null
echo "[Setup] Build helpers are up to date."

if [[ -f "$REQ_FILE" && -s "$REQ_FILE" ]]; then
  mkdir -p "$SETUP_STATE_DIR"
  if [[ "${SCYTALEDROID_SETUP_FORCE:-0}" == "1" ]] || requirements_changed; then
    echo "[Setup] Installing Python requirements from $REQ_FILE..."
    run_pip_install -r "$REQ_FILE"
    requirements_hash > "$REQ_HASH_FILE"
    echo "[Setup] Python requirements are up to date."
  else
    echo "[Setup] Python requirements already satisfied."
  fi
else
  echo "[Setup] No requirements.txt found or file is empty. Skipping dependency installation."
fi

if command_exists dnf; then
  # Use actual RPM names (case-sensitive) so the presence check is accurate.
  FEDORA_DEPS=(python3-devel gcc libffi-devel openssl-devel python3-PyMySQL)
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

ensure_adb

if [[ -f "$ANDROID_TOOLS_LIB" ]]; then
  if ! command_exists sdkmanager; then
    echo "[Setup] Android command-line tools not detected. Installing..."
    # shellcheck disable=SC1090
    source "$ANDROID_TOOLS_LIB"
    setup_android_tools_main
  else
    echo "[Setup] Android command-line tools already available."
  fi
else
  echo "[Setup] Android tools helper not found; skipping Android tools setup."
fi

echo "[Setup] Completed."
