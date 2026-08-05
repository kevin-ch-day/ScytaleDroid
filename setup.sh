#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_REQUESTED="${SCYTALEDROID_PYTHON:-}"
ANDROID_SETUP_MODE="${SCYTALEDROID_SETUP_ANDROID:-auto}"
SETUP_VALIDATE="${SCYTALEDROID_SETUP_VALIDATE:-0}"
PYTHON_BIN=""
VENV_CREATED=0
REQ_FILE_DEFAULT="$ROOT_DIR/requirements.lock"
REQ_FILE_PAPER="$ROOT_DIR/requirements-paper-toolchain.txt"
REQ_FILE="${SCYTALEDROID_REQUIREMENTS_FILE:-$REQ_FILE_DEFAULT}"
if [[ "${SCYTALEDROID_PAPER_TOOLCHAIN:-0}" == "1" ]] && [[ -f "$REQ_FILE_PAPER" ]]; then
  REQ_FILE="$REQ_FILE_PAPER"
fi
SETUP_STATE_DIR="$ROOT_DIR/.setup"
REQ_HASH_FILE="$SETUP_STATE_DIR/requirements.sha256"
ANDROID_TOOLS_LIB="$ROOT_DIR/scripts/lib/android_tools.sh"

usage() {
  cat <<EOF
Usage: ./setup.sh [--validate]

Creates or refreshes the local Python environment and configured workspace
directories. It does not create databases, rotate credentials, or inspect
secret values.

  --validate  After setup, run the read-only new-system check and require the
              configured MariaDB and Permission Intel catalogs to be reachable.

Environment switches:
  SCYTALEDROID_SETUP_ANDROID=1          Provision Android tools for capture hosts.
  SCYTALEDROID_SETUP_INSTALL_SYSTEM=1   Install missing Fedora packages.
  SCYTALEDROID_SETUP_UPGRADE_TOOLING=1  Upgrade pip/setuptools/wheel.
  SCYTALEDROID_SETUP_VALIDATE=1         Same as --validate.
EOF
}

for argument in "$@"; do
  case "$argument" in
    --validate) SETUP_VALIDATE=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unsupported setup option: $argument" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$SETUP_VALIDATE" in
  0|1) ;;
  *)
    echo "Error: SCYTALEDROID_SETUP_VALIDATE must be 0 or 1." >&2
    exit 1
    ;;
esac

case "$ANDROID_SETUP_MODE" in
  auto|0|1) ;;
  *)
    echo "Error: SCYTALEDROID_SETUP_ANDROID must be auto, 0, or 1." >&2
    exit 1
    ;;
esac

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

python_available() {
  local candidate="$1"
  if [[ "$candidate" == */* ]]; then
    [[ -x "$candidate" ]]
  else
    command_exists "$candidate"
  fi
}

supported_python() {
  "$1" -c 'import sys; raise SystemExit(0 if (3, 11) <= sys.version_info[:2] <= (3, 13) else 1)' \
    >/dev/null 2>&1
}

select_base_python() {
  local candidate
  if [[ -n "$PYTHON_REQUESTED" ]]; then
    if ! python_available "$PYTHON_REQUESTED" || ! supported_python "$PYTHON_REQUESTED"; then
      echo "Error: SCYTALEDROID_PYTHON must select Python 3.11, 3.12, or 3.13." >&2
      exit 1
    fi
    printf '%s\n' "$PYTHON_REQUESTED"
    return 0
  fi

  for candidate in python3.13 python3.12 python3.11 python3; do
    if command_exists "$candidate" && supported_python "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  echo "Error: ScytaleDroid setup requires Python 3.11, 3.12, or 3.13." >&2
  echo "       Fedora: sudo dnf install python3.13 python3.13-devel" >&2
  exit 1
}

rpm_installed() {
  rpm -q "$1" >/dev/null 2>&1
}

echo "[Setup] Verifying Python availability..."
if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  if ! supported_python "$PYTHON_BIN"; then
    echo "Error: .venv uses an unsupported Python version. Remove .venv and rerun setup with Python 3.11-3.13 installed." >&2
    exit 1
  fi
else
  BASE_PYTHON="$(select_base_python)"
  echo "[Setup] Creating project virtual environment with $BASE_PYTHON..."
  "$BASE_PYTHON" -m venv "$ROOT_DIR/.venv"
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  VENV_CREATED=1
fi
echo "[Setup] Using project virtual environment: $PYTHON_BIN"

install_fedora_packages() {
  local packages=("$@")
  if ! command_exists dnf; then
    echo "Error: dnf is required to install Fedora packages: ${packages[*]}" >&2
    return 1
  fi
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    dnf install -y "${packages[@]}"
    return 0
  fi
  if command_exists sudo; then
    sudo dnf install -y "${packages[@]}"
    return 0
  fi
  echo "Error: sudo is unavailable; install these packages as an administrator: ${packages[*]}" >&2
  return 1
}

ensure_adb() {
  if command_exists adb; then
    echo "[Setup] adb is available."
    return 0
  fi
  if command_exists dnf; then
    echo "[Setup] adb not found. Installing android-tools..."
    install_fedora_packages android-tools >/dev/null
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
if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
  echo "[Setup] pip not detected, attempting to bootstrap with ensurepip..."
  if ! "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1; then
    echo "Error: Failed to bootstrap pip. Consider installing python3-pip via 'sudo dnf install python3-pip'." >&2
    exit 1
  fi
fi

# Build a safe pip install command
PIP_INSTALL=("$PYTHON_BIN" -m pip install --disable-pip-version-check)
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
    REQ_FILE="$REQ_FILE" "$PYTHON_BIN" - <<'PY'
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

if [[ "${SCYTALEDROID_SETUP_UPGRADE_TOOLING:-0}" == "1" ]]; then
  echo "[Setup] Upgrading pip to the latest version..."
  run_pip_install --upgrade pip >/dev/null
  echo "[Setup] pip is up to date."

  echo "[Setup] Upgrading build helpers (setuptools, wheel)..."
  run_pip_install --upgrade setuptools wheel >/dev/null
  echo "[Setup] Build helpers are up to date."
else
  echo "[Setup] Leaving pip/setuptools/wheel unchanged (set SCYTALEDROID_SETUP_UPGRADE_TOOLING=1 to upgrade)."
fi

if [[ -f "$REQ_FILE" && -s "$REQ_FILE" ]]; then
  mkdir -p "$SETUP_STATE_DIR"
  if [[ "$VENV_CREATED" -eq 1 ]] || [[ "${SCYTALEDROID_SETUP_FORCE:-0}" == "1" ]] || requirements_changed; then
    echo "[Setup] Installing Python requirements from $REQ_FILE..."
    run_pip_install -r "$REQ_FILE"
    echo "[Setup] Python requirements are up to date."
  else
    echo "[Setup] Python requirements already satisfied."
  fi
else
  echo "[Setup] No pinned requirements file found or file is empty. Skipping dependency installation."
fi

if ! "$PYTHON_BIN" -m pip check >/dev/null; then
  echo "Error: installed Python dependencies are inconsistent. Re-run setup after resolving pip output:" >&2
  "$PYTHON_BIN" -m pip check >&2 || true
  exit 1
fi
echo "[Setup] Python dependency check passed."
mkdir -p "$SETUP_STATE_DIR"
requirements_hash > "$REQ_HASH_FILE"

if command_exists dnf; then
  # Use actual RPM names (case-sensitive) so the presence check is accurate.
  FEDORA_DEPS=(python3-devel gcc libffi-devel openssl-devel python3-PyMySQL wireshark-cli mariadb)
  missing=()
  for pkg in "${FEDORA_DEPS[@]}"; do
    if ! rpm_installed "$pkg"; then
      missing+=("$pkg")
    fi
  done
  if (( ${#missing[@]} )); then
    echo "[Setup] Fedora detected. Missing system packages were found:"
    echo "        sudo dnf install ${missing[*]}"
    if [[ "${SCYTALEDROID_SETUP_INSTALL_SYSTEM:-0}" == "1" ]]; then
      echo "[Setup] Installing requested Fedora runtime packages..."
      install_fedora_packages "${missing[@]}"
    else
      echo "        Set SCYTALEDROID_SETUP_INSTALL_SYSTEM=1 to install them during setup."
    fi
  fi
fi

if [[ "$ANDROID_SETUP_MODE" == "1" ]]; then
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
elif command_exists adb; then
  echo "[Setup] Android tooling available; leaving it unchanged (set SCYTALEDROID_SETUP_ANDROID=1 to provision tools)."
else
  echo "[Setup] Android tooling is optional for this setup. Set SCYTALEDROID_SETUP_ANDROID=1 to install adb and SDK tools."
fi

if ! WORKSPACE_DIR_OUTPUT="$(PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON_BIN" - <<'PY'
from pathlib import Path

from scytaledroid.Config import app_config

print(Path(app_config.DATA_DIR) / "store" / "apk")
print(Path(app_config.DYNAMIC_EVIDENCE_ROOT))
print(Path(app_config.OUTPUT_DIR))
print(Path(app_config.LOGS_DIR))
PY
)"; then
  echo "Error: Could not resolve configured workspace directories." >&2
  exit 1
fi
mapfile -t WORKSPACE_DIRS <<< "$WORKSPACE_DIR_OUTPUT"
if [[ ${#WORKSPACE_DIRS[@]} -ne 4 ]] || [[ -z "${WORKSPACE_DIRS[0]}${WORKSPACE_DIRS[1]}${WORKSPACE_DIRS[2]}${WORKSPACE_DIRS[3]}" ]]; then
  echo "Error: Configured workspace directory resolution returned incomplete paths." >&2
  exit 1
fi
mkdir -p "${WORKSPACE_DIRS[@]}"

echo "[Setup] Workspace directories are ready (configured data/output/log roots)."
if ! command_exists tshark || ! command_exists capinfos; then
  echo "[Setup] Dynamic PCAP tools are missing. Install with: sudo scripts/install_wireshark_cli.sh"
fi
if ! command_exists mariadb || ! command_exists mariadb-dump; then
  echo "[Setup] MariaDB client tools are missing. Install with: sudo dnf install mariadb"
fi
if [[ -L "$ROOT_DIR/.env" ]]; then
  echo "[Setup] Existing .env is a symlink; replace it with an owner-only regular file before deployment checks."
  ENVIRONMENT_STATE="needs-repair"
elif [[ -f "$ROOT_DIR/.env" ]]; then
  ENV_MODE="$(stat -c '%a' "$ROOT_DIR/.env" 2>/dev/null || printf 'unknown')"
  if [[ "$ENV_MODE" == "600" ]]; then
    echo "[Setup] Existing owner-only .env detected; leaving it unchanged."
    ENVIRONMENT_STATE="ready"
  else
    echo "[Setup] Existing .env detected with mode $ENV_MODE; do not overwrite it. Run: chmod 600 .env"
    ENVIRONMENT_STATE="needs-repair"
  fi
else
  echo "[Setup] Fresh host: copy .env.example to .env, then run: chmod 600 .env"
  ENVIRONMENT_STATE="missing"
fi
if [[ "$ENVIRONMENT_STATE" == "ready" ]]; then
  echo "[Setup] Next: validate this configured host with:"
  echo "        ./setup.sh --validate"
else
  echo "[Setup] Next: repair/create .env and restore data/DB if applicable, then run:"
  echo "        ./setup.sh --validate"
fi
echo "        Use SCYTALEDROID_SETUP_ANDROID=1 ./setup.sh when this host will capture from Android devices."

if [[ "$SETUP_VALIDATE" == "1" ]]; then
  echo "[Setup] Running read-only configured-host validation..."
  if "$ROOT_DIR/run.sh" --new-system-check --require-database; then
    echo "[Setup] Validation passed: this host is ready for the configured workflows."
  else
    echo "[Setup] Validation failed: resolve the reported checks, then rerun ./setup.sh --validate." >&2
    exit 1
  fi
fi
