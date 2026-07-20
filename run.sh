#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${SCYTALEDROID_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi
if [[ "$PYTHON_BIN" == */* ]]; then
  [[ -x "$PYTHON_BIN" ]] || { echo "Error: Python interpreter is not executable: $PYTHON_BIN" >&2; exit 1; }
elif ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Error: Python interpreter is not available: $PYTHON_BIN" >&2
  exit 1
fi
cd "$ROOT_DIR"

# Runtime preset defaults:
# - physical: quiet operator mode on physical host
# - virtual: debug/dev defaults for virtualized validation
# - validation: debug/dev defaults plus system-test flag
export SCYTALEDROID_RUNTIME_PRESET="${SCYTALEDROID_RUNTIME_PRESET:-physical}"

exec "$PYTHON_BIN" "$ROOT_DIR/main.py" "$@"
