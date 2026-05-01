#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

# Runtime preset defaults:
# - physical: quiet operator mode on physical host
# - virtual: debug/dev defaults for virtualized validation
# - validation: debug/dev defaults plus system-test flag
export SCYTALEDROID_RUNTIME_PRESET="${SCYTALEDROID_RUNTIME_PRESET:-physical}"

python3 main.py "$@"
