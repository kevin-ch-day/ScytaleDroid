#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

pytest -q "$@" \
  tests/device_analysis \
  tests/harvest \
  tests/dynamic \
  tests/static_analysis \
  tests/persistence \
  tests/ml \
  tests/api \
  tests/publication \
  tests/integration \
  tests/profile_tools \
  tests/test_inventory_guard_state.py \
  tests/test_inventory_status.py \
  tests/test_inventory_summary.py \
  tests/test_db_paramstyle.py
