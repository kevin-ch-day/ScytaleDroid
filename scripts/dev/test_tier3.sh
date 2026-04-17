#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

pytest -q "$@" \
  tests/gates \
  tests/docs \
  tests/analysis \
  tests/database \
  tests/db \
  tests/db_utils \
  tests/test_main_db_maintenance.py

python -m compileall -q scytaledroid tests
