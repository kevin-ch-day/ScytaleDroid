#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

pytest -q "$@"
python -m compileall -q scytaledroid tests
