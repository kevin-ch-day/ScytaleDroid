#!/usr/bin/env bash
# Dev shortcut: run static full profile on TikTok and audit the run.
set -euo pipefail
SESSION_LABEL="static-dev-tiktok"
export SCYTALEDROID_DEV_SHORTCUTS=1

cd "$(dirname "$0")/.."

printf "2\nT\nR\nn\n%s\n" "$SESSION_LABEL" | ./run.sh || true

python -m scytaledroid.Database.db_scripts.static_run_audit --session "$SESSION_LABEL" || true
