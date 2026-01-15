#!/usr/bin/env bash
# Golden-path static demo runner (design/staging). Requires MariaDB DEV via .env.
# Usage: ./scripts/fedora/run_static_demo.sh /path/to/app.apk
set -euo pipefail

APK_PATH="${1:-}"
if [[ -z "$APK_PATH" || ! -f "$APK_PATH" ]]; then
  echo "Usage: $0 /path/to/app.apk"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  echo ".env not found in ${ROOT_DIR}; please configure SCYTALEDROID_DB_URL for MariaDB DEV."
  exit 1
fi

echo "[INFO] Checking DB status..."
python -m scytaledroid.Database.tools.db_status || {
  echo "[ERROR] DB status failed; aborting."
  exit 1
}

SESSION1="demo-$(date +%Y%m%d-%H%M%S)-1"
SESSION2="demo-$(date +%Y%m%d-%H%M%S)-2"

echo "[INFO] Running static analysis session ${SESSION1}"
"${ROOT_DIR}/run_mariadb.sh" static --apk "$APK_PATH" --session "$SESSION1" --scope-label DEMO

echo "[INFO] Running static analysis session ${SESSION2}"
"${ROOT_DIR}/run_mariadb.sh" static --apk "$APK_PATH" --session "$SESSION2" --scope-label DEMO

echo "[INFO] Completed. Verify DB tables for two distinct run_ids and no duplicate explosions."
