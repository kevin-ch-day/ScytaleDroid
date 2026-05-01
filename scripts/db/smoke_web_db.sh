#!/usr/bin/env bash
# Run the ScytaleDroid-Web PHP DB smoke script (read-only checks).
# Set SCYTALEDROID_WEB_ROOT to your web checkout; default matches common layout.
set -euo pipefail
ROOT="${SCYTALEDROID_WEB_ROOT:-/var/www/html/ScytaleDroid-Web}"
SMOKE="${ROOT}/scripts/sd_web_db_smoke.php"
if [[ ! -f "$SMOKE" ]]; then
  echo "Missing ${SMOKE}. Set SCYTALEDROID_WEB_ROOT to the ScytaleDroid-Web directory." >&2
  exit 2
fi
exec php "$SMOKE" "$@"
