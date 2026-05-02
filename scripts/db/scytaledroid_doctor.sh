#!/usr/bin/env bash
# Operator readiness: main DB, view posture, semantic smoke, permission intel, optional web smoke.
# Run from repo root: ./scripts/db/scytaledroid_doctor.sh
#
# Environment overrides:
#   SCYTALEDROID_DOCTOR_QUICK=1     — only Primary DB + Permission Intel (fast gate).
#   SCYTALEDROID_DOCTOR_SKIP_POSTURE=1
#   SCYTALEDROID_DOCTOR_SKIP_SEMANTIC=1
#   SCYTALEDROID_DOCTOR_SKIP_INTEL=1
#   SCYTALEDROID_WEB_ROOT=…       — enables Web DB smoke (unless SKIP_WEB=1).
#   SCYTALEDROID_DOCTOR_SKIP_WEB=1
#
# Requires: env for MariaDB (SCYTALEDROID_DB_*) when exercising DB steps.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

FAIL=0
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found"
  exit 2
fi

QUICK="${SCYTALEDROID_DOCTOR_QUICK:-0}"
SKIP_POSTURE="${SCYTALEDROID_DOCTOR_SKIP_POSTURE:-0}"
SKIP_SEM="${SCYTALEDROID_DOCTOR_SKIP_SEMANTIC:-0}"
SKIP_INTEL="${SCYTALEDROID_DOCTOR_SKIP_INTEL:-0}"
SKIP_WEB="${SCYTALEDROID_DOCTOR_SKIP_WEB:-0}"

if [[ "$QUICK" =~ ^(1|true|yes|on)$ ]]; then
  SKIP_POSTURE=1
  SKIP_SEM=1
  SKIP_WEB=1
fi

echo "========================================"
echo " ScytaleDroid doctor ($(basename "$0"))"
echo "========================================"

run_py() {
  python3 "$@"
}

echo ""
echo "## Primary DB (quick)"
if run_py -c "
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core.db_engine import DatabaseEngine
if not db_config.db_enabled():
    print('Main DB: not configured (filesystem-only / optional)')
    raise SystemExit(0)
eng = DatabaseEngine()
eng.fetch_one('SELECT 1')
eng.close()
print('Main DB: OK')
"; then
  echo "  -> OK"
else
  echo "  -> FAILED"
  FAIL=1
fi

if [[ ! "$SKIP_POSTURE" =~ ^(1|true|yes|on)$ ]]; then
  echo ""
  echo "## Static consumer views — posture"
  if run_py scripts/db/recreate_web_consumer_views.py posture; then
    echo "  -> OK"
  else
    echo "  -> FAILED"
    FAIL=1
  fi
else
  echo ""
  echo "## Static consumer views — posture: skipped"
fi

if [[ ! "$SKIP_SEM" =~ ^(1|true|yes|on)$ ]]; then
  echo ""
  echo "## Static consumer views — semantic"
  if run_py scripts/db/recreate_web_consumer_views.py semantic; then
    echo "  -> OK"
  else
    echo "  -> FAILED"
    FAIL=1
  fi
else
  echo ""
  echo "## Static consumer views — semantic: skipped"
fi

if [[ ! "$SKIP_INTEL" =~ ^(1|true|yes|on)$ ]]; then
  echo ""
  echo "## Permission Intel"
  if run_py scripts/db/check_permission_intel.py; then
    echo "  -> OK"
  else
    echo "  -> FAILED or not paper-grade ready"
    FAIL=1
  fi
else
  echo ""
  echo "## Permission Intel: skipped"
fi

WEB_ROOT="${SCYTALEDROID_WEB_ROOT:-}"
echo ""
if [[ -n "$WEB_ROOT" ]] && [[ ! "$SKIP_WEB" =~ ^(1|true|yes|on)$ ]]; then
  echo "## Web DB smoke (SCYTALEDROID_WEB_ROOT=$WEB_ROOT)"
  if bash scripts/db/smoke_web_db.sh; then
    echo "  -> OK"
  else
    echo "  -> FAILED"
    FAIL=1
  fi
else
  echo "## Web DB smoke: skipped (set SCYTALEDROID_WEB_ROOT or unset SKIP_WEB)"
fi

echo ""
echo "========================================"
if [[ "$FAIL" -eq 0 ]]; then
  echo " Summary: READY — safe to run static analysis"
  echo "========================================"
  exit 0
fi

echo " Summary: ISSUES — fix failures above before long runs"
echo "========================================"
exit 1
