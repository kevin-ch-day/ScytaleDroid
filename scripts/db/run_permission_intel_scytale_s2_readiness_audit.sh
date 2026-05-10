#!/usr/bin/env bash
# Read-only S2-P1A bundle: PI config + queue audit + static linkage + targeted pytest.
# Requires: repo root, venv optional, PYTHONPATH=.
#
#   ./scripts/db/run_permission_intel_scytale_s2_readiness_audit.sh
#
# Does not run DML/DDL. Queue/matrix scripts connect only when env is set.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${PYTHONPATH:-.}"

echo "=== 1) Permission Intel config (operational) ==="
python scripts/db/check_permission_intel.py || true

echo ""
echo "=== 2) PI queue compatibility (skips if PI unset) ==="
python scripts/db/audit_permission_intel_queue_compatibility.py || {
  echo "(queue audit exited non-zero — often PI not configured in this shell)"
}

echo ""
echo "=== 3) Core DB static → observation linkage (skips if DB down) ==="
python scripts/db/audit_static_permission_observation_linkage.py || {
  echo "(linkage audit exited non-zero — check SCYTALEDROID_DB_*)"
}

echo ""
echo "=== 4) Targeted pytest ==="
python -m pytest \
  tests/database/test_permission_intel_triage_vocabulary_contract.py \
  tests/static_analysis/test_permissions_db_persistence.py \
  tests/database/test_permission_intel_family.py \
  tests/database/test_permission_intel_sql_routing_guard.py \
  tests/database/test_permission_observation_contract_transform.py \
  tests/database/test_queue_apply_compat_check.py \
  tests/static_analysis/test_run_dispatch_permission_intel_preflight.py \
  tests/static_analysis/test_permission_flow_failures.py \
  tests/database/test_schema_gate_permissions.py \
  -q

echo ""
echo "Done. See docs/database/permission_intel_scytaledroid_s2_p1a_operational_readiness.md"
