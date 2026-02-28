#!/usr/bin/env bash
set -euo pipefail

# Paper #3 (Profile v3) freeze-event wrapper.
# Produces a deterministic audit trail: provenance -> gates -> strict manifest -> strict exports -> strict lint.

cd "$(dirname "$0")/../.."

export SCYTALEDROID_PAPER_STRICT=1
export SCYTALEDROID_FAIL_ON_DIRTY=1

SNAPSHOT="${1:-data/state/ZY22JK89DR/inventory/scoped/latest_scoped_paper3_beta.json}"

echo "[RUN] provenance"
python3 scripts/operator/provenance_stamp.py --write-audit --fail-on-dirty
PROV_RECEIPT="$(ls -1t output/audit/provenance/provenance_*.json | head -n 1 || true)"

echo "[RUN] v3 gates (pinned snapshot: $SNAPSHOT)"
python3 scripts/profile_tools/profile_v3_integrity_gates.py --freshness-snapshot "$SNAPSHOT" --write-audit
GATES_RECEIPT="$(ls -1t output/audit/profile_v3/integrity_gates_*.json | head -n 1 || true)"

echo "[RUN] strict v3 manifest build"
python3 scripts/profile_tools/profile_v3_manifest_build.py --strict

echo "[RUN] strict v3 exports"
python3 scripts/publication/export_profile.py --profile v3 --strict

echo "[RUN] strict v3 lint"
python3 scripts/publication/profile_v3_lint.py --strict --write-audit

echo "[RUN] freeze bundle manifest"
python3 scripts/operator/profile_v3_freeze_bundle.py \
  --snapshot "$SNAPSHOT" \
  ${PROV_RECEIPT:+--provenance-receipt "$PROV_RECEIPT"} \
  ${GATES_RECEIPT:+--gates-receipt "$GATES_RECEIPT"}

echo "FREEZE EVENT PASS"
