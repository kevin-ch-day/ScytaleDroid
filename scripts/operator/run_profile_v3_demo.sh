#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

export SCYTALEDROID_PAPER_STRICT=1

echo "[provenance] stamp..."
python3 scripts/operator/provenance_stamp.py --write-audit

echo "[profile_v3] catalog validate..."
python3 scripts/profile_tools/profile_v3_catalog_validate.py

echo "[profile_v3] apk freshness check..."
python3 scripts/profile_tools/profile_v3_apk_freshness_check.py

echo "[profile_v3] scripted coverage audit..."
python3 scripts/profile_tools/profile_v3_scripted_coverage_audit.py

echo "[profile_v3] export..."
# Strict mode: missing stats deps should fail for paper/demo runs.
python3 scripts/publication/export_profile.py --profile v3 --strict
echo "EXPORT PASS"

echo "[profile_v3] lint..."
python3 - <<'PY'
from pathlib import Path
from scytaledroid.Publication.profile_v3_contract import lint_profile_v3_bundle

pub_root = Path("output/publication/profile_v3")
lint = lint_profile_v3_bundle(pub_root)
if not lint.ok:
    raise SystemExit("LINT FAIL: " + "; ".join(lint.errors))
print("LINT PASS")
PY
