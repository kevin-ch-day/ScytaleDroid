#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "[profile_v2] export..."
python3 scripts/publication/export_profile.py --profile v2 --v2-include-results-numbers
echo "EXPORT PASS"

echo "[profile_v2] lint..."
python3 - <<'PY'
from pathlib import Path
from scytaledroid.Publication.publication_contract import lint_publication_bundle

pub_root = Path("output/publication")
lint = lint_publication_bundle(pub_root)
if not lint.ok:
    raise SystemExit("LINT FAIL: " + "; ".join(lint.errors))
print("LINT PASS")
PY

