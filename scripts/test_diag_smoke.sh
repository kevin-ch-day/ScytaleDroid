#!/usr/bin/env bash
set -euo pipefail

echo "[1/3] Human-readable diag..."
./run.sh --diag | sed -n '1,80p'

echo "[2/3] JSON diag..."
out="$(./run.sh --diag --json)"
echo "$out" | python3 -c 'import sys,json; json.loads(sys.stdin.read()); print("[OK] JSON valid")'

echo "[3/3] JSON contains required keys..."
tmp_json="$(mktemp)"
trap 'rm -f "$tmp_json"' EXIT
printf '%s' "$out" > "$tmp_json"
python3 - <<'PY' "$tmp_json"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

required = ["timings", "import_smells", "io_hotspots", "fast_wins"]
missing = [key for key in required if key not in payload]
assert not missing, f"Missing keys: {missing}"
print("[OK] Required keys present:", ", ".join(required))
PY

rm -f "$tmp_json"
trap - EXIT

echo "[DONE] Diagnostics smoke passed."
