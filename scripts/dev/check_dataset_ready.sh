#!/usr/bin/env bash
#
# Dataset readiness quick-check
#
# This is intentionally fast and operator-friendly. It does NOT mutate state.
# It checks:
# - Host PCAP tools required for dataset-tier runs (tshark + capinfos)
# - DB baseline schema gates (static + dynamic)
# - Presence of static plans for the active research cohort packages
#
# Exit codes:
#   0  ready
#   1  not ready (action required)
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

fail=0

hr() { echo "------------------------------------------------------------"; }
ok() { echo "[OK] $*"; }
warn() { echo "[WARN] $*"; }
err() { echo "[ERROR] $*"; fail=1; }

hr
echo "ScytaleDroid Dataset Readiness Check"
echo "Workspace: $ROOT_DIR"
hr

echo "Host PCAP tools"
missing_tools=()
for tool in tshark capinfos; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool: $(command -v "$tool")"
  else
    missing_tools+=("$tool")
    err "$tool: missing"
  fi
done
if [[ ${#missing_tools[@]} -gt 0 ]]; then
  if [[ -x scripts/install_wireshark_cli.sh ]]; then
    warn "Fix: sudo scripts/install_wireshark_cli.sh"
  else
    warn "Fix: install wireshark-cli (tshark + capinfos) via OS package manager"
  fi
fi

hr
echo "DB schema gates"
python - <<'PY' || exit 1
from scytaledroid.Database.db_utils import schema_gate

def _show(name, fn):
    ok, msg, detail = fn()
    prefix = "[OK]" if ok else "[ERROR]"
    print(f"{prefix} {name}: {msg}")
    if detail and not ok:
        print(detail)
    return ok

all_ok = True
all_ok &= _show("static", schema_gate.static_schema_gate)
all_ok &= _show("dynamic", schema_gate.dynamic_schema_gate)
raise SystemExit(0 if all_ok else 1)
PY
if [[ $? -ne 0 ]]; then
  fail=1
fi

hr
echo "Static plans for active research cohort"
python - <<'PY' || exit 1
from scytaledroid.DynamicAnalysis import plan_selection
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_context

cohort = active_research_cohort_context()
label = str(cohort.get("display_name") or "Research cohort")
pkgs = [str(p).strip() for p in cohort.get("packages", ()) if str(p).strip()]
missing = []
for pkg in sorted({p.lower(): p for p in pkgs}.values()):
    candidates, _ = plan_selection._load_plan_candidates(pkg)
    if not candidates:
        missing.append(pkg)

if missing:
    print(f"[ERROR] Missing static plans for {label}:")
    for pkg in missing:
        print(f"  - {pkg}")
    print(f"Fix: Static APK analysis -> Analyze research cohort -> {label}")
    raise SystemExit(1)
print(f"[OK] {label}: plans present for {len(pkgs)} package(s).")
raise SystemExit(0)
PY
if [[ $? -ne 0 ]]; then
  fail=1
fi

hr
echo "Config (audit visibility)"
python - <<'PY' || exit 1
from scytaledroid.Config import app_config
print(f"MIN_PCAP_BYTES={getattr(app_config, 'DYNAMIC_MIN_PCAP_BYTES', None)}")
print(f"MIN_DURATION_S={getattr(app_config, 'DYNAMIC_MIN_DURATION_S', None)}")
print(f"TARGET_DURATION_S={getattr(app_config, 'DYNAMIC_TARGET_DURATION_S', None)}")
PY

hr
if [[ "$fail" -eq 0 ]]; then
  ok "Dataset environment is READY."
  exit 0
fi
err "Dataset environment is NOT ready. Fix errors above."
exit 1
