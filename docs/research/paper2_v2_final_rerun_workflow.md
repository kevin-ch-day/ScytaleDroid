# Paper 2 v2 Final Rerun Workflow

Use this only after collection is explicitly complete. Do not run this during optional collection.

## Purpose

Produce the final submission lock once, regenerate all Paper 2 v2 outputs, and compare the final package with the preserved 114-run checkpoint.

## Preserved Checkpoint

- Checkpoint package: `output/_internal/publication/paper2_v2/`
- Checkpoint minimum validation: `output/_internal/publication/paper2_v2/minimum_validation/`
- Checkpoint size: 15 apps, 114 runs

Before the final rerun, copy the checkpoint package to a timestamped comparison directory:

```bash
CHECKPOINT_COPY=output/_internal/publication/paper2_v2_checkpoint_114run_$(date -u +%Y%m%dT%H%M%SZ)
rsync -a output/_internal/publication/paper2_v2/ "$CHECKPOINT_COPY"/
```

## Final Rerun Workflow

Run from the repository root only after the operator confirms collection is closed.

The freeze rebuild and locked-dataset scoring are currently supported through
the ScytaleDroid CLI, because those steps use the active cohort/device runtime
configuration:

```text
./run.sh
  Machine Learning
    2) Rebuild locked dataset anchor
    3) Refresh ML scoring
    5) Refresh locked dataset bundle
    6) QA audit
```

After those menu steps complete, run the deterministic publication scripts:

```bash
set -euo pipefail

export PYTHONPATH=.

# 3. Regenerate canonical Paper 2 v2 results.
python scripts/publication/generate_paper2_results_v2.py

# 4-8. Rerun held-out validation, feature ablation, bytes/sec control,
# seed stability, and temporal-order control.
python scripts/publication/generate_paper2_minimum_validation.py

# 9. Regenerate the supplemental locked runtime bundle.
python - <<'PY'
import json
from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import freeze_anchor_path
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import paper_artifacts_path
from scytaledroid.DynamicAnalysis.ml.artifact_bundle_writer import write_locked_runtime_deliverables_bundle

payload = json.loads(paper_artifacts_path(freeze_anchor_path()).read_text(encoding="utf-8"))
artifacts = write_locked_runtime_deliverables_bundle(
    fig_b1_run_id=str(payload.get("fig_B1_run_id") or "").strip(),
    interaction_tag=str(payload.get("interaction_tag") or "").strip() or None,
)
print(artifacts.out_root)
print(artifacts.artifacts_manifest_json)
PY

# 10. Run package contract validation.
python - <<'PY'
from scytaledroid.Publication.paper2_v2_contract import validate_paper2_v2_results_contract

result = validate_paper2_v2_results_contract()
print("ok", result.ok)
print("errors", result.errors)
print("warnings", result.warnings)
raise SystemExit(0 if result.ok else 1)
PY

# 11. Run independent recomputation.
python scripts/publication/validate_paper2_results_v2.py --write

# 12. Compare final results with the preserved checkpoint.
CHECKPOINT_COPY_PATH="$CHECKPOINT_COPY" python - <<'PY'
import csv
import json
import os
from pathlib import Path

before = Path(os.environ["CHECKPOINT_COPY_PATH"])
after = Path("output/_internal/publication/paper2_v2")

def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))

def read_csv(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

before_results = read_json(before / "publication_results_v2.json")
after_results = read_json(after / "publication_results_v2.json")
before_validation = read_json(before / "minimum_validation" / "summary.json")
after_validation = read_json(after / "minimum_validation" / "summary.json")

summary = {
    "before_root": str(before),
    "after_root": str(after),
    "before_dataset": before_results.get("dataset"),
    "after_dataset": after_results.get("dataset"),
    "before_primary": before_results.get("primary_result"),
    "after_primary": after_results.get("primary_result"),
    "before_validation": {
        "apps": before_validation.get("apps"),
        "runs": before_validation.get("runs"),
        "heldout_eligible_apps": before_validation.get("heldout_eligible_apps"),
        "temporal_order_status": before_validation.get("temporal_order_status"),
    },
    "after_validation": {
        "apps": after_validation.get("apps"),
        "runs": after_validation.get("runs"),
        "heldout_eligible_apps": after_validation.get("heldout_eligible_apps"),
        "temporal_order_status": after_validation.get("temporal_order_status"),
    },
}

out = after / "manifest" / "paper2_v2_checkpoint_comparison.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(out)
PY
```

## Notes

- If any menu action or script path in this workflow changes, update this file before the final rerun.
- Do not hand-edit the freeze, evidence packs, score files, or generated result tables.
- Do not update the manuscript until the final package validates and the checkpoint comparison is reviewed.
- The comparison must call out cohort/run changes, selected build changes, primary IF deltas, held-out baseline changes, bytes/sec control changes, seed stability changes, and temporal-order control changes.
