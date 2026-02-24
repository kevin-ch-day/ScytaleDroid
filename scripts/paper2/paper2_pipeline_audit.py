#!/usr/bin/env python3
"""Deep audit for Paper #2 ML + dynamic pipeline (freeze-anchored).

This is a reviewer-simulation / bug-hunting tool. It cross-checks:
- freeze cohort structure (12 apps, 36 runs, 1 idle + 2 interaction per app)
- ML windowing integrity (per-run scored window counts)
- baseline-only training invariants (same baseline run id per app across all runs)
- per-app threshold determinism (same thresholds across the 3 runs)
- seed determinism (seed derived from identity key matches stored seed)

Outputs:
  output/publication/qa/paper2_pipeline_audit_v1.json
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.ml.seed_identity import derive_seed  # noqa: E402

FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"
EVIDENCE_ROOT = REPO_ROOT / "output" / "evidence" / "dynamic"
PAPER_RESULTS = REPO_ROOT / "output" / "publication" / "manifests" / "paper_results_v1.json"
OUT = REPO_ROOT / "output" / "publication" / "qa" / "paper2_pipeline_audit_v1.json"


def _rjson(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ml_scores_len(run_id: str) -> int | None:
    p = EVIDENCE_ROOT / run_id / "analysis" / "ml" / "v1" / "anomaly_scores_iforest.csv"
    if not p.exists():
        return None
    try:
        n = 0
        with p.open("r", encoding="utf-8") as f:
            for i, ln in enumerate(f):
                if i == 0:
                    continue
                if ln.strip():
                    n += 1
        return int(n)
    except Exception:
        return None


def _bucket_from_manifest(man: dict) -> str:
    ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
    op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
    run_profile = str(op.get("run_profile") or ds.get("run_profile") or "").strip().lower()
    interaction_level = str(op.get("interaction_level") or ds.get("interaction_level") or "").strip().lower()
    if run_profile.startswith("baseline"):
        return "idle"
    if interaction_level == "scripted" or "scripted" in run_profile:
        return "scripted"
    if interaction_level == "manual" or "manual" in run_profile:
        return "manual"
    return "other"


@dataclass(frozen=True)
class AuditSummary:
    ok: bool
    generated_at_utc: str
    freeze_dataset_hash: str | None
    included_run_ids: int
    apps: int
    errors: list[str]
    warnings: list[str]
    notes: dict[str, object]


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    for p in (FREEZE, PAPER_RESULTS):
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    freeze = _rjson(FREEZE) or {}
    paper = _rjson(PAPER_RESULTS) or {}
    included = [str(x) for x in (freeze.get("included_run_ids") or [])]
    freeze_hash = freeze.get("freeze_dataset_hash")

    if len(included) != 36:
        errors.append(f"FREEZE_INCLUDED_RUN_IDS_UNEXPECTED:{len(included)}:expected_36")

    # Load manifests + model manifests for included runs.
    by_pkg: dict[str, list[dict]] = {}
    by_run: dict[str, dict] = {}
    model_by_run: dict[str, dict] = {}
    for rid in included:
        run_dir = EVIDENCE_ROOT / rid
        man = _rjson(run_dir / "run_manifest.json")
        if not isinstance(man, dict):
            errors.append(f"MISSING_OR_BAD_RUN_MANIFEST:{rid}")
            continue
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        if not pkg:
            errors.append(f"MISSING_PACKAGE_NAME:{rid}")
            continue
        by_pkg.setdefault(pkg, []).append(man)
        by_run[rid] = man

        mm = _rjson(run_dir / "analysis" / "ml" / "v1" / "model_manifest.json")
        if isinstance(mm, dict):
            model_by_run[rid] = mm
        else:
            errors.append(f"MISSING_MODEL_MANIFEST:{rid}")

    if len(by_pkg) != 12:
        errors.append(f"UNEXPECTED_APP_COUNT:{len(by_pkg)}:expected_12")

    # Per-app structural checks + baseline-only invariants.
    interaction_breakdown = {"scripted": 0, "manual": 0, "other": 0, "idle": 0}
    threshold_mismatch = 0
    provenance_mismatch = 0
    seed_mismatch = 0
    windows_missing = 0
    windows_zero = 0

    for pkg, mans in sorted(by_pkg.items(), key=lambda kv: kv[0]):
        # Identify baseline run id (idle).
        run_ids = []
        idle_ids = []
        inter_ids = []
        for man in mans:
            rid = str(man.get("dynamic_run_id") or "").strip() or ""
            if not rid:
                continue
            run_ids.append(rid)
            b = _bucket_from_manifest(man)
            interaction_breakdown[b] = int(interaction_breakdown.get(b, 0) + 1)
            if b == "idle":
                idle_ids.append(rid)
            else:
                inter_ids.append(rid)
        if len(run_ids) != 3:
            errors.append(f"APP_RUN_COUNT_NOT_3:{pkg}:{len(run_ids)}")
            continue
        if len(idle_ids) != 1:
            errors.append(f"APP_BASELINE_COUNT_NOT_1:{pkg}:{len(idle_ids)}")
            continue
        if len(inter_ids) != 2:
            errors.append(f"APP_INTERACTIVE_COUNT_NOT_2:{pkg}:{len(inter_ids)}")
            continue

        baseline_id = idle_ids[0]

        # Check threshold determinism across the 3 runs (IF threshold should match).
        if_thresholds = []
        oc_thresholds = []
        for rid in run_ids:
            mm = model_by_run.get(rid) or {}
            models = mm.get("models") if isinstance(mm.get("models"), dict) else {}
            if_m = models.get("isolation_forest") if isinstance(models.get("isolation_forest"), dict) else {}
            oc_m = models.get("one_class_svm") if isinstance(models.get("one_class_svm"), dict) else {}
            if_thresholds.append(if_m.get("threshold_value"))
            oc_thresholds.append(oc_m.get("threshold_value"))

            # Baseline provenance should point to the baseline run id for this app.
            bp = if_m.get("baseline_provenance") if isinstance(if_m.get("baseline_provenance"), dict) else {}
            bp_rid = str(bp.get("baseline_run_id") or "").strip()
            if bp_rid and bp_rid != baseline_id:
                provenance_mismatch += 1
                errors.append(f"BASELINE_PROVENANCE_MISMATCH:{pkg}:{rid}:expected:{baseline_id}:got:{bp_rid}")

            # Seed determinism: seed must match identity-derived seed.
            seed = mm.get("seed")
            identity_key = mm.get("identity_key_used")
            if seed is None or not identity_key:
                warnings.append(f"MISSING_SEED_OR_IDENTITY_KEY:{rid}")
            else:
                try:
                    expected = derive_seed(str(identity_key))
                    if int(seed) != int(expected):
                        seed_mismatch += 1
                        errors.append(f"SEED_MISMATCH:{rid}:expected:{expected}:got:{seed}")
                except Exception:
                    warnings.append(f"SEED_CHECK_FAILED:{rid}")

            # Window counts: must exist and be non-zero for included runs.
            nwin = _ml_scores_len(rid)
            if nwin is None:
                windows_missing += 1
                errors.append(f"MISSING_ANOMALY_SCORES_IFOREST:{rid}")
            elif nwin <= 0:
                windows_zero += 1
                errors.append(f"ZERO_WINDOWS_SCORED:{rid}")

        def _all_equal(xs) -> bool:
            ys = [x for x in xs if x is not None]
            if len(ys) <= 1:
                return True
            return all(abs(float(ys[0]) - float(y)) <= 1e-12 for y in ys[1:])

        if not _all_equal(if_thresholds):
            threshold_mismatch += 1
            errors.append(f"IF_THRESHOLD_NOT_CONSTANT_WITHIN_APP:{pkg}:{if_thresholds}")
        if not _all_equal(oc_thresholds):
            threshold_mismatch += 1
            errors.append(f"OCSVM_THRESHOLD_NOT_CONSTANT_WITHIN_APP:{pkg}:{oc_thresholds}")

    # Paper results cross-check.
    if int(paper.get("n_apps") or 0) != 12:
        warnings.append(f"PAPER_RESULTS_N_APPS_UNEXPECTED:{paper.get('n_apps')}")
    if int(paper.get("n_runs_total") or 0) != 36:
        warnings.append(f"PAPER_RESULTS_N_RUNS_TOTAL_UNEXPECTED:{paper.get('n_runs_total')}")

    notes = {
        "interaction_breakdown_runs": interaction_breakdown,
        "threshold_mismatch_apps": threshold_mismatch,
        "baseline_provenance_mismatches": provenance_mismatch,
        "seed_mismatches": seed_mismatch,
        "windows_missing": windows_missing,
        "windows_zero": windows_zero,
    }

    # Message-level warning if the cohort is not scripted-only.
    if int(interaction_breakdown.get("manual") or 0) > 0:
        warnings.append(
            "COHORT_INTERACTIONS_INCLUDE_MANUAL:paper_language_must_say_interactive_or_clarify_scripted_vs_manual"
        )

    ok = len(errors) == 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            asdict(
                AuditSummary(
                    ok=ok,
                    generated_at_utc=datetime.now(UTC).isoformat(),
                    freeze_dataset_hash=str(freeze_hash) if freeze_hash else None,
                    included_run_ids=len(included),
                    apps=len(by_pkg),
                    errors=errors,
                    warnings=warnings,
                    notes=notes,
                )
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(str(OUT))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())

