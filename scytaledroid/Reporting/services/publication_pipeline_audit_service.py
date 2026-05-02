"""Runtime service for frozen-archive pipeline audits."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml.seed_identity import derive_seed


def _freeze_path() -> Path:
    return Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"


def _evidence_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _publication_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "publication"


def _write_legacy_aliases() -> bool:
    return str(os.environ.get("SCYTALEDROID_WRITE_LEGACY_ALIASES") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _rjson(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ml_scores_len(run_id: str) -> int | None:
    path = _evidence_root() / run_id / "analysis" / "ml" / "v1" / "anomaly_scores_iforest.csv"
    if not path.exists():
        return None
    try:
        n = 0
        with path.open("r", encoding="utf-8") as handle:
            for i, line in enumerate(handle):
                if i == 0:
                    continue
                if line.strip():
                    n += 1
        return int(n)
    except Exception:
        return None


def _bucket_from_manifest(manifest: dict) -> str:
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    run_profile = str(operator.get("run_profile") or dataset.get("run_profile") or "").strip().lower()
    interaction_level = str(operator.get("interaction_level") or dataset.get("interaction_level") or "").strip().lower()
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


def generate_pipeline_audit() -> tuple[Path, bool]:
    """Generate the deep frozen-archive pipeline audit."""

    freeze = _freeze_path()
    evidence_root = _evidence_root()
    pub_root = _publication_root()
    publication_results = pub_root / "manifests" / "publication_results_v1.json"
    legacy_publication_results = pub_root / "manifests" / "paper_results_v1.json"
    out = pub_root / "qa" / "pipeline_audit_v1.json"

    errors: list[str] = []
    warnings: list[str] = []
    results_path = publication_results if publication_results.exists() else legacy_publication_results
    for path in (freeze, results_path):
        if not path.exists():
            raise RuntimeError(f"Missing required input: {path}")

    freeze_payload = _rjson(freeze) or {}
    publication_payload = _rjson(results_path) or {}
    included = [str(x) for x in (freeze_payload.get("included_run_ids") or [])]
    freeze_hash = freeze_payload.get("freeze_dataset_hash")

    if len(included) != 36:
        errors.append(f"FREEZE_INCLUDED_RUN_IDS_UNEXPECTED:{len(included)}:expected_36")

    by_pkg: dict[str, list[dict]] = {}
    model_by_run: dict[str, dict] = {}
    for rid in included:
        run_dir = evidence_root / rid
        manifest = _rjson(run_dir / "run_manifest.json")
        if not isinstance(manifest, dict):
            errors.append(f"MISSING_OR_BAD_RUN_MANIFEST:{rid}")
            continue
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        pkg = str(target.get("package_name") or "").strip().lower()
        if not pkg:
            errors.append(f"MISSING_PACKAGE_NAME:{rid}")
            continue
        by_pkg.setdefault(pkg, []).append(manifest)

        model_manifest = _rjson(run_dir / "analysis" / "ml" / "v1" / "model_manifest.json")
        if isinstance(model_manifest, dict):
            model_by_run[rid] = model_manifest
        else:
            errors.append(f"MISSING_MODEL_MANIFEST:{rid}")

    if len(by_pkg) != 12:
        errors.append(f"UNEXPECTED_APP_COUNT:{len(by_pkg)}:expected_12")

    interaction_breakdown = {"scripted": 0, "manual": 0, "other": 0, "idle": 0}
    threshold_mismatch = 0
    provenance_mismatch = 0
    seed_mismatch = 0
    windows_missing = 0
    windows_zero = 0

    for pkg, manifests in sorted(by_pkg.items(), key=lambda kv: kv[0]):
        run_ids: list[str] = []
        idle_ids: list[str] = []
        inter_ids: list[str] = []
        for manifest in manifests:
            rid = str(manifest.get("dynamic_run_id") or "").strip() or ""
            if not rid:
                continue
            run_ids.append(rid)
            bucket = _bucket_from_manifest(manifest)
            interaction_breakdown[bucket] = int(interaction_breakdown.get(bucket, 0) + 1)
            if bucket == "idle":
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
        if_thresholds = []
        oc_thresholds = []
        for rid in run_ids:
            model_manifest = model_by_run.get(rid) or {}
            models = model_manifest.get("models") if isinstance(model_manifest.get("models"), dict) else {}
            if_model = models.get("isolation_forest") if isinstance(models.get("isolation_forest"), dict) else {}
            oc_model = models.get("one_class_svm") if isinstance(models.get("one_class_svm"), dict) else {}
            if_thresholds.append(if_model.get("threshold_value"))
            oc_thresholds.append(oc_model.get("threshold_value"))

            baseline_provenance = if_model.get("baseline_provenance") if isinstance(if_model.get("baseline_provenance"), dict) else {}
            bp_rid = str(baseline_provenance.get("baseline_run_id") or "").strip()
            if bp_rid and bp_rid != baseline_id:
                provenance_mismatch += 1
                errors.append(f"BASELINE_PROVENANCE_MISMATCH:{pkg}:{rid}:expected:{baseline_id}:got:{bp_rid}")

            seed = model_manifest.get("seed")
            identity_key = model_manifest.get("identity_key_used")
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

            nwin = _ml_scores_len(rid)
            if nwin is None:
                windows_missing += 1
                errors.append(f"MISSING_ANOMALY_SCORES_IFOREST:{rid}")
            elif nwin <= 0:
                windows_zero += 1
                errors.append(f"ZERO_WINDOWS_SCORED:{rid}")

        def _all_equal(values) -> bool:
            usable = [x for x in values if x is not None]
            if len(usable) <= 1:
                return True
            return all(abs(float(usable[0]) - float(v)) <= 1e-12 for v in usable[1:])

        if not _all_equal(if_thresholds):
            threshold_mismatch += 1
            errors.append(f"IF_THRESHOLD_NOT_CONSTANT_WITHIN_APP:{pkg}:{if_thresholds}")
        if not _all_equal(oc_thresholds):
            threshold_mismatch += 1
            errors.append(f"OCSVM_THRESHOLD_NOT_CONSTANT_WITHIN_APP:{pkg}:{oc_thresholds}")

    if int(publication_payload.get("n_apps") or 0) != 12:
        warnings.append(f"PUBLICATION_RESULTS_N_APPS_UNEXPECTED:{publication_payload.get('n_apps')}")
    if int(publication_payload.get("n_runs_total") or 0) != 36:
        warnings.append(f"PUBLICATION_RESULTS_N_RUNS_TOTAL_UNEXPECTED:{publication_payload.get('n_runs_total')}")

    notes = {
        "interaction_breakdown_runs": interaction_breakdown,
        "threshold_mismatch_apps": threshold_mismatch,
        "baseline_provenance_mismatches": provenance_mismatch,
        "seed_mismatches": seed_mismatch,
        "windows_missing": windows_missing,
        "windows_zero": windows_zero,
    }
    if int(interaction_breakdown.get("manual") or 0) > 0:
        warnings.append(
            "COHORT_INTERACTIONS_INCLUDE_MANUAL:paper_language_must_say_interactive_or_clarify_scripted_vs_manual"
        )

    ok = len(errors) == 0
    payload = (
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
        + "\n"
    )
    targets = [out]
    if _write_legacy_aliases():
        targets.append(pub_root / "qa" / "paper2_pipeline_audit_v1.json")
    for path in targets:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    return out, ok


def main() -> int:
    out, ok = generate_pipeline_audit()
    print(str(out))
    return 0 if ok else 2
