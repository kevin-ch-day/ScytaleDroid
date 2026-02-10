#!/usr/bin/env python3
"""Query-mode smoke gate for Phase F1 (variable-N + unknown mode).

This is intentionally a *local* smoke test:
- Creates a temporary evidence root by copying a small number of existing evidence packs.
- Mutates only the copies to synthesize:
  - 1 baseline run with < MIN_WINDOWS_BASELINE (forces union fallback)
  - >2 interactive runs (cloned)
  - >=1 unknown-mode run (cloned; huge duration) that must NOT enter training
- Runs QuerySelector (DB-free scan) + query-mode ML snapshot writer.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_run_dir(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def _mutate_manifest_for_clone(run_dir: Path, *, new_run_id: str, run_profile: str, sampling_duration_s: float | None) -> None:
    mf = run_dir / "run_manifest.json"
    payload = _read_json(mf)
    payload["dynamic_run_id"] = new_run_id
    # Keep both legacy mirror fields aligned (some tooling still reads operator.run_profile).
    op = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
    op["run_profile"] = run_profile
    rc = op.get("run_context") if isinstance(op.get("run_context"), dict) else {}
    rc["run_profile"] = run_profile
    op["run_context"] = rc
    payload["operator"] = op
    if sampling_duration_s is not None:
        ds = payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {}
        ds["sampling_duration_seconds"] = float(sampling_duration_s)
        payload["dataset"] = ds
        # Keep legacy mirror in operator.dataset_validity if present.
        if isinstance(op.get("dataset_validity"), dict):
            op["dataset_validity"]["sampling_duration_seconds"] = float(sampling_duration_s)
            payload["operator"] = op

        # Phase E/ML windowing uses analysis/summary.json telemetry stats.
        # Update it so smoke runs can deterministically force union fallback / large unknown spans.
        summary_path = run_dir / "analysis" / "summary.json"
        if summary_path.exists():
            try:
                summary = _read_json(summary_path)
            except Exception:
                summary = {}
            if isinstance(summary, dict):
                tel = summary.get("telemetry") if isinstance(summary.get("telemetry"), dict) else {}
                stats = tel.get("stats") if isinstance(tel.get("stats"), dict) else {}
                stats["sampling_duration_seconds"] = float(sampling_duration_s)
                tel["stats"] = stats
                summary["telemetry"] = tel
                _write_json(summary_path, summary)
    _write_json(mf, payload)


@dataclass(frozen=True)
class PickedRuns:
    package_name: str
    baseline_dir: Path
    interactive_dir: Path


def _pick_one_app_runs(evidence_root: Path) -> PickedRuns:
    # Find one package with at least 1 baseline + 1 interactive.
    baseline: dict[str, Path] = {}
    interactive: dict[str, Path] = {}
    for mf in sorted(evidence_root.glob("*/run_manifest.json")):
        try:
            payload = json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            continue
        target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
        pkg = str(target.get("package_name") or "").strip()
        if not pkg:
            continue
        op = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
        prof = str(op.get("run_profile") or "").strip().lower()
        if prof.startswith(("baseline", "idle", "minimal")):
            baseline.setdefault(pkg, mf.parent)
        elif prof.startswith(("interactive", "normal", "heavy")):
            interactive.setdefault(pkg, mf.parent)
    for pkg in sorted(set(baseline.keys()).intersection(interactive.keys())):
        return PickedRuns(package_name=pkg, baseline_dir=baseline[pkg], interactive_dir=interactive[pkg])
    raise RuntimeError("No app found with both baseline and interactive runs under evidence root.")


def _recompute_manifest_sha(payload: dict[str, Any]) -> str:
    # Mirror SelectionManifest hashing: payload without selection_manifest_sha256.
    from hashlib import sha256

    p = dict(payload)
    p.pop("selection_manifest_sha256", None)
    blob = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sha256(blob).hexdigest()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-temp-evidence", action="store_true", help="Do not delete the temporary evidence root.")
    args = ap.parse_args(argv)

    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.ml.query_mode_runner import run_ml_query_mode
    from scytaledroid.DynamicAnalysis.ml.selectors import QueryParams
    from scytaledroid.DynamicAnalysis.ml.selectors.query_selector import QuerySelector

    src_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not src_root.exists():
        print("[query_mode_smoke_gate] FAIL: no evidence root at output/evidence/dynamic")
        return 2

    picked = _pick_one_app_runs(src_root)
    temp_root = Path(app_config.OUTPUT_DIR) / "tmp" / f"query_smoke_evidence_{uuid.uuid4().hex[:8]}"
    temp_root.mkdir(parents=True, exist_ok=True)

    try:
        # Copy baseline + one interactive, then synthesize extra interactives and one unknown.
        base_id = f"smoke-{uuid.uuid4().hex}"
        rid_baseline = base_id + "-baseline"
        rid_int0 = base_id + "-int0"
        rid_int1 = base_id + "-int1"
        rid_int2 = base_id + "-int2"
        rid_unknown = base_id + "-unknown"

        dst_baseline = temp_root / rid_baseline
        dst_int0 = temp_root / rid_int0
        dst_int1 = temp_root / rid_int1
        dst_int2 = temp_root / rid_int2
        dst_unknown = temp_root / rid_unknown

        _copy_run_dir(picked.baseline_dir, dst_baseline)
        _copy_run_dir(picked.interactive_dir, dst_int0)
        _copy_run_dir(picked.interactive_dir, dst_int1)
        _copy_run_dir(picked.interactive_dir, dst_int2)
        _copy_run_dir(picked.interactive_dir, dst_unknown)

        # Force union fallback by making baseline too short for MIN_WINDOWS_BASELINE (30).
        _mutate_manifest_for_clone(dst_baseline, new_run_id=rid_baseline, run_profile="baseline_smoke", sampling_duration_s=100.0)
        _mutate_manifest_for_clone(dst_int0, new_run_id=rid_int0, run_profile="interactive_smoke", sampling_duration_s=None)
        _mutate_manifest_for_clone(dst_int1, new_run_id=rid_int1, run_profile="interactive_smoke", sampling_duration_s=None)
        _mutate_manifest_for_clone(dst_int2, new_run_id=rid_int2, run_profile="interactive_smoke", sampling_duration_s=None)

        # Unknown mode: run_profile doesn't match baseline/interactive prefixes.
        # Make it long so if it were incorrectly included in training, training_samples would jump.
        _mutate_manifest_for_clone(dst_unknown, new_run_id=rid_unknown, run_profile="", sampling_duration_s=800.0)

        params = QueryParams(
            tier="dataset",
            package_name=None,
            base_apk_sha256=None,
            mode=None,
            include_unknown_mode=True,
            pool_versions=False,
            require_valid_dataset_run=True,
        )
        selector = QuerySelector(evidence_root=temp_root, params=params, allow_db_index=False)
        sel1 = selector.select()
        sel2 = selector.select()
        if [r.run_id for r in sel1.included] != [r.run_id for r in sel2.included]:
            print("[query_mode_smoke_gate] FAIL: selector ordering not deterministic across calls")
            return 2

        stats = run_ml_query_mode(selection=sel1, reuse_existing_outputs=False)
        snap = Path(stats.snapshot_dir)
        manifest_path = snap / "selection_manifest.json"
        if not manifest_path.exists():
            print("[query_mode_smoke_gate] FAIL: missing selection_manifest.json")
            return 2

        manifest = _read_json(manifest_path)
        recorded = str(manifest.get("selection_manifest_sha256") or "")
        recomputed = _recompute_manifest_sha(manifest)
        if not recorded or recorded != recomputed:
            print("[query_mode_smoke_gate] FAIL: selection_manifest_sha256 mismatch")
            return 2

        # Assert outputs exist.
        per_run_csv = snap / "tables" / "anomaly_prevalence_per_run.csv"
        if not per_run_csv.exists():
            print("[query_mode_smoke_gate] FAIL: missing tables/anomaly_prevalence_per_run.csv")
            return 2

        # Assert we have variable-N and unknown.
        included_ids = [r.run_id for r in sel1.included]
        if rid_unknown not in included_ids:
            print("[query_mode_smoke_gate] FAIL: unknown run not included")
            return 2

        # Read per-run summaries to compute expected training_samples (baseline+interactive only).
        def _summary(rid: str) -> dict[str, Any]:
            p = snap / "runs" / rid / "ml" / "v1" / "ml_summary.json"
            if not p.exists():
                raise RuntimeError(f"missing ml_summary.json for {rid}")
            return _read_json(p)

        summaries = {rid: _summary(rid) for rid in included_ids}
        modes = {rid: str(s.get("mode") or "unknown") for rid, s in summaries.items()}
        if modes.get(rid_unknown) != "unknown":
            print(f"[query_mode_smoke_gate] FAIL: expected unknown mode, got {modes.get(rid_unknown)!r}")
            return 2

        windows_total = {rid: int(s.get("windows_total") or 0) for rid, s in summaries.items()}
        expected_train = sum(windows_total[rid] for rid, m in modes.items() if m in ("baseline", "interactive"))
        unknown_windows = windows_total.get(rid_unknown, 0)
        if unknown_windows <= 0:
            print("[query_mode_smoke_gate] FAIL: unknown run has 0 windows; cannot validate exclusion")
            return 2

        # Check model_manifest training_samples matches expected baseline+interactive (unknown excluded).
        any_manifest = snap / "runs" / included_ids[0] / "ml" / "v1" / "model_manifest.json"
        mm = _read_json(any_manifest)
        models = mm.get("models") if isinstance(mm.get("models"), dict) else {}
        for name, meta in models.items():
            if not isinstance(meta, dict):
                continue
            ts = int(meta.get("training_samples") or 0)
            if ts != expected_train:
                print(
                    "[query_mode_smoke_gate] FAIL: training_samples mismatch "
                    f"model={name} got={ts} expected={expected_train} (unknown_windows={unknown_windows})"
                )
                return 2

        print("[query_mode_smoke_gate] PASS")
        print(f"- snapshot: {snap}")
        print(f"- group: {picked.package_name} runs={len(included_ids)} expected_train_samples={expected_train} unknown_windows={unknown_windows}")
        return 0
    finally:
        if not args.keep_temp_evidence and temp_root.exists():
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
