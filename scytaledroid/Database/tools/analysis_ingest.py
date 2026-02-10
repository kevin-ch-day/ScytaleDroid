"""Phase H: ingest publication/operational artifacts into DB (tables-only; no JSON discovery).

Goal:
- Stop hunting scattered JSON/CSVs for derived facts.
- Make DB queryable for: cohort membership, run roles, and paper-backed aggregates.

Non-goals:
- No recomputation of ML or deltas here (Phase H1). We import already-derived CSVs
  produced by Phase E / operational snapshot tooling.
- Evidence packs remain immutable ground truth. This tool stores indices + aggregates
  with provenance receipts.

Usage (example):
  python -m scytaledroid.Database.tools.analysis_ingest \\
    --bundle-root output/publication \\
    --cohort-id paper2_submission_20260209 \\
    --name "Paper2 submission" \\
    --selector-type freeze
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.session import database_session, get_current_engine
from scytaledroid.Database.db_func.apps.app_labels import upsert_display_aliases, upsert_display_names
from scytaledroid.Database.db_func.apps.app_ordering import upsert_ordering
from scytaledroid.Publication.contract_inputs import load_publication_contracts
from scytaledroid.Utils.LoggingUtils import logging_utils as log

ROOT = Path(__file__).resolve().parents[3]


def _utc_now() -> str:
    # MariaDB DATETIME expects "YYYY-MM-DD HH:MM:SS" (no timezone marker).
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(p: Path) -> dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _read_csv_rows(p: Path) -> list[dict[str, str]]:
    txt = p.read_text(encoding="utf-8", errors="strict")
    lines: list[str] = []
    for ln in txt.splitlines():
        if not lines and (not ln.strip() or ln.startswith("#")):
            continue
        if ln.strip():
            lines.append(ln)
    if not lines:
        return []
    r = csv.DictReader(lines)
    return [dict(row) for row in r]


def _git_sha() -> str | None:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT), text=True).strip()
        return out or None
    except Exception:
        return None


def _toolchain_fingerprint(toolchain_txt: Path | None) -> str | None:
    if not toolchain_txt or not toolchain_txt.exists():
        return None
    return hashlib.sha256(toolchain_txt.read_bytes()).hexdigest()


@dataclass(frozen=True)
class BundlePaths:
    bundle_root: Path
    manifests_dir: Path
    internal_baseline_root: Path
    internal_snapshot_root: Path | None
    snapshot_id: str | None

    @property
    def baseline_tables_dir(self) -> Path:
        return self.internal_baseline_root / "tables"

    @property
    def baseline_inputs_dir(self) -> Path:
        return self.internal_baseline_root / "inputs"

    @property
    def snapshot_tables_dir(self) -> Path | None:
        if not self.internal_snapshot_root:
            return None
        return self.internal_snapshot_root / "tables"


def resolve_bundle_paths(*, bundle_root: Path) -> BundlePaths:
    bundle_root = bundle_root.resolve()
    manifests = bundle_root / "manifests"
    internal_baseline = bundle_root / "internal" / "baseline"
    if not manifests.exists():
        raise RuntimeError(f"bundle_root missing manifests/: {manifests}")
    if not internal_baseline.exists():
        raise RuntimeError(f"bundle_root missing internal/baseline/: {internal_baseline}")

    snapshot_id = None
    snap_dir = None
    for name in ("publication_snapshot_id.txt", "paper_snapshot_id.txt"):
        sid_path = manifests / name
        if not sid_path.exists():
            continue
        snapshot_id = sid_path.read_text(encoding="utf-8").strip() or None
        if snapshot_id:
            cand = bundle_root / "internal" / "snapshots" / snapshot_id
            if cand.exists():
                snap_dir = cand
        break
    return BundlePaths(
        bundle_root=bundle_root,
        manifests_dir=manifests,
        internal_baseline_root=internal_baseline,
        internal_snapshot_root=snap_dir,
        snapshot_id=snapshot_id,
    )


def _upsert_cohort(
    *,
    cohort_id: str,
    name: str,
    selector_type: str,
    freeze_sha256: str | None,
    selection_manifest_sha256: str | None,
    toolchain_fingerprint: str | None,
    pipeline_git_sha: str | None,
) -> None:
    sql = """
    INSERT INTO analysis_cohorts
      (cohort_id, name, selector_type, freeze_sha256, selection_manifest_sha256, toolchain_fingerprint, pipeline_git_sha, created_at_utc)
    VALUES
      (%s,%s,%s,%s,%s,%s,%s,%s)
    ON DUPLICATE KEY UPDATE
      name=VALUES(name),
      selector_type=VALUES(selector_type),
      freeze_sha256=VALUES(freeze_sha256),
      selection_manifest_sha256=VALUES(selection_manifest_sha256),
      toolchain_fingerprint=VALUES(toolchain_fingerprint),
      pipeline_git_sha=VALUES(pipeline_git_sha);
    """
    core_q.run_sql_write(
        sql,
        (
            cohort_id,
            name,
            selector_type,
            freeze_sha256,
            selection_manifest_sha256,
            toolchain_fingerprint,
            pipeline_git_sha,
            _utc_now(),
        ),
        query_name="analysis_ingest.upsert_cohort",
    )


def _insert_receipt(
    *,
    cohort_id: str,
    freeze_sha256: str | None,
    selection_manifest_sha256: str | None,
    toolchain_fingerprint: str | None,
    pipeline_git_sha: str | None,
    params_json: dict[str, Any],
) -> int:
    sql = """
    INSERT INTO analysis_derivation_receipts
      (cohort_id, freeze_sha256, selection_manifest_sha256, toolchain_fingerprint, pipeline_git_sha, params_json, status, created_at_utc)
    VALUES
      (%s,%s,%s,%s,%s,%s,%s,%s)
    """
    rid = core_q.run_sql(
        sql,
        (
            cohort_id,
            freeze_sha256,
            selection_manifest_sha256,
            toolchain_fingerprint,
            pipeline_git_sha,
            json.dumps(params_json, sort_keys=True),
            "RUNNING",
            _utc_now(),
        ),
        fetch="none",
        return_lastrowid=True,
        query_name="analysis_ingest.insert_receipt",
    )
    if rid is None:
        raise RuntimeError("Failed to obtain receipt_id")
    return int(rid)


def _finalize_receipt_ok(receipt_id: int) -> None:
    core_q.run_sql_write(
        "UPDATE analysis_derivation_receipts SET status='OK', finished_at_utc=%s, error_text=NULL WHERE receipt_id=%s",
        (_utc_now(), int(receipt_id)),
        query_name="analysis_ingest.receipt.ok",
    )


def _finalize_receipt_fail(receipt_id: int, *, error_text: str) -> None:
    core_q.run_sql_write(
        "UPDATE analysis_derivation_receipts SET status='FAIL', finished_at_utc=%s, error_text=%s WHERE receipt_id=%s",
        (_utc_now(), str(error_text)[:8000], int(receipt_id)),
        query_name="analysis_ingest.receipt.fail",
    )


def _mark_stale_running_receipts(*, cohort_id: str) -> None:
    """Fail-closed ingest should not leave durable RUNNING receipts forever.

    If prior ingests crashed before finalising, mark old RUNNING receipts as FAIL.
    """
    # Keep this small and configurable; long-lived RUNNING receipts are almost always
    # a crash/kill signal and make audits noisy.
    stale_minutes = 15
    try:
        raw = str(os.environ.get("SCYTALEDROID_ANALYSIS_RECEIPT_STALE_MINUTES", "")).strip()
        if raw:
            stale_minutes = int(raw)
    except Exception:
        stale_minutes = 15
    if stale_minutes < 1:
        stale_minutes = 1
    if stale_minutes > 24 * 60:
        stale_minutes = 24 * 60

    cutoff_dt = datetime.now(UTC) - timedelta(minutes=stale_minutes)
    cutoff_s = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
    try:
        core_q.run_sql_write(
            """
            UPDATE analysis_derivation_receipts
            SET status='FAIL',
                finished_at_utc=COALESCE(finished_at_utc, NOW()),
                error_text=COALESCE(error_text, 'stale RUNNING receipt (auto-marked FAIL)')
            WHERE cohort_id=%s
              AND status='RUNNING'
              AND finished_at_utc IS NULL
              AND created_at_utc < %s
            """,
            (cohort_id, cutoff_s),
            query_name="analysis_ingest.receipt.mark_stale",
        )
    except Exception:
        return


def _query_dynamic_session(run_id: str) -> dict[str, Any] | None:
    row = core_q.run_sql(
        """
        SELECT dynamic_run_id, package_name, base_apk_sha256, evidence_path, pcap_sha256
        FROM dynamic_sessions
        WHERE dynamic_run_id = %s
        """,
        (run_id,),
        fetch="one_dict",
        query_name="analysis_ingest.dynamic_sessions.by_id",
    )
    return dict(row) if row else None


def ingest_cohort_runs_from_manifests(
    *,
    cohort_id: str,
    paths: BundlePaths,
) -> int:
    """Populate analysis_cohort_runs from the paper bundle manifests (idempotent)."""
    now = _utc_now()
    dataset_freeze = paths.manifests_dir / "dataset_freeze.json"
    selection_manifest = paths.manifests_dir / "selection_manifest.json"

    included: dict[str, dict[str, Any]] = {}
    run_role_by_id: dict[str, str] = {}

    if selection_manifest.exists():
        obj = _read_json(selection_manifest)
        runs = obj.get("inclusion", {}).get("runs", {})
        if isinstance(runs, dict):
            for run_id, meta in runs.items():
                if not run_id:
                    continue
                included[str(run_id)] = dict(meta or {})
                mode = str((meta or {}).get("mode") or "").strip().lower()
                if mode in {"baseline", "interactive", "unknown"}:
                    run_role_by_id[str(run_id)] = mode

    if not included and dataset_freeze.exists():
        obj = _read_json(dataset_freeze)
        apps = obj.get("apps", {}) if isinstance(obj.get("apps"), dict) else {}
        for _, app in apps.items():
            if not isinstance(app, dict):
                continue
            for rid in app.get("baseline_run_ids", []) or []:
                rid = str(rid).strip()
                if rid:
                    included[rid] = {}
                    run_role_by_id[rid] = "baseline"
            for rid in app.get("interactive_run_ids", []) or []:
                rid = str(rid).strip()
                if rid:
                    included[rid] = {}
                    run_role_by_id[rid] = "interactive"

    rows: list[tuple[Any, ...]] = []
    for run_id, meta in included.items():
        dyn = _query_dynamic_session(run_id)
        if not dyn:
            continue
        pkg = str(dyn.get("package_name") or "").strip()
        base_sha = str(dyn.get("base_apk_sha256") or "").strip() or None
        role = run_role_by_id.get(run_id, str(meta.get("mode") or "").strip().lower() or "unknown")
        if role not in {"baseline", "interactive", "unknown"}:
            role = "unknown"
        rows.append(
            (
                cohort_id,
                run_id,
                pkg,
                base_sha,
                role,
                1,
                None,
                None,
                str(dyn.get("pcap_sha256") or "").strip() or None,
                now,
            )
        )

    if not rows:
        return 0

    sql = """
    INSERT INTO analysis_cohort_runs
      (cohort_id, dynamic_run_id, package_name, base_apk_sha256, run_role, included, exclude_reason, evidence_pack_sha256, pcap_sha256, created_at_utc)
    VALUES
      (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON DUPLICATE KEY UPDATE
      package_name=VALUES(package_name),
      base_apk_sha256=VALUES(base_apk_sha256),
      run_role=VALUES(run_role),
      included=VALUES(included),
      exclude_reason=VALUES(exclude_reason),
      evidence_pack_sha256=VALUES(evidence_pack_sha256),
      pcap_sha256=VALUES(pcap_sha256);
    """
    core_q.run_sql_many(sql, rows, query_name="analysis_ingest.upsert_cohort_runs")
    return len(rows)


def ingest_aggregates_from_csvs(
    *,
    cohort_id: str,
    receipt_id: int,
    paths: BundlePaths,
) -> dict[str, int]:
    """Import already-derived aggregate facts from canonical CSVs (no recomputation)."""
    now = _utc_now()
    contracts = load_publication_contracts(fail_closed=True)

    # 1) ML app/phase/model metrics: prefer internal baseline input copy, fallback to repo data/.
    ml_src = paths.baseline_inputs_dir / "anomaly_prevalence_per_app_phase.csv"
    if not ml_src.exists():
        cand = ROOT / "data" / "anomaly_prevalence_per_app_phase.csv"
        ml_src = cand if cand.exists() else ml_src
    ml_rows = _read_csv_rows(ml_src) if ml_src.exists() else []
    ml_param_rows: list[tuple[Any, ...]] = []
    for r in ml_rows:
        pkg = (r.get("package_name") or "").strip()
        phase = (r.get("phase") or "").strip()
        model = (r.get("model") or "").strip()
        if not (pkg and phase and model):
            continue
        ml_param_rows.append(
            (
                receipt_id,
                cohort_id,
                pkg,
                phase,
                model,
                int(float(r.get("windows_total") or 0)),
                int(float(r.get("windows_flagged") or 0)),
                float(r.get("flagged_pct") or 0.0),
                None,
                (r.get("training_mode") or "").strip() or None,
                None,
                None,
                (r.get("ml_schema_version") or "").strip() or None,
                None,
                now,
            )
        )
    if ml_param_rows:
        sql = """
        INSERT INTO analysis_ml_app_phase_model_metrics
          (receipt_id, cohort_id, package_name, phase, model_key,
           windows_total, windows_flagged, flagged_pct, threshold_value, training_mode,
           train_samples, np_percentile_method, ml_schema_version, pipeline_git_sha, created_at_utc)
        VALUES
          (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          receipt_id=VALUES(receipt_id),
          windows_total=VALUES(windows_total),
          windows_flagged=VALUES(windows_flagged),
          flagged_pct=VALUES(flagged_pct),
          threshold_value=VALUES(threshold_value),
          training_mode=VALUES(training_mode),
          train_samples=VALUES(train_samples),
          np_percentile_method=VALUES(np_percentile_method),
          ml_schema_version=VALUES(ml_schema_version),
          pipeline_git_sha=VALUES(pipeline_git_sha);
        """
        core_q.run_sql_many(sql, ml_param_rows, query_name="analysis_ingest.ml_metrics")

    # 2) Signature deltas from paper-facing Table 4 (app label -> package via contracts).
    inv: dict[str, str] = {}
    for pkg, name in contracts.display_name_by_package.items():
        if name in inv:
            raise RuntimeError(f"Duplicate display name in alias map: {name}")
        inv[name] = pkg
    t4 = paths.bundle_root / "tables" / "table_4_signature_deltas.csv"
    t4_rows = _read_csv_rows(t4) if t4.exists() else []
    sig_param_rows: list[tuple[Any, ...]] = []
    for r in t4_rows:
        app = (r.get("app") or "").strip()
        pkg = inv.get(app)
        if not pkg:
            continue
        sig_param_rows.append(
            (
                receipt_id,
                cohort_id,
                pkg,
                float(r.get("bytes_p50_delta") or 0.0),
                float(r.get("bytes_p95_delta") or 0.0),
                float(r.get("pps_p50_delta") or 0.0),
                float(r.get("pps_p95_delta") or 0.0),
                float(r.get("pkt_size_p50_delta") or 0.0),
                float(r.get("pkt_size_p95_delta") or 0.0),
                None,
                None,
                now,
            )
        )
    if sig_param_rows:
        sql = """
        INSERT INTO analysis_signature_deltas
          (receipt_id, cohort_id, package_name,
           bytes_p50_delta, bytes_p95_delta, pps_p50_delta, pps_p95_delta, pkt_size_p50_delta, pkt_size_p95_delta,
           idle_windows, interactive_windows, created_at_utc)
        VALUES
          (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          receipt_id=VALUES(receipt_id),
          bytes_p50_delta=VALUES(bytes_p50_delta),
          bytes_p95_delta=VALUES(bytes_p95_delta),
          pps_p50_delta=VALUES(pps_p50_delta),
          pps_p95_delta=VALUES(pps_p95_delta),
          pkt_size_p50_delta=VALUES(pkt_size_p50_delta),
          pkt_size_p95_delta=VALUES(pkt_size_p95_delta);
        """
        core_q.run_sql_many(sql, sig_param_rows, query_name="analysis_ingest.signature_deltas")

    # 3) Static exposure from Table 6 (internal baseline).
    t6 = paths.baseline_tables_dir / "table_6_static_posture_scores.csv"
    t6_rows = _read_csv_rows(t6) if t6.exists() else []
    exp_param_rows: list[tuple[Any, ...]] = []
    for r in t6_rows:
        pkg = (r.get("package_name") or "").strip()
        if not pkg:
            continue
        exp_param_rows.append(
            (
                receipt_id,
                cohort_id,
                pkg,
                int(float(r.get("exported_raw") or 0)),
                int(float(r.get("dangerous_raw") or 0)),
                int(float(r.get("cleartext_flag") or 0)),
                float(r.get("sdk_score") or 0.0),
                float(r.get("exported_norm") or 0.0),
                float(r.get("dangerous_norm") or 0.0),
                float(r.get("static_posture_score") or 0.0),
                None,
                json.dumps({"notes": (r.get("notes") or "").strip()}),
                now,
            )
        )
    if exp_param_rows:
        sql = """
        INSERT INTO analysis_static_exposure
          (receipt_id, cohort_id, package_name,
           exported_components_raw, dangerous_permissions_raw, uses_cleartext_traffic, sdk_indicators_score,
           exported_components_norm, dangerous_permissions_norm, static_posture_score, exposure_grade, notes_json, created_at_utc)
        VALUES
          (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          receipt_id=VALUES(receipt_id),
          exported_components_raw=VALUES(exported_components_raw),
          dangerous_permissions_raw=VALUES(dangerous_permissions_raw),
          uses_cleartext_traffic=VALUES(uses_cleartext_traffic),
          sdk_indicators_score=VALUES(sdk_indicators_score),
          exported_components_norm=VALUES(exported_components_norm),
          dangerous_permissions_norm=VALUES(dangerous_permissions_norm),
          static_posture_score=VALUES(static_posture_score),
          notes_json=VALUES(notes_json);
        """
        core_q.run_sql_many(sql, exp_param_rows, query_name="analysis_ingest.static_exposure")

    # 4) Risk regime summary from surfaced snapshot (optional).
    regime_rows: list[dict[str, str]] = []
    if paths.snapshot_tables_dir and (paths.snapshot_tables_dir / "risk_summary_per_group.csv").exists():
        regime_rows = _read_csv_rows(paths.snapshot_tables_dir / "risk_summary_per_group.csv")
    regime_param_rows: list[tuple[Any, ...]] = []
    for r in regime_rows:
        pkg = (r.get("package_name") or "").strip()
        if not pkg:
            continue
        regime_param_rows.append(
            (
                receipt_id,
                cohort_id,
                pkg,
                float(r.get("static_exposure_score") or 0.0),
                (r.get("exposure_grade") or "").strip() or None,
                float(r.get("dynamic_deviation_score_if") or 0.0),
                (r.get("deviation_grade_if") or "").strip() or None,
                (r.get("final_regime_if") or "").strip() or None,
                json.dumps(
                    {
                        "final_grade_if": (r.get("final_grade_if") or "").strip(),
                        "confidence_level": (r.get("confidence_level") or "").strip(),
                        "confidence_notes": (r.get("confidence_notes") or "").strip(),
                        "static_drivers": (r.get("static_drivers") or "").strip(),
                        "dynamic_driver_if": (r.get("dynamic_driver_if") or "").strip(),
                        "ml_schema_version": (r.get("ml_schema_version") or "").strip(),
                    },
                    sort_keys=True,
                ),
                now,
            )
        )
    if regime_param_rows:
        sql = """
        INSERT INTO analysis_risk_regime_summary
          (receipt_id, cohort_id, package_name,
           static_score, static_grade, dynamic_score_if, dynamic_grade_if, final_regime_if, notes_json, created_at_utc)
        VALUES
          (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          receipt_id=VALUES(receipt_id),
          static_score=VALUES(static_score),
          static_grade=VALUES(static_grade),
          dynamic_score_if=VALUES(dynamic_score_if),
          dynamic_grade_if=VALUES(dynamic_grade_if),
          final_regime_if=VALUES(final_regime_if),
          notes_json=VALUES(notes_json);
        """
        core_q.run_sql_many(sql, regime_param_rows, query_name="analysis_ingest.regime_summary")

    return {
        "ml_app_phase_model_metrics": len(ml_param_rows),
        "signature_deltas": len(sig_param_rows),
        "static_exposure": len(exp_param_rows),
        "risk_regime_summary": len(regime_param_rows),
    }


def ingest_publication_bundle_to_db(
    *,
    bundle_root: Path,
    cohort_id: str,
    name: str,
    selector_type: str,
) -> None:
    paths = resolve_bundle_paths(bundle_root=bundle_root)

    freeze_path = paths.manifests_dir / "dataset_freeze.json"
    sel_path = paths.manifests_dir / "selection_manifest.json"
    toolchain = paths.manifests_dir / "toolchain.txt"
    freeze_sha = _sha256_file(freeze_path) if freeze_path.exists() else None
    sel_sha = _sha256_file(sel_path) if sel_path.exists() else None
    toolchain_fp = _toolchain_fingerprint(toolchain if toolchain.exists() else None)
    git_sha = _git_sha()

    _upsert_cohort(
        cohort_id=cohort_id,
        name=name,
        selector_type=selector_type,
        freeze_sha256=freeze_sha,
        selection_manifest_sha256=sel_sha,
        toolchain_fingerprint=toolchain_fp,
        pipeline_git_sha=git_sha,
    )

    _mark_stale_running_receipts(cohort_id=cohort_id)

    receipt_id = _insert_receipt(
        cohort_id=cohort_id,
        freeze_sha256=freeze_sha,
        selection_manifest_sha256=sel_sha,
        toolchain_fingerprint=toolchain_fp,
        pipeline_git_sha=git_sha,
        params_json={
            "bundle_root": str(paths.bundle_root),
            "snapshot_id": paths.snapshot_id,
            "sources": {
                "dataset_freeze": str(freeze_path) if freeze_path.exists() else None,
                "selection_manifest": str(sel_path) if sel_path.exists() else None,
                "ml_metrics_csv": str(paths.baseline_inputs_dir / "anomaly_prevalence_per_app_phase.csv"),
                "table_4_signature_deltas": str(paths.bundle_root / "tables" / "table_4_signature_deltas.csv"),
                "table_6_static_posture_scores": str(paths.baseline_tables_dir / "table_6_static_posture_scores.csv"),
                "risk_summary_per_group": str((paths.snapshot_tables_dir / "risk_summary_per_group.csv") if paths.snapshot_tables_dir else None),
            },
        },
    )

    try:
        # Make derived facts atomic: either all cohort facts are updated, or none are.
        # This function may be called from menu code; ensure a session-bound engine exists.
        with database_session():
            engine = get_current_engine()
            if engine is None:  # pragma: no cover - defensive
                raise RuntimeError("No active DB engine (expected database_session)")
            with engine.transaction():
                runs_ingested = ingest_cohort_runs_from_manifests(cohort_id=cohort_id, paths=paths)
                counts = ingest_aggregates_from_csvs(cohort_id=cohort_id, receipt_id=receipt_id, paths=paths)
                _finalize_receipt_ok(receipt_id)
    except Exception as exc:
        # Keep receipts durable even when the derived-facts transaction rolls back.
        try:
            _finalize_receipt_fail(receipt_id, error_text=str(exc))
        except Exception:
            pass
        raise

    # Ensure labels and ordering are populated (avoid scattered JSON maps).
    # Canonical DB display_name should remain the full product name; publication shortening
    # is stored under app_display_aliases (alias_key='paper2').
    try:
        contracts = load_publication_contracts(fail_closed=True)
        upsert_display_names(contracts.display_name_by_package, overwrite=False)
        upsert_display_aliases("paper2", contracts.display_name_by_package, overwrite=True)
        upsert_ordering("paper2", contracts.package_order)
    except Exception:
        pass

    # Simple sanity queries (DB-first posture).
    try:
        n_runs = core_q.run_sql(
            "SELECT COUNT(*) FROM analysis_cohort_runs WHERE cohort_id=%s",
            (cohort_id,),
            fetch="one",
        )
        log.info(f"analysis_cohort_runs rowcount={n_runs[0] if n_runs else 'n/a'} for cohort={cohort_id}", category="database")
    except Exception:
        pass

    print(f"[OK] Cohort upserted: {cohort_id}")
    print(f"[OK] Receipt id: {receipt_id}")
    print(f"[OK] Cohort runs ingested: {runs_ingested}")
    for k, v in counts.items():
        print(f"[OK] {k}: {v}")


def ingest_paper_bundle_to_db(
    *,
    paper_root: Path,
    cohort_id: str,
    name: str,
    selector_type: str,
) -> None:
    """Back-compat wrapper (deprecated): use ingest_publication_bundle_to_db()."""
    ingest_publication_bundle_to_db(
        bundle_root=paper_root,
        cohort_id=cohort_id,
        name=name,
        selector_type=selector_type,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Ingest publication bundle artifacts into DB (Phase H1).")
    ap.add_argument("--bundle-root", default="output/publication", help="Path to canonical output/publication directory.")
    ap.add_argument("--paper-root", default=None, help="Deprecated alias for --bundle-root.")
    ap.add_argument("--cohort-id", required=True, help="Deterministic cohort_id to register in DB.")
    ap.add_argument("--name", required=True, help="Human-friendly cohort name.")
    ap.add_argument("--selector-type", default="freeze", choices=["freeze", "query", "manual"], help="Selector type.")
    args = ap.parse_args(argv)

    with database_session(reuse_connection=False):
        bundle_root = args.bundle_root
        if args.paper_root:
            bundle_root = args.paper_root
        ingest_publication_bundle_to_db(
            bundle_root=Path(bundle_root),
            cohort_id=args.cohort_id.strip(),
            name=args.name.strip(),
            selector_type=args.selector_type.strip(),
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
