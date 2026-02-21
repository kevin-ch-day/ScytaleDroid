"""Query-mode ML execution (Phase F2).

Goals:
- Keep Phase E (paper) semantics intact and reproducible.
- In operational snapshots, add stability + persistence metrics and (optional) feature stabilisation.
- Selection is explicit and provenance is written to output/operational/<snapshot_id>/selection_manifest.json.
- Per-run outputs are written under the operational snapshot:
  output/operational/<snapshot_id>/runs/<run_id>/...
"""

from __future__ import annotations

import csv
import json
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from scytaledroid.Config import app_config

from . import ml_parameters_operational as config
from . import ml_parameters_paper2 as paper_config
from .anomaly_model_training import anomaly_scores, fit_model, fixed_model_specs
from .evidence_pack_ml_preflight import (
    RunInputs,
    compute_ml_preflight,
    derive_run_mode,
    get_sampling_duration_seconds,
    load_run_inputs,
    write_ml_preflight,
)
from .numpy_percentile import percentile as np_percentile
from .operational_lint import lint_operational_snapshot
from .operational_metrics import (
    anomaly_streaks,
    infer_intensity_from_windows,
    persistence_seconds,
    threshold_stability,
)
from .operational_risk import (
    build_static_inputs_from_plan,
    deviation_grade,
    dynamic_deviation_score_0_100,
    exposure_grade,
    final_posture_grade,
    final_posture_regime,
    minmax_norm,
    static_exposure_score_components,
)
from .pcap_window_features import (
    build_window_features,
    extract_packet_timeline,
    write_anomaly_scores_csv,
)
from .seed_identity import derive_seed
from .selectors.models import SelectionResult, write_selection_manifest
from .snapshot_freeze import write_snapshot_freeze_manifest
from .telemetry_windowing import WindowSpec


@dataclass(frozen=True)
class QueryMlRunStats:
    groups_seen: int
    groups_trained: int
    runs_scored: int
    runs_skipped: int
    snapshot_id: str
    snapshot_dir: Path
    generated_at_utc: str


def _snapshot_id(*, selector_type: str) -> str:
    return f"{selector_type}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"


def _mode_rank(mode: str) -> int:
    return 0 if mode == "baseline" else (1 if mode == "interactive" else 2)


def _rows_to_matrix(rows: list[dict[str, Any]], *, window_spec: WindowSpec) -> tuple[np.ndarray, list[str]]:
    denom = float(window_spec.window_size_s) if window_spec.window_size_s > 0 else 1.0
    feature_names = ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"]
    data: list[list[float]] = []
    def _f(value: Any) -> float:
        try:
            return float(value or 0.0)
        except Exception:
            return 0.0
    for row in rows:
        byte_count = _f(row.get("byte_count"))
        pkt_count = _f(row.get("packet_count"))
        avg_pkt = _f(row.get("avg_packet_size_bytes"))
        bytes_per_sec = byte_count / denom
        packets_per_sec = pkt_count / denom
        if config.FEATURE_LOG1P:
            bytes_per_sec = float(np.log1p(bytes_per_sec))
            packets_per_sec = float(np.log1p(packets_per_sec))
        data.append([bytes_per_sec, packets_per_sec, avg_pkt])
    if not data:
        return np.zeros((0, len(feature_names)), dtype=float), feature_names
    return np.asarray(data, dtype=float), feature_names


def _apply_robust_scaling(
    X_train: np.ndarray, X_all: np.ndarray
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    if X_train.size == 0:
        return X_train, X_all, {"method": "none"}
    q1 = np_percentile(X_train, 25.0, axis=0, method=config.NP_PERCENTILE_METHOD)
    q3 = np_percentile(X_train, 75.0, axis=0, method=config.NP_PERCENTILE_METHOD)
    med = np.median(X_train, axis=0)
    iqr = np.maximum(np.asarray(q3) - np.asarray(q1), 1e-9)
    X_train_scaled = (X_train - med) / iqr
    X_all_scaled = (X_all - med) / iqr
    return (
        X_train_scaled,
        X_all_scaled,
        {
            "method": "robust_zscore",
            "median": [float(v) for v in med],
            "iqr": [float(v) for v in iqr],
        },
    )


def _run_output_dir(snapshot_dir: Path, run_id: str) -> Path:
    # Keep this entirely separate from evidence packs to avoid polluting archival inputs.
    return snapshot_dir / "runs" / run_id / "ml" / config.ML_SCHEMA_LABEL


def _write_cohort_status(
    *,
    snapshot_dir: Path,
    run_id: str,
    package_name: str | None,
    status: str,
    reason_code: str | None,
    details: dict[str, Any] | None = None,
    min_windows_baseline: int | None = None,
    min_pcap_bytes: int | None = None,
) -> None:
    allowed = {
        None,
        "ML_SKIPPED_BASELINE_GATE_FAIL",
        "ML_SKIPPED_MISSING_FREEZE_MANIFEST",
        "ML_SKIPPED_BAD_FREEZE_CHECKSUM",
        "ML_SKIPPED_MISSING_STATIC_LINK",
        "ML_SKIPPED_MISSING_BASE_APK_SHA256",
    }
    if reason_code not in allowed:
        raise RuntimeError(f"Unknown paper exclusion reason code: {reason_code}")
    out_dir = _run_output_dir(snapshot_dir, run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "run_id": str(run_id),
        "package_name": package_name,
        "status": status,
        "reason_code": reason_code,
        "gates": {
            "min_windows_baseline": int(min_windows_baseline if min_windows_baseline is not None else config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes": int(min_pcap_bytes if min_pcap_bytes is not None else config.MIN_PCAP_BYTES_FALLBACK),
        },
    }
    if details:
        payload["details"] = details
    (out_dir / "cohort_status.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _pcap_size_bytes(inputs: RunInputs) -> int | None:
    if isinstance(inputs.pcap_report, dict):
        try:
            v = inputs.pcap_report.get("pcap_size_bytes")
            if v is not None:
                return int(v)
        except Exception:
            pass
    if inputs.pcap_path and inputs.pcap_path.exists():
        try:
            return int(inputs.pcap_path.stat().st_size)
        except Exception:
            return None
    return None


def _clamp01(v: float | None) -> float | None:
    if v is None:
        return None
    try:
        x = float(v)
    except Exception:
        return None
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _safe_float(v: object) -> float | None:
    try:
        return float(v)  # type: ignore[arg-type]
    except Exception:
        return None


def _transport_ratios_from_inputs(inputs: RunInputs) -> tuple[float | None, float | None, float | None, float | None]:
    proxies = None
    if isinstance(inputs.pcap_features, dict):
        p = inputs.pcap_features.get("proxies")
        if isinstance(p, dict):
            proxies = p
    if proxies:
        return (
            _safe_float(proxies.get("tls_ratio")),
            _safe_float(proxies.get("quic_ratio")),
            _safe_float(proxies.get("tcp_ratio")),
            _safe_float(proxies.get("udp_ratio")),
        )
    if not isinstance(inputs.pcap_report, dict):
        return None, None, None, None
    pb: dict[str, int] = {}
    for row in inputs.pcap_report.get("protocol_hierarchy") or []:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "").strip().lower()
        if not proto:
            continue
        try:
            b = int(row.get("bytes") or 0)
        except Exception:
            b = 0
        pb[proto] = pb.get(proto, 0) + max(b, 0)
    tcp_b = pb.get("tcp") or 0
    udp_b = pb.get("udp") or 0
    tls_b = pb.get("tls") or 0
    quic_b = (pb.get("quic") or 0) + (pb.get("gquic") or 0)
    total = float(tcp_b + udp_b) if (tcp_b + udp_b) > 0 else 0.0
    tls_ratio = float(min(tls_b, tcp_b)) / float(tcp_b) if tcp_b > 0 else None
    quic_denom = float(max(udp_b, quic_b))
    quic_ratio = (float(quic_b) / quic_denom) if quic_denom > 0 else None
    tcp_ratio = float(tcp_b) / total if total > 0 else None
    udp_ratio = float(udp_b) / total if total > 0 else None
    return _clamp01(tls_ratio), _clamp01(quic_ratio), _clamp01(tcp_ratio), _clamp01(udp_ratio)


def _write_json_if_missing(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_model_manifest(
    path: Path,
    *,
    run_inputs: RunInputs,
    identity_key_used: str,
    seed: int,
    window_spec: WindowSpec,
    model_outputs: dict[str, dict[str, Any]],
    selection_manifest_path: Path,
) -> None:
    pcapdroid_version = "unknown"
    capture_mode = "unknown"
    linktype = "unknown"
    if isinstance(run_inputs.manifest, dict):
        artifacts = run_inputs.manifest.get("artifacts")
        if isinstance(artifacts, list):
            for art in artifacts:
                if not isinstance(art, dict) or str(art.get("type") or "") != "pcapdroid_capture_meta":
                    continue
                rel = art.get("relative_path")
                if isinstance(rel, str) and rel:
                    try:
                        meta = json.loads((run_inputs.run_dir / rel).read_text(encoding="utf-8"))
                        if isinstance(meta, dict):
                            capture_mode = str(meta.get("capture_mode") or "unknown")
                            pcapdroid_version = str(meta.get("pcapdroid_version") or "unknown")
                    except Exception:
                        pass
                break
    if isinstance(run_inputs.pcap_report, dict):
        cap = run_inputs.pcap_report.get("capinfos")
        parsed = (cap.get("parsed") if isinstance(cap, dict) else None) if cap is not None else None
        if isinstance(parsed, dict):
            linktype = str(parsed.get("file_type") or parsed.get("encapsulation") or "unknown")

    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "identity_key_used": identity_key_used,
        "seed": int(seed),
        "seed_salt": {"label": config.SEED_SALT_LABEL},
        "windowing": {"window_size_s": window_spec.window_size_s, "stride_s": window_spec.stride_s},
        "paper_constants": {
            "window_size_s": float(config.WINDOW_SIZE_S),
            "window_stride_s": float(config.WINDOW_STRIDE_S),
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes_fallback": int(config.MIN_PCAP_BYTES_FALLBACK),
            "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
        },
        "capture_semantics": {
            "capture_scope": "PCAPdroid-filtered capture restricted to the target package.",
            "byte_semantics": "aggregate frame length (frame.len) as reported by tshark.",
            "directionality": "no direction split is performed.",
            "capture_tool": "PCAPdroid",
            "filter_type": "PCAPdroid app_filter (package)",
            "capture_mode": capture_mode,
            "pcapdroid_version": pcapdroid_version,
            "pcap_linktype": linktype,
        },
        "selection_manifest_path": str(selection_manifest_path),
        "run": {
            "run_id": run_inputs.run_id,
            "package_name": run_inputs.package_name,
            "run_profile": run_inputs.run_profile,
        },
        "models": model_outputs,
        "model_reporting_roles": {
            config.MODEL_IFOREST: "primary",
            config.MODEL_OCSVM: "secondary_model_robustness_check",
        },
    }
    _write_json_if_missing(path, payload)


def _write_ml_summary(
    path: Path,
    *,
    run_inputs: RunInputs,
    mode: str,
    window_rows: list[dict[str, Any]],
    dropped_partial_windows: int,
    model_outputs: dict[str, dict[str, Any]],
    out_dir: Path,
) -> None:
    ds = run_inputs.manifest.get("dataset") if isinstance(run_inputs.manifest.get("dataset"), dict) else {}
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "run_id": run_inputs.run_id,
        "package_name": run_inputs.package_name,
        "run_profile": run_inputs.run_profile,
        "mode": mode,
        "low_signal": bool(ds.get("low_signal")) if ds.get("low_signal") is not None else None,
        "windows_total": len(window_rows),
        "dropped_partial_windows": int(dropped_partial_windows),
        "models": {},
        "skip": None,
    }
    for model_name, meta in model_outputs.items():
        csv_path = out_dir / f"anomaly_scores_{model_name}.csv"
        if not csv_path.exists():
            continue
        scores: list[float] = []
        with csv_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                try:
                    scores.append(float(row.get("score") or 0.0))
                except Exception:
                    continue
        if not scores:
            continue
        threshold = float(meta.get("threshold_value") or 0.0)
        is_anom = [float(s) >= threshold for s in scores]
        streak_count, longest_streak = anomaly_streaks(is_anom)
        longest_s = persistence_seconds(longest_streak, spec=WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S))
        payload["models"][model_name] = {
            "median": float(statistics.median(scores)),
            "p95": float(
                np_percentile(
                    np.asarray(scores, dtype=float),
                    95.0,
                    method=config.NP_PERCENTILE_METHOD,
                )
            ),
            "max": float(max(scores)),
            "anomalous_windows": int(sum(1 for s in scores if float(s) >= threshold)),
            "anomalous_streaks": {"count": streak_count, "longest": longest_streak, "longest_seconds": float(longest_s)},
            "threshold_value": float(threshold),
            "threshold_percentile": float(meta.get("threshold_percentile") or config.THRESHOLD_PERCENTILE),
            "np_percentile_method": str(meta.get("np_percentile_method") or config.NP_PERCENTILE_METHOD),
            "training_mode": meta.get("training_mode"),
            "training_samples": int(meta.get("training_samples") or 0),
            "training_samples_warning": bool(meta.get("training_samples_warning")),
            "threshold_equals_max": bool(meta.get("threshold_equals_max")),
        }
    _write_json_if_missing(path, payload)


def _write_tables(
    snapshot_dir: Path,
    *,
    per_run_rows: list[dict[str, Any]],
    per_group_mode_rows: list[dict[str, Any]],
    persistence_rows: list[dict[str, Any]],
    stability_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    risk_rows: list[dict[str, Any]],
    dynamic_math_audit_rows: list[dict[str, Any]],
    overlap_rows: list[dict[str, Any]],
    transport_rows: list[dict[str, Any]],
    transport_group_mode_rows: list[dict[str, Any]],
) -> None:
    tables = snapshot_dir / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    def _write(path: Path, rows: list[dict[str, Any]]) -> None:
        fields: list[str] = []
        for r in rows:
            for k in r.keys():
                if k not in fields:
                    fields.append(k)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k) for k in fields})

    _write(tables / "anomaly_prevalence_per_run.csv", per_run_rows)
    _write(tables / "anomaly_prevalence_per_group_mode.csv", per_group_mode_rows)
    _write(tables / "anomaly_persistence_per_run.csv", persistence_rows)
    _write(tables / "threshold_stability_per_group_model.csv", stability_rows)
    _write(tables / "coverage_confidence_per_group.csv", coverage_rows)
    _write(tables / "risk_summary_per_group.csv", risk_rows)
    _write(tables / "dynamic_math_audit_per_group_model.csv", dynamic_math_audit_rows)
    _write(tables / "model_overlap_per_run.csv", overlap_rows)
    _write(tables / "transport_mix_per_run.csv", transport_rows)
    _write(tables / "transport_mix_per_group_mode.csv", transport_group_mode_rows)


def _write_snapshot_summary(snapshot_dir: Path, summary: dict[str, Any]) -> None:
    path = snapshot_dir / "snapshot_summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_snapshot_bundle_manifest(snapshot_dir: Path) -> Path:
    """Write a sha256 inventory of snapshot outputs (Phase F3)."""
    payload: dict[str, Any] = {
        "artifact_type": "operational_snapshot_bundle_manifest",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "snapshot_dir": str(snapshot_dir),
        "files": {},
    }
    files: dict[str, str] = {}
    for p in sorted(snapshot_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        if p.suffix.lower() not in {".json", ".csv", ".tex", ".png", ".md", ".txt"}:
            continue
        rel = str(p.relative_to(snapshot_dir))
        files[rel] = _sha256_file(p)
    payload["files"] = files
    out = snapshot_dir / "snapshot_bundle_manifest.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def run_ml_query_mode(
    *,
    selection: SelectionResult,
    snapshot_root: Path | None = None,
    reuse_existing_outputs: bool = True,
) -> QueryMlRunStats:
    """Run ML in query mode and write operational snapshot outputs."""

    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not evidence_root.exists():
        raise RuntimeError(f"Evidence root missing: {evidence_root}")

    snap_root = snapshot_root or (Path(app_config.OUTPUT_DIR) / "operational")
    sid = _snapshot_id(selector_type=selection.selector_type)
    snapshot_dir = snap_root / sid
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = snapshot_dir / "selection_manifest.json"
    write_selection_manifest(manifest_path, result=selection)

    paper_mode = str(selection.selector_type or "") == "freeze"
    min_windows_baseline_req = int(paper_config.MIN_WINDOWS_BASELINE if paper_mode else config.MIN_WINDOWS_BASELINE)
    min_pcap_bytes_req_default = int(paper_config.MIN_PCAP_BYTES if paper_mode else config.MIN_PCAP_BYTES_FALLBACK)
    # Group by base_apk_sha256 in paper/freeze mode; query mode keeps legacy fallback.
    groups: dict[str, list[RunInputs]] = defaultdict(list)
    skipped_runs = 0
    for ref in selection.included:
        inputs = load_run_inputs(ref.evidence_dir)
        if not inputs:
            skipped_runs += 1
            continue
        if paper_mode:
            ident = inputs.plan.get("run_identity") if isinstance(inputs.plan, dict) and isinstance(inputs.plan.get("run_identity"), dict) else {}
            static_handoff_hash = str(ident.get("static_handoff_hash") or "").strip() if isinstance(ident, dict) else ""
            if not static_handoff_hash:
                out_dir = _run_output_dir(snapshot_dir, ref.run_id)
                out_dir.mkdir(parents=True, exist_ok=True)
                payload = {
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    "run_id": str(ref.run_id),
                    "package_name": ref.package_name,
                    "skip": {"reason": "ML_SKIPPED_MISSING_STATIC_LINK"},
                }
                (out_dir / "ml_summary.json").write_text(
                    json.dumps(payload, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                _write_cohort_status(
                    snapshot_dir=snapshot_dir,
                    run_id=str(ref.run_id),
                    package_name=ref.package_name,
                    status="EXCLUDED",
                    reason_code="ML_SKIPPED_MISSING_STATIC_LINK",
                    min_windows_baseline=min_windows_baseline_req,
                    min_pcap_bytes=min_pcap_bytes_req_default,
                )
                skipped_runs += 1
                continue
        base_sha = ref.base_apk_sha256 or ""
        if not base_sha and paper_mode:
            out_dir = _run_output_dir(snapshot_dir, ref.run_id)
            out_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                "run_id": str(ref.run_id),
                "package_name": ref.package_name,
                "skip": {"reason": "ML_SKIPPED_MISSING_BASE_APK_SHA256"},
            }
            (out_dir / "ml_summary.json").write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            _write_cohort_status(
                snapshot_dir=snapshot_dir,
                run_id=str(ref.run_id),
                package_name=ref.package_name,
                status="EXCLUDED",
                reason_code="ML_SKIPPED_MISSING_BASE_APK_SHA256",
                min_windows_baseline=min_windows_baseline_req,
                min_pcap_bytes=min_pcap_bytes_req_default,
            )
            skipped_runs += 1
            continue
        if not base_sha:
            base_sha = ref.package_name or "unknown"
        groups[base_sha].append(inputs)

    window_spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)

    per_run_prevalence: list[dict[str, Any]] = []
    per_group_mode_prevalence: list[dict[str, Any]] = []
    per_run_persistence: list[dict[str, Any]] = []
    per_group_model_stability: list[dict[str, Any]] = []
    per_group_coverage: list[dict[str, Any]] = []
    per_group_risk: list[dict[str, Any]] = []
    per_group_model_math_audit: list[dict[str, Any]] = []
    model_registry_rows: list[dict[str, Any]] = []
    overlap_rows: list[dict[str, Any]] = []
    transport_rows: list[dict[str, Any]] = []
    transport_group_mode_rows: list[dict[str, Any]] = []
    static_inputs_by_group: dict[str, dict[str, Any]] = {}

    groups_seen = len(groups)
    groups_trained = 0
    runs_scored = 0
    runs_skipped = 0
    groups_skipped_no_baseline = 0
    groups_union_fallback = 0
    groups_skipped_baseline_gate_fail = 0
    groups_baseline_thin = 0

    for group_key in sorted(groups.keys()):
        runs = groups[group_key]
        # Sort runs deterministically.
        runs = sorted(
            runs,
            key=lambda r: (
                str(r.package_name or ""),
                _mode_rank(derive_run_mode(r)[0]),
                str(r.manifest.get("ended_at") or ""),
                r.run_id,
            ),
        )
        pkg = next((r.package_name for r in runs if r.package_name), None) or "<unknown>"
        # Static inputs: plan is embedded in evidence packs (baseline run is canonical).
        # If missing, we still run dynamic ML; static is optional for operational summary.
        static_inputs = None
        for candidate in runs:
            if derive_run_mode(candidate)[0] == "baseline":
                plan_path = candidate.run_dir / "inputs" / "static_dynamic_plan.json"
                if plan_path.exists():
                    try:
                        plan = json.loads(plan_path.read_text(encoding="utf-8"))
                    except Exception:
                        plan = None
                    if isinstance(plan, dict):
                        static_inputs = build_static_inputs_from_plan(plan)
                break
        if static_inputs is not None:
            static_inputs_by_group[group_key] = {
                "package_name": pkg,
                "E_raw": int(static_inputs.exported_components_total),
                "P_raw": int(static_inputs.dangerous_permission_count),
                "C": int(static_inputs.uses_cleartext_traffic),
                "S": float(static_inputs.sdk_indicator_score),
            }

        # Preflight + windowing per run.
        by_run_rows: dict[str, tuple[list[dict[str, Any]], int, str]] = {}
        all_rows: list[dict[str, Any]] = []
        for r in runs:
            out_dir = _run_output_dir(snapshot_dir, r.run_id)
            out_dir.mkdir(parents=True, exist_ok=True)
            pf_path = out_dir / "ml_preflight.json"
            if not pf_path.exists():
                write_ml_preflight(pf_path, compute_ml_preflight(r))

            duration = get_sampling_duration_seconds(r)
            if duration is None or duration <= 0 or not r.pcap_path or not r.pcap_path.exists():
                runs_skipped += 1
                continue
            try:
                packets = extract_packet_timeline(r.pcap_path)
                rows, dropped = build_window_features(packets, duration_s=float(duration), spec=window_spec)
            except Exception:
                runs_skipped += 1
                continue
            if not rows:
                runs_skipped += 1
                continue
            mode, _ = derive_run_mode(r)
            for row in rows:
                row["_run_id"] = r.run_id
                row["_mode"] = mode
            by_run_rows[r.run_id] = (rows, dropped, mode)
            all_rows.extend(rows)

            # Transport mix per run (best-effort; independent of ML scoring).
            tls, quic, tcp, udp = _transport_ratios_from_inputs(r)
            transport_rows.append(
                {
                    "group_key": group_key,
                    "package_name": pkg,
                    "run_id": r.run_id,
                    "mode": mode,
                    "tls_ratio": tls,
                    "quic_ratio": quic,
                    "tcp_ratio": tcp,
                    "udp_ratio": udp,
                    "pcap_bytes": _pcap_size_bytes(r),
                }
            )

        if not by_run_rows:
            continue

        # Split by mode.
        baseline_rows: list[dict[str, Any]] = []
        interactive_rows: list[dict[str, Any]] = []
        unknown_rows: list[dict[str, Any]] = []
        for _rid, (rows, _, mode) in by_run_rows.items():
            if mode == "baseline":
                baseline_rows.extend(rows)
            elif mode == "interactive":
                interactive_rows.extend(rows)
            else:
                unknown_rows.extend(rows)

        if not baseline_rows:
            # Policy: need >=1 baseline to train.
            groups_skipped_no_baseline += 1
            continue
        baseline_run_count = sum(1 for _, (_, _, m) in by_run_rows.items() if m == "baseline")
        interactive_run_count = sum(1 for _, (_, _, m) in by_run_rows.items() if m == "interactive")
        unknown_run_count = sum(1 for _, (_, _, m) in by_run_rows.items() if m == "unknown")
        if baseline_run_count < 2:
            groups_baseline_thin += 1

        # Training selection:
        # - paper/freeze mode: baseline-only fail-closed
        # - query mode: legacy union fallback allowed
        baseline_windows_ok = len(baseline_rows) >= int(min_windows_baseline_req)
        min_bytes = int(min_pcap_bytes_req_default)
        baseline_pcap_bytes_total = 0
        for r in runs:
            mode, _ = derive_run_mode(r)
            if mode != "baseline":
                continue
            if r.pcap_path and r.pcap_path.exists():
                baseline_pcap_bytes_total += int(r.pcap_path.stat().st_size)
            ds = r.manifest.get("dataset") if isinstance(r.manifest.get("dataset"), dict) else {}
            try:
                mb = int(ds.get("min_pcap_bytes") or 0)
                if mb > min_bytes:
                    min_bytes = mb
            except Exception:
                pass
        baseline_bytes_ok = baseline_pcap_bytes_total >= int(min_bytes)
        if baseline_bytes_ok and baseline_windows_ok:
            training_mode = "baseline_only"
            train_rows = baseline_rows
        elif paper_mode:
            groups_skipped_baseline_gate_fail += 1
            for r in runs:
                out_dir = _run_output_dir(snapshot_dir, r.run_id)
                out_dir.mkdir(parents=True, exist_ok=True)
                payload = {
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    "run_id": str(r.run_id),
                    "package_name": r.package_name,
                    "skip": {"reason": "ML_SKIPPED_BASELINE_GATE_FAIL"},
                }
                (out_dir / "ml_summary.json").write_text(
                    json.dumps(payload, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                _write_cohort_status(
                    snapshot_dir=snapshot_dir,
                    run_id=str(r.run_id),
                    package_name=r.package_name,
                    status="EXCLUDED",
                    reason_code="ML_SKIPPED_BASELINE_GATE_FAIL",
                    details={
                        "baseline_windows_total": int(len(baseline_rows)),
                        "min_windows_baseline": int(min_windows_baseline_req),
                        "baseline_windows_ok": bool(baseline_windows_ok),
                        "baseline_pcap_bytes_ok": bool(baseline_bytes_ok),
                        "baseline_min_pcap_bytes": int(min_bytes),
                    },
                    min_windows_baseline=min_windows_baseline_req,
                    min_pcap_bytes=min_bytes,
                )
            runs_skipped += len(runs)
            continue
        else:
            training_mode = "union_fallback"
            groups_union_fallback += 1
            train_rows = baseline_rows + interactive_rows

        # Training run provenance (Phase F3): unknown-mode runs are never used for training.
        training_run_ids: list[str] = []
        for rid, (_, _, m) in by_run_rows.items():
            if m == "baseline":
                training_run_ids.append(rid)
            elif m == "interactive" and training_mode == "union_fallback":
                training_run_ids.append(rid)
        training_run_ids = sorted(set(training_run_ids))

        # Baseline p95 bytes/sec for intensity inference (heuristic).
        baseline_p95_bps: float | None = None
        try:
            denom = float(window_spec.window_size_s) if window_spec.window_size_s > 0 else 1.0
            bps = [float(r.get("byte_count") or 0.0) / denom for r in baseline_rows]
            if bps:
                baseline_p95_bps = float(np_percentile(np.asarray(bps, dtype=float), 95.0, method="linear"))
        except Exception:
            baseline_p95_bps = None

        X_train, feature_names = _rows_to_matrix(train_rows, window_spec=window_spec)
        X_all, _ = _rows_to_matrix(all_rows, window_spec=window_spec)
        if X_train.size == 0 or X_train.shape[0] < 3 or X_all.size == 0:
            continue

        feature_scaling: dict[str, Any] | None = None
        if config.FEATURE_ROBUST_SCALE:
            X_train, X_all, feature_scaling = _apply_robust_scaling(X_train, X_all)

        # Seed: stable per group key.
        identity_key = f"group:{group_key}"
        seed = derive_seed(identity_key)
        specs = fixed_model_specs(seed)
        groups_trained += 1

        per_model_thresholds: dict[str, float] = {}
        model_outputs: dict[str, dict[str, Any]] = {}
        per_model_scores_by_run: dict[str, dict[str, list[float]]] = {}

        for spec in specs:
            model = fit_model(spec, X_train)
            scores_train = anomaly_scores(spec.name, model, X_train)
            scores_all = anomaly_scores(spec.name, model, X_all)
            threshold = float(
                np_percentile(
                    scores_train,
                    config.THRESHOLD_PERCENTILE,
                    method=config.NP_PERCENTILE_METHOD,
                )
            )
            stability = threshold_stability(scores_train, threshold, np_method=config.NP_PERCENTILE_METHOD)
            train_max = float(np.max(scores_train)) if scores_train.size else 0.0
            threshold_equals_max = bool(abs(threshold - train_max) <= 1e-9)
            training_samples = int(X_train.shape[0])
            training_samples_warning = bool(training_samples < int(config.MIN_TRAINING_SAMPLES_WARNING))

            per_model_thresholds[spec.name] = threshold
            model_outputs[spec.name] = {
                "threshold_percentile": config.THRESHOLD_PERCENTILE,
                "threshold_value": threshold,
                "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                "training_samples": training_samples,
                "training_samples_warning": training_samples_warning,
                "threshold_equals_max": threshold_equals_max,
                "feature_transform": "log1p_bytes_packets" if config.FEATURE_LOG1P else "none",
                "feature_scaling": feature_scaling,
                "feature_names": list(feature_names),
                "params": dict(spec.params),
                "score_semantics": "higher_is_more_anomalous",
                "training_mode": training_mode,
                "baseline_provenance": {
                    "baseline_run_id": str(baseline_runs[0].run_id) if baseline_runs else None,
                    "baseline_pcap_bytes_ok": bool(baseline_bytes_ok),
                    "baseline_windows_ok": bool(baseline_windows_ok),
                    "fallback_reason": (
                        []
                        if training_mode == "baseline_only"
                        else [
                            reason
                            for reason, ok in (
                                ("bytes_gate", bool(baseline_bytes_ok)),
                                ("windows_gate", bool(baseline_windows_ok)),
                            )
                            if not ok
                        ]
                    ),
                    "degraded_comparability": bool(training_mode == "union_fallback"),
                },
                "threshold_stability": stability,
                "quality_gates": {
                    "baseline_min_pcap_bytes": int(min_bytes),
                    "baseline_pcap_bytes_total": int(baseline_pcap_bytes_total),
                    "baseline_pcap_bytes_ok": bool(baseline_bytes_ok),
                    "min_windows_baseline": int(min_windows_baseline_req),
                    "baseline_windows_total": int(len(baseline_rows)),
                    "baseline_windows_ok": bool(baseline_windows_ok),
                },
            }
            per_group_model_stability.append(
                {
                    "group_key": group_key,
                    "package_name": pkg,
                    "model": spec.name,
                    "training_mode": training_mode,
                    "baseline_runs": int(baseline_run_count),
                    "interactive_runs": int(interactive_run_count),
                    "unknown_runs": int(unknown_run_count),
                    **stability,
                    "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                    "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                }
            )
            model_registry_rows.append(
                {
                    "group_key": group_key,
                    "package_name": pkg,
                    "model": spec.name,
                    "training_mode": training_mode,
                    "training_run_ids": training_run_ids,
                    "training_samples": int(stability.get("training_samples") or 0),
                    "threshold_value": float(threshold),
                    "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                    "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                    "feature_log1p": bool(config.FEATURE_LOG1P),
                    "feature_robust_scale": bool(config.FEATURE_ROBUST_SCALE),
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                }
            )

            # Split per-run scores in deterministic order.
            scores_by_run: dict[str, list[float]] = defaultdict(list)
            rows_by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row, score in zip(all_rows, scores_all, strict=True):
                rid = str(row.get("_run_id") or "")
                if not rid:
                    continue
                scores_by_run[rid].append(float(score))
                rows_by_run[rid].append(
                    {
                        "window_start_s": row["window_start_s"],
                        "window_end_s": row["window_end_s"],
                        "score": float(score),
                        "threshold": float(threshold),
                        "is_anomalous": bool(float(score) >= float(threshold)),
                    }
                )
            per_model_scores_by_run[spec.name] = dict(scores_by_run)

            for r in runs:
                out_dir = _run_output_dir(snapshot_dir, r.run_id)
                out_dir.mkdir(parents=True, exist_ok=True)
                scores_path = out_dir / f"anomaly_scores_{spec.name}.csv"
                if reuse_existing_outputs and scores_path.exists():
                    continue
                write_anomaly_scores_csv(scores_path, rows_by_run.get(r.run_id) or [])

        # Coverage/confidence row per group (operational diagnostic; heuristic, auditable).
        confidence_notes: list[str] = []
        if baseline_run_count < 2:
            confidence_notes.append("baseline_thin")
        if not baseline_windows_ok:
            confidence_notes.append("baseline_windows_below_min")
        if not baseline_bytes_ok:
            confidence_notes.append("baseline_pcap_bytes_below_min")
        if training_mode == "union_fallback":
            confidence_notes.append("union_fallback")
        # Very simple level: high if baseline-only and not thin, else medium/low.
        if training_mode == "baseline_only" and baseline_run_count >= 2 and baseline_windows_ok and baseline_bytes_ok:
            confidence_level = "high"
        elif training_mode == "baseline_only" and baseline_windows_ok and baseline_bytes_ok:
            confidence_level = "medium"
        else:
            confidence_level = "low"
        per_group_coverage.append(
            {
                "group_key": group_key,
                "package_name": pkg,
                "baseline_runs": int(baseline_run_count),
                "interactive_runs": int(interactive_run_count),
                "unknown_runs": int(unknown_run_count),
                "baseline_windows_total": int(len(baseline_rows)),
                "interactive_windows_total": int(len(interactive_rows)),
                "unknown_windows_total": int(len(unknown_rows)),
                "baseline_pcap_bytes_total": int(baseline_pcap_bytes_total),
                "baseline_min_pcap_bytes": int(min_bytes),
                "training_mode": training_mode,
                "confidence_level": confidence_level,
                "confidence_notes": ",".join(confidence_notes) if confidence_notes else "",
                "ml_schema_version": int(config.ML_SCHEMA_VERSION),
            }
        )

        # Write per-run manifests/summaries.
        for r in runs:
            out_dir = _run_output_dir(snapshot_dir, r.run_id)
            out_dir.mkdir(parents=True, exist_ok=True)
            manifest_out = out_dir / "model_manifest.json"
            summary_out = out_dir / "ml_summary.json"
            mode, _ = derive_run_mode(r)
            if not (reuse_existing_outputs and manifest_out.exists()):
                _write_model_manifest(
                    manifest_out,
                    run_inputs=r,
                    identity_key_used=identity_key,
                    seed=seed,
                    window_spec=window_spec,
                    model_outputs=model_outputs,
                    selection_manifest_path=manifest_path,
                )
            if not (reuse_existing_outputs and summary_out.exists()):
                window_rows = by_run_rows.get(r.run_id, ([], 0, mode))[0]
                dropped = by_run_rows.get(r.run_id, ([], 0, mode))[1]
                _write_ml_summary(
                    summary_out,
                    run_inputs=r,
                    mode=mode,
                    window_rows=window_rows,
                    dropped_partial_windows=int(dropped),
                    model_outputs=model_outputs,
                    out_dir=out_dir,
                )
            if paper_mode:
                _write_cohort_status(
                    snapshot_dir=snapshot_dir,
                    run_id=str(r.run_id),
                    package_name=r.package_name,
                    status="CANONICAL_PAPER_ELIGIBLE",
                    reason_code=None,
                    details={"group_key": str(group_key)},
                    min_windows_baseline=min_windows_baseline_req,
                    min_pcap_bytes=min_pcap_bytes_req_default,
                )

        # Model overlap per run (IF vs OC-SVM).
        if config.MODEL_IFOREST in per_model_scores_by_run and config.MODEL_OCSVM in per_model_scores_by_run:
            if_thr = float(per_model_thresholds.get(config.MODEL_IFOREST) or 0.0)
            oc_thr = float(per_model_thresholds.get(config.MODEL_OCSVM) or 0.0)
            for rid in sorted(by_run_rows.keys()):
                if_scores = per_model_scores_by_run[config.MODEL_IFOREST].get(rid) or []
                oc_scores = per_model_scores_by_run[config.MODEL_OCSVM].get(rid) or []
                n = min(len(if_scores), len(oc_scores))
                if n <= 0:
                    continue
                a = {i for i in range(n) if float(if_scores[i]) >= if_thr}
                b = {i for i in range(n) if float(oc_scores[i]) >= oc_thr}
                union = a.union(b)
                inter = a.intersection(b)
                jaccard = (float(len(inter)) / float(len(union))) if union else 0.0
                overlap_rows.append(
                    {
                        "group_key": group_key,
                        "package_name": pkg,
                        "run_id": rid,
                        "mode": by_run_rows[rid][2],
                        "training_mode": training_mode,
                        "windows_total": int(n),
                        "iforest_flagged": int(len(a)),
                        "ocsvm_flagged": int(len(b)),
                        "both_flagged": int(len(inter)),
                        "either_flagged": int(len(union)),
                        "jaccard": float(jaccard),
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )

        # Per-run prevalence rows.
        for model_name, scores_by_run in per_model_scores_by_run.items():
            thr = float(per_model_thresholds.get(model_name) or 0.0)
            for rid, scores in scores_by_run.items():
                if not scores:
                    continue
                mode = by_run_rows.get(rid, ([], 0, "unknown"))[2]
                anomalous = int(sum(1 for s in scores if float(s) >= thr))
                arr = np.asarray(scores, dtype=float)
                # Persistence (Phase F2)
                is_anom = [float(s) >= thr for s in scores]
                streak_count, longest_streak = anomaly_streaks(is_anom)
                longest_s = persistence_seconds(longest_streak, spec=window_spec)
                intensity = infer_intensity_from_windows(
                    run_window_rows=by_run_rows.get(rid, ([], 0, mode))[0],
                    baseline_p95_bytes_per_sec=baseline_p95_bps,
                    spec=window_spec,
                )
                per_run_prevalence.append(
                    {
                        "group_key": group_key,
                        "package_name": pkg,
                        "run_id": rid,
                        "mode": mode,
                        "model": model_name,
                        "training_mode": training_mode,
                        "windows_total": int(arr.shape[0]),
                        "median": float(statistics.median(scores)),
                        "p95": float(np_percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)),
                        "max": float(np.max(arr)),
                        "anomalous_windows": anomalous,
                        "anomalous_pct": float(anomalous) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0,
                        "threshold_value": float(thr),
                        "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                        "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )
                per_run_persistence.append(
                    {
                        "group_key": group_key,
                        "package_name": pkg,
                        "run_id": rid,
                        "mode": mode,
                        "model": model_name,
                        "training_mode": training_mode,
                        "windows_total": int(arr.shape[0]),
                        "anomalous_windows": int(anomalous),
                        "anomalous_pct": float(anomalous) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0,
                        "anomalous_streak_count": int(streak_count),
                        "anomalous_longest_streak_windows": int(longest_streak),
                        "anomalous_longest_streak_seconds": float(longest_s),
                        "intensity_label": intensity.label,
                        "intensity_score": float(intensity.score) if intensity.score is not None else None,
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )

        # Per-group-mode aggregate prevalence rows (concatenate windows by mode).
        for model_name, scores_by_run in per_model_scores_by_run.items():
            thr = float(per_model_thresholds.get(model_name) or 0.0)
            mode_scores: dict[str, list[float]] = {"baseline": [], "interactive": [], "unknown": []}
            for rid, scores in scores_by_run.items():
                mode = by_run_rows.get(rid, ([], 0, "unknown"))[2]
                mode_scores.setdefault(mode, []).extend(scores)
            for mode, scores in sorted(mode_scores.items(), key=lambda kv: _mode_rank(kv[0])):
                if not scores:
                    continue
                anomalous = int(sum(1 for s in scores if float(s) >= thr))
                arr = np.asarray(scores, dtype=float)
                per_group_mode_prevalence.append(
                    {
                        "group_key": group_key,
                        "package_name": pkg,
                        "mode": mode,
                        "model": model_name,
                        "training_mode": training_mode,
                        "windows_total": int(arr.shape[0]),
                        "median": float(statistics.median(scores)),
                        "p95": float(np_percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)),
                        "max": float(np.max(arr)),
                        "anomalous_windows": anomalous,
                        "anomalous_pct": float(anomalous) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0,
                        "threshold_value": float(thr),
                        "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                        "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )

        # Transport mix group-mode rollup (weighted by pcap_bytes).
        by_mode: dict[str, list[dict[str, Any]]] = {"baseline": [], "interactive": [], "unknown": []}
        for tr in transport_rows:
            if tr.get("group_key") == group_key:
                by_mode.setdefault(str(tr.get("mode") or "unknown"), []).append(tr)

        def _wavg(pairs: list[tuple[float | None, int]]) -> float | None:
            num = 0.0
            den = 0.0
            for v, w in pairs:
                if v is None:
                    continue
                if w <= 0:
                    continue
                num += float(v) * float(w)
                den += float(w)
            return (num / den) if den > 0 else None

        for mode, rs in sorted(by_mode.items(), key=lambda kv: _mode_rank(kv[0])):
            if not rs:
                continue
            transport_group_mode_rows.append(
                {
                    "group_key": group_key,
                    "package_name": pkg,
                    "mode": mode,
                    "tls_ratio": _wavg([(_safe_float(r.get("tls_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "quic_ratio": _wavg([(_safe_float(r.get("quic_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "tcp_ratio": _wavg([(_safe_float(r.get("tcp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "udp_ratio": _wavg([(_safe_float(r.get("udp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "pcap_bytes_total": int(sum(int(r.get("pcap_bytes") or 0) for r in rs)),
                }
            )

        runs_scored += len(by_run_rows)

    # ---- Derived operational summary tables (F2) ----
    # Static exposure: cohort-relative min-max over selected groups (within snapshot).
    static_by_group: dict[str, dict[str, Any]] = {}
    if static_inputs_by_group:
        gks = sorted(static_inputs_by_group.keys())
        e_norm = minmax_norm([float(static_inputs_by_group[g]["E_raw"]) for g in gks])
        p_norm = minmax_norm([float(static_inputs_by_group[g]["P_raw"]) for g in gks])
        for idx, gk in enumerate(gks):
            rec = dict(static_inputs_by_group[gk])
            rec["E_norm"] = float(e_norm[idx])
            rec["P_norm"] = float(p_norm[idx])
            rec["static_exposure_score"] = static_exposure_score_components(
                E_norm=e_norm[idx],
                P_norm=p_norm[idx],
                C=rec.get("C"),
                S=rec.get("S"),
            )
            rec["exposure_grade"] = exposure_grade(rec.get("static_exposure_score"))
            static_by_group[gk] = rec

    # Dynamic math audit per group/model: join stability + interactive aggregate + persistence aggregate.
    # Index interactive prevalence per group/model.
    prev_idx: dict[tuple[str, str], dict[str, Any]] = {}
    for r in per_group_mode_prevalence:
        if str(r.get("mode") or "") != "interactive":
            continue
        key = (str(r.get("group_key") or ""), str(r.get("model") or ""))
        prev_idx[key] = r
    # Persistence aggregate per group/model over interactive runs: take max longest streak, sum windows.
    pers_idx: dict[tuple[str, str], dict[str, Any]] = {}
    for r in per_run_persistence:
        if str(r.get("mode") or "") != "interactive":
            continue
        key = (str(r.get("group_key") or ""), str(r.get("model") or ""))
        rec = pers_idx.setdefault(
            key,
            {
                "windows_total": 0,
                "anomalous_windows": 0,
                "anomalous_longest_streak_windows": 0,
                "anomalous_longest_streak_seconds": 0.0,
            },
        )
        rec["windows_total"] += int(r.get("windows_total") or 0)
        rec["anomalous_windows"] += int(r.get("anomalous_windows") or 0)
        rec["anomalous_longest_streak_windows"] = max(
            int(rec.get("anomalous_longest_streak_windows") or 0),
            int(r.get("anomalous_longest_streak_windows") or 0),
        )
        rec["anomalous_longest_streak_seconds"] = float(
            max(
                float(rec.get("anomalous_longest_streak_seconds") or 0.0),
                float(r.get("anomalous_longest_streak_seconds") or 0.0),
            )
        )
        pers_idx[key] = rec
    # Confidence per group.
    conf_idx = {str(r.get("group_key") or ""): r for r in per_group_coverage}

    for st in per_group_model_stability:
        gk = str(st.get("group_key") or "")
        model = str(st.get("model") or "")
        pkg = str(st.get("package_name") or "")
        conf = conf_idx.get(gk) or {}
        prev = prev_idx.get((gk, model)) or {}
        pers = pers_idx.get((gk, model)) or {}
        anomalous_pct = prev.get("anomalous_pct")
        longest_s = pers.get("anomalous_longest_streak_seconds")
        grade = deviation_grade(
            anomalous_pct=float(anomalous_pct) if anomalous_pct is not None else None,
            longest_streak_seconds=float(longest_s) if longest_s is not None else None,
            confidence_level=str(conf.get("confidence_level") or ""),
        )
        dyn_score = dynamic_deviation_score_0_100(
            anomalous_pct=float(anomalous_pct) if anomalous_pct is not None else None,
            longest_streak_windows=int(pers.get("anomalous_longest_streak_windows") or 0),
            windows_total=int(pers.get("windows_total") or 0),
            confidence_level=str(conf.get("confidence_level") or ""),
        )
        per_group_model_math_audit.append(
            {
                "group_key": gk,
                "package_name": pkg,
                "model": model,
                "training_mode": st.get("training_mode"),
                "training_samples": st.get("training_samples"),
                "threshold_value": st.get("threshold_value"),
                "threshold_equals_max": st.get("threshold_equals_max"),
                "threshold_near_max": st.get("threshold_near_max"),
                "threshold_to_max_norm": st.get("threshold_to_max_norm"),
                "interactive_windows_total": pers.get("windows_total"),
                "interactive_anomalous_pct": anomalous_pct,
                "interactive_longest_streak_seconds": pers.get("anomalous_longest_streak_seconds"),
                "deviation_grade": grade,
                "dynamic_deviation_score": dyn_score,
                "confidence_level": conf.get("confidence_level"),
                "confidence_notes": conf.get("confidence_notes"),
                "ml_schema_version": int(config.ML_SCHEMA_VERSION),
            }
        )

    # Per-group unified risk summary (primary model IF; include OC-SVM as secondary columns if available).
    # Use deviation grades and exposure grades; final is a rule-based regime label (not fused scalar).
    # Index dynamic audit by group/model.
    audit_idx = {(r["group_key"], r["model"]): r for r in per_group_model_math_audit if r.get("group_key") and r.get("model")}
    for cov in per_group_coverage:
        gk = str(cov.get("group_key") or "")
        pkg = str(cov.get("package_name") or "")
        stat = static_by_group.get(gk) or {}
        exp_score = stat.get("static_exposure_score")
        exp_grade = stat.get("exposure_grade") or exposure_grade(exp_score if exp_score is not None else None)
        # Primary model = isolation forest.
        if_row = audit_idx.get((gk, config.MODEL_IFOREST)) or {}
        oc_row = audit_idx.get((gk, config.MODEL_OCSVM)) or {}
        dev_grade_if = if_row.get("deviation_grade") or "Unknown"
        final_reg = final_posture_regime(exposure_grade_label=str(exp_grade), deviation_grade_label=str(dev_grade_if))
        final_grade = final_posture_grade(exposure_grade_label=str(exp_grade), deviation_grade_label=str(dev_grade_if))
        conf_level = str(cov.get("confidence_level") or "")
        # Rationale: compact, operator-facing.
        static_drivers = []
        if "E_raw" in stat:
            static_drivers.append(f"exported={stat.get('E_raw')}")
        if "P_raw" in stat:
            static_drivers.append(f"dangerous_perms={stat.get('P_raw')}")
        if stat.get("C") is not None:
            static_drivers.append(f"cleartext_flag={int(stat.get('C') or 0)}")
        dyn_driver = ""
        if if_row:
            dyn_driver = f"p={if_row.get('interactive_anomalous_pct')} longest_s={if_row.get('interactive_longest_streak_seconds')}"
        per_group_risk.append(
            {
                "group_key": gk,
                "package_name": pkg,
                "static_exposure_score": exp_score,
                "exposure_grade": exp_grade,
                "dynamic_deviation_score_if": if_row.get("dynamic_deviation_score"),
                "deviation_grade_if": dev_grade_if,
                "dynamic_deviation_score_oc": oc_row.get("dynamic_deviation_score"),
                "deviation_grade_oc": oc_row.get("deviation_grade") or "",
                "final_regime_if": final_reg,
                "final_grade_if": final_grade,
                "confidence_level": conf_level,
                "confidence_notes": cov.get("confidence_notes") or "",
                "static_drivers": ";".join(static_drivers),
                "dynamic_driver_if": dyn_driver,
                "ml_schema_version": int(config.ML_SCHEMA_VERSION),
            }
        )

    _write_tables(
        snapshot_dir,
        per_run_rows=per_run_prevalence,
        per_group_mode_rows=per_group_mode_prevalence,
        persistence_rows=per_run_persistence,
        stability_rows=per_group_model_stability,
        coverage_rows=per_group_coverage,
        risk_rows=per_group_risk,
        dynamic_math_audit_rows=per_group_model_math_audit,
        overlap_rows=overlap_rows,
        transport_rows=transport_rows,
        transport_group_mode_rows=transport_group_mode_rows,
    )

    # Phase F3: snapshot closure artifacts (freeze + lint + model registry + bundle manifest).
    evidence_root_fs = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    freeze_ok = True
    freeze_err: str | None = None
    try:
        write_snapshot_freeze_manifest(snapshot_dir=snapshot_dir, evidence_root=evidence_root_fs, overwrite=True)
    except Exception as exc:  # noqa: BLE001
        freeze_ok = False
        freeze_err = str(exc)
        (snapshot_dir / "freeze_manifest_error.txt").write_text(freeze_err + "\n", encoding="utf-8")

    lint = lint_operational_snapshot(snapshot_dir)
    lint_path = snapshot_dir / "operational_lint.json"
    lint_path.write_text(json.dumps({"ok": lint.ok, "issues": lint.issues}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    reg_path = snapshot_dir / "model_registry.json"
    reg_path.write_text(
        json.dumps(
            {
                "artifact_type": "operational_model_registry",
                "created_at_utc": datetime.now(UTC).isoformat(),
                "snapshot_id": sid,
                "models": model_registry_rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    bundle_manifest = _write_snapshot_bundle_manifest(snapshot_dir)

    _write_snapshot_summary(
        snapshot_dir,
        {
            "snapshot_id": sid,
            "selector_type": selection.selector_type,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "groups_seen": int(groups_seen),
            "groups_trained": int(groups_trained),
            "groups_skipped_no_baseline": int(groups_skipped_no_baseline),
            "groups_union_fallback": int(groups_union_fallback),
            "groups_skipped_baseline_gate_fail": int(groups_skipped_baseline_gate_fail),
            "groups_baseline_thin": int(groups_baseline_thin),
            "runs_selected": int(len(selection.included)),
            "runs_scored": int(runs_scored),
            "runs_skipped": int(runs_skipped + skipped_runs),
            "outputs": {
                "selection_manifest": str(manifest_path),
                "tables_dir": str(snapshot_dir / "tables"),
                "runs_dir": str(snapshot_dir / "runs"),
                "freeze_manifest": str(snapshot_dir / "freeze_manifest.json"),
                "operational_lint": str(lint_path),
                "model_registry": str(reg_path),
                "snapshot_bundle_manifest": str(bundle_manifest),
            },
            "bundle_ok": bool(lint.ok and freeze_ok),
            "freeze_ok": bool(freeze_ok),
            "freeze_error": freeze_err,
            "lint_ok": bool(lint.ok),
        },
    )

    return QueryMlRunStats(
        groups_seen=int(groups_seen),
        groups_trained=int(groups_trained),
        runs_scored=int(runs_scored),
        runs_skipped=int(runs_skipped + skipped_runs),
        snapshot_id=sid,
        snapshot_dir=snapshot_dir,
        generated_at_utc=datetime.now(UTC).isoformat(),
    )


__all__ = ["QueryMlRunStats", "run_ml_query_mode"]
