"""Query-mode ML phase helpers.

Phase split goal:
- Keep ``run_ml_query_mode`` as the orchestrator.
- Move selection/gating and per-group preparation out of the main rollout.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import numpy as np

from . import ml_parameters_operational as config
from . import ml_parameters_profile as paper_config
from .evidence_pack_ml_preflight import (
    RunInputs,
    compute_ml_preflight,
    derive_run_mode,
    get_sampling_duration_seconds,
    load_run_inputs,
    write_ml_preflight,
)
from .numpy_percentile import percentile as np_percentile
from .operational_risk import build_static_inputs_from_plan
from .pcap_window_features import build_window_features, extract_packet_timeline
from .selectors.models import SelectionResult
from .telemetry_windowing import WindowSpec


@dataclass(frozen=True)
class PreparedSelectionGroups:
    groups: dict[str, list[RunInputs]]
    skipped_runs: int


@dataclass(frozen=True)
class GroupPreparationStats:
    runs_skipped: int = 0
    groups_skipped_no_baseline: int = 0
    groups_union_fallback: int = 0
    groups_skipped_baseline_gate_fail: int = 0
    groups_baseline_thin: int = 0


@dataclass(frozen=True)
class PreparedGroupInputs:
    group_key: str
    package_name: str
    runs: list[RunInputs]
    static_inputs: dict[str, Any] | None
    static_snapshot: dict[str, Any]
    by_run_rows: dict[str, tuple[list[dict[str, Any]], int, str]]
    all_rows: list[dict[str, Any]]
    baseline_rows: list[dict[str, Any]]
    interactive_rows: list[dict[str, Any]]
    unknown_rows: list[dict[str, Any]]
    baseline_run_count: int
    interactive_run_count: int
    unknown_run_count: int
    baseline_run_ids: list[str]
    training_mode: str
    train_rows: list[dict[str, Any]]
    baseline_windows_ok: bool
    baseline_bytes_ok: bool
    baseline_pcap_bytes_total: int
    min_pcap_bytes: int
    baseline_p95_bps: float | None
    transport_rows: list[dict[str, Any]]


ExcludeRunFn = Callable[[str, str | None, str, dict[str, Any] | None, int, int], None]
RunOutputDirFn = Callable[[str], Path]


def prepare_query_selection_groups(
    *,
    selection: SelectionResult,
    paper_mode: bool,
    exclude_run: ExcludeRunFn,
    min_windows_baseline_req: int,
    min_pcap_bytes_req_default: int,
) -> PreparedSelectionGroups:
    """Load selected evidence packs and apply per-run identity/static gates."""

    groups: dict[str, list[RunInputs]] = defaultdict(list)
    skipped_runs = 0

    for ref in selection.included:
        inputs = load_run_inputs(ref.evidence_dir)
        if not inputs:
            skipped_runs += 1
            continue

        if paper_mode:
            ident = (
                inputs.plan.get("run_identity")
                if isinstance(inputs.plan, dict) and isinstance(inputs.plan.get("run_identity"), dict)
                else {}
            )
            static_handoff_hash = str(ident.get("static_handoff_hash") or "").strip() if isinstance(ident, dict) else ""
            if not static_handoff_hash:
                exclude_run(
                    str(ref.run_id),
                    ref.package_name,
                    "ML_SKIPPED_MISSING_STATIC_LINK",
                    None,
                    min_windows_baseline_req,
                    min_pcap_bytes_req_default,
                )
                skipped_runs += 1
                continue

            identity_reason, identity_details = paper_identity_consistency_issue(inputs)
            if identity_reason:
                exclude_run(
                    str(ref.run_id),
                    ref.package_name,
                    identity_reason,
                    identity_details,
                    min_windows_baseline_req,
                    min_pcap_bytes_req_default,
                )
                skipped_runs += 1
                continue

            static_features = (
                inputs.plan.get("static_features")
                if isinstance(inputs.plan, dict) and isinstance(inputs.plan.get("static_features"), dict)
                else {}
            )
            required_static_features = (
                "exported_components_total",
                "dangerous_permission_count",
                "uses_cleartext_traffic",
                "sdk_indicator_score",
            )
            missing_static_features = [key for key in required_static_features if key not in static_features]
            if missing_static_features:
                exclude_run(
                    str(ref.run_id),
                    ref.package_name,
                    "ML_SKIPPED_MISSING_STATIC_FEATURES",
                    {"missing_static_features": missing_static_features},
                    min_windows_baseline_req,
                    min_pcap_bytes_req_default,
                )
                skipped_runs += 1
                continue

        base_sha = ref.base_apk_sha256 or ""
        if not base_sha and paper_mode:
            exclude_run(
                str(ref.run_id),
                ref.package_name,
                "ML_SKIPPED_MISSING_BASE_APK_SHA256",
                None,
                min_windows_baseline_req,
                min_pcap_bytes_req_default,
            )
            skipped_runs += 1
            continue
        if not base_sha:
            base_sha = ref.package_name or "unknown"
        groups[base_sha].append(inputs)

    return PreparedSelectionGroups(groups=dict(groups), skipped_runs=skipped_runs)


def prepare_group_training_inputs(
    *,
    group_key: str,
    runs: list[RunInputs],
    snapshot_dir: Path,
    paper_mode: bool,
    min_windows_baseline_req: int,
    min_pcap_bytes_req_default: int,
    window_spec: WindowSpec,
    run_output_dir: RunOutputDirFn,
    exclude_run: ExcludeRunFn,
) -> tuple[PreparedGroupInputs | None, GroupPreparationStats]:
    """Prepare one grouped identity for training/scoring.

    This phase owns:
    - deterministic run ordering
    - static-input snapshot extraction
    - per-run preflight + window extraction
    - baseline gating and training-mode selection
    """

    stats = GroupPreparationStats()
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

    static_inputs = None
    static_plan_payload: dict[str, Any] | None = None
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
                    static_plan_payload = plan
            break

    static_snapshot = _extract_static_features_snapshot(static_plan_payload)

    by_run_rows: dict[str, tuple[list[dict[str, Any]], int, str]] = {}
    all_rows: list[dict[str, Any]] = []
    transport_rows: list[dict[str, Any]] = []
    runs_skipped = 0

    for run in runs:
        out_dir = run_output_dir(run.run_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        pf_path = out_dir / "ml_preflight.json"
        if not pf_path.exists():
            write_ml_preflight(pf_path, compute_ml_preflight(run))

        duration = get_sampling_duration_seconds(run)
        if duration is None or duration <= 0 or not run.pcap_path or not run.pcap_path.exists():
            runs_skipped += 1
            continue
        try:
            packets = extract_packet_timeline(run.pcap_path)
            rows, dropped = build_window_features(packets, duration_s=float(duration), spec=window_spec)
        except Exception:
            runs_skipped += 1
            continue
        if not rows:
            runs_skipped += 1
            continue
        mode, _ = derive_run_mode(run)
        for row in rows:
            row["_run_id"] = run.run_id
            row["_mode"] = mode
        by_run_rows[run.run_id] = (rows, dropped, mode)
        all_rows.extend(rows)

        tls, quic, tcp, udp = _transport_ratios_from_inputs(run)
        transport_rows.append(
            {
                "group_key": group_key,
                "package_name": pkg,
                "run_id": run.run_id,
                "mode": mode,
                "tls_ratio": tls,
                "quic_ratio": quic,
                "tcp_ratio": tcp,
                "udp_ratio": udp,
                "pcap_bytes": _pcap_size_bytes(run),
            }
        )

    if not by_run_rows:
        return None, GroupPreparationStats(runs_skipped=runs_skipped)

    baseline_rows: list[dict[str, Any]] = []
    interactive_rows: list[dict[str, Any]] = []
    unknown_rows: list[dict[str, Any]] = []
    for rows, _dropped, mode in by_run_rows.values():
        if mode == "baseline":
            baseline_rows.extend(rows)
        elif mode == "interactive":
            interactive_rows.extend(rows)
        else:
            unknown_rows.extend(rows)

    if not baseline_rows:
        return None, GroupPreparationStats(
            runs_skipped=runs_skipped,
            groups_skipped_no_baseline=1,
        )

    baseline_run_count = sum(1 for _, (_, _, m) in by_run_rows.items() if m == "baseline")
    interactive_run_count = sum(1 for _, (_, _, m) in by_run_rows.items() if m == "interactive")
    unknown_run_count = sum(1 for _, (_, _, m) in by_run_rows.items() if m == "unknown")
    baseline_run_ids = [rid for rid, (_, _, m) in by_run_rows.items() if m == "baseline"]
    groups_baseline_thin = 1 if baseline_run_count < 2 else 0

    baseline_windows_ok = len(baseline_rows) >= int(min_windows_baseline_req)
    min_bytes = int(min_pcap_bytes_req_default)
    baseline_pcap_bytes_total = 0
    for run in runs:
        mode, _ = derive_run_mode(run)
        if mode != "baseline":
            continue
        if run.pcap_path and run.pcap_path.exists():
            baseline_pcap_bytes_total += int(run.pcap_path.stat().st_size)
        ds = run.manifest.get("dataset") if isinstance(run.manifest.get("dataset"), dict) else {}
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
        groups_union_fallback = 0
        groups_skipped_baseline_gate_fail = 0
        baseline_gate_skipped_runs = 0
    elif paper_mode:
        details = {
            "baseline_windows_total": int(len(baseline_rows)),
            "min_windows_baseline": int(min_windows_baseline_req),
            "baseline_windows_ok": bool(baseline_windows_ok),
            "baseline_pcap_bytes_ok": bool(baseline_bytes_ok),
            "baseline_min_pcap_bytes": int(min_bytes),
        }
        for run in runs:
            exclude_run(
                str(run.run_id),
                run.package_name,
                "ML_SKIPPED_BASELINE_GATE_FAIL",
                details,
                min_windows_baseline_req,
                min_bytes,
            )
        return None, GroupPreparationStats(
            runs_skipped=runs_skipped + len(runs),
            groups_skipped_baseline_gate_fail=1,
            groups_baseline_thin=groups_baseline_thin,
        )
    else:
        training_mode = "union_fallback"
        train_rows = baseline_rows + interactive_rows
        groups_union_fallback = 1
        groups_skipped_baseline_gate_fail = 0
        baseline_gate_skipped_runs = 0

    baseline_p95_bps: float | None = None
    try:
        denom = float(window_spec.window_size_s) if window_spec.window_size_s > 0 else 1.0
        bps = [float(row.get("byte_count") or 0.0) / denom for row in baseline_rows]
        if bps:
            baseline_p95_bps = float(np_percentile(np.asarray(bps, dtype=float), 95.0, method="linear"))
    except Exception:
        baseline_p95_bps = None

    return (
        PreparedGroupInputs(
            group_key=group_key,
            package_name=pkg,
            runs=runs,
            static_inputs=(
                {
                    "package_name": pkg,
                    "E_raw": int(static_inputs.exported_components_total),
                    "P_raw": int(static_inputs.dangerous_permission_count),
                    "C": int(static_inputs.uses_cleartext_traffic),
                    "S": float(static_inputs.sdk_indicator_score),
                }
                if static_inputs is not None
                else None
            ),
            static_snapshot=static_snapshot,
            by_run_rows=by_run_rows,
            all_rows=all_rows,
            baseline_rows=baseline_rows,
            interactive_rows=interactive_rows,
            unknown_rows=unknown_rows,
            baseline_run_count=baseline_run_count,
            interactive_run_count=interactive_run_count,
            unknown_run_count=unknown_run_count,
            baseline_run_ids=baseline_run_ids,
            training_mode=training_mode,
            train_rows=train_rows,
            baseline_windows_ok=baseline_windows_ok,
            baseline_bytes_ok=baseline_bytes_ok,
            baseline_pcap_bytes_total=baseline_pcap_bytes_total,
            min_pcap_bytes=min_bytes,
            baseline_p95_bps=baseline_p95_bps,
            transport_rows=transport_rows,
        ),
        GroupPreparationStats(
            runs_skipped=runs_skipped + baseline_gate_skipped_runs,
            groups_union_fallback=groups_union_fallback,
            groups_skipped_baseline_gate_fail=groups_skipped_baseline_gate_fail,
            groups_baseline_thin=groups_baseline_thin,
        ),
    )


def _mode_rank(mode: str) -> int:
    return 0 if mode == "baseline" else (1 if mode == "interactive" else 2)


def _pcap_size_bytes(inputs: RunInputs) -> int | None:
    if isinstance(inputs.pcap_report, dict):
        try:
            value = inputs.pcap_report.get("pcap_size_bytes")
            if value is not None:
                return int(value)
        except Exception:
            pass
    if inputs.pcap_path and inputs.pcap_path.exists():
        try:
            return int(inputs.pcap_path.stat().st_size)
        except Exception:
            return None
    return None


def _clamp01(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        x = float(value)
    except Exception:
        return None
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _safe_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
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
    protocol_bytes: dict[str, int] = {}
    for row in inputs.pcap_report.get("protocol_hierarchy") or []:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "").strip().lower()
        if not proto:
            continue
        try:
            byte_count = int(row.get("bytes") or 0)
        except Exception:
            byte_count = 0
        protocol_bytes[proto] = protocol_bytes.get(proto, 0) + max(byte_count, 0)
    tcp_b = protocol_bytes.get("tcp") or 0
    udp_b = protocol_bytes.get("udp") or 0
    tls_b = protocol_bytes.get("tls") or 0
    quic_b = (protocol_bytes.get("quic") or 0) + (protocol_bytes.get("gquic") or 0)
    total = float(tcp_b + udp_b) if (tcp_b + udp_b) > 0 else 0.0
    tls_ratio = float(min(tls_b, tcp_b)) / float(tcp_b) if tcp_b > 0 else None
    quic_denom = float(max(udp_b, quic_b))
    quic_ratio = (float(quic_b) / quic_denom) if quic_denom > 0 else None
    tcp_ratio = float(tcp_b) / total if total > 0 else None
    udp_ratio = float(udp_b) / total if total > 0 else None
    return _clamp01(tls_ratio), _clamp01(quic_ratio), _clamp01(tcp_ratio), _clamp01(udp_ratio)


def _extract_static_features_snapshot(plan: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(plan, dict):
        return {}
    static_features = plan.get("static_features") if isinstance(plan.get("static_features"), dict) else {}
    if not isinstance(static_features, dict):
        return {}
    out: dict[str, Any] = {}
    out["static_features_schema_version"] = static_features.get("schema_version")
    for key in (
        "permissions_total",
        "high_value_permission_count",
        "nsc_cleartext_domain_count",
        "masvs_control_count_total",
    ):
        try:
            if static_features.get(key) is not None:
                out[key] = int(static_features.get(key))
        except Exception:
            continue
    if static_features.get("uses_webview") is not None:
        out["uses_webview"] = bool(static_features.get("uses_webview"))
    try:
        if static_features.get("static_risk_score") is not None:
            out["static_risk_score"] = float(static_features.get("static_risk_score"))
    except Exception:
        pass
    value = static_features.get("static_risk_band")
    if isinstance(value, str) and value.strip():
        out["static_risk_band"] = value.strip()
    if "masvs_area_counts" in static_features:
        out["masvs_area_counts"] = static_features.get("masvs_area_counts")
    return out


def paper_identity_consistency_issue(inputs: RunInputs) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(inputs.plan, dict):
        return "ML_SKIPPED_MISSING_STATIC_LINK", {"reason": "missing_plan"}
    identity = inputs.plan.get("run_identity") if isinstance(inputs.plan.get("run_identity"), dict) else {}
    if not isinstance(identity, dict):
        return "ML_SKIPPED_MISSING_STATIC_LINK", {"reason": "missing_run_identity"}
    base_sha = _normalize_hex_hash(identity.get("base_apk_sha256"), expected_len=64)
    static_handoff_hash = _normalize_hex_hash(identity.get("static_handoff_hash"), expected_len=64)
    artifact_set_hash = _normalize_hex_hash(identity.get("artifact_set_hash"), expected_len=64)
    signer_set_hash = _normalize_hex_hash(identity.get("signer_set_hash") or identity.get("signer_digest"), expected_len=64)
    if not base_sha:
        return "ML_SKIPPED_BAD_IDENTITY_HASH", {"field": "base_apk_sha256"}
    if not static_handoff_hash:
        return "ML_SKIPPED_BAD_IDENTITY_HASH", {"field": "static_handoff_hash"}
    if not artifact_set_hash:
        return "ML_SKIPPED_BAD_IDENTITY_HASH", {"field": "artifact_set_hash"}
    if not signer_set_hash:
        return "ML_SKIPPED_BAD_IDENTITY_HASH", {"field": "signer_set_hash"}

    package = str(identity.get("package_name_lc") or inputs.plan.get("package_name") or "").strip().lower()
    version_code = str(identity.get("version_code") or inputs.plan.get("version_code") or "").strip()
    signer_digest = str(identity.get("signer_digest") or "").strip()
    if not package or not version_code:
        return "ML_SKIPPED_MISSING_STATIC_LINK", {"reason": "missing_package_or_version"}
    if not signer_digest or signer_digest.upper() == "UNKNOWN":
        return "ML_SKIPPED_MISSING_STATIC_LINK", {"reason": "missing_signer_digest"}

    target = inputs.manifest.get("target") if isinstance(inputs.manifest.get("target"), dict) else {}
    target_package = str(target.get("package_name") or "").strip().lower()
    target_version = str(target.get("version_code") or "").strip()
    if target_package and target_package != package:
        return "ML_SKIPPED_APK_CHANGED_DURING_RUN", {
            "expected_package_name_lc": package,
            "observed_package_name_lc": target_package,
        }
    if target_version and target_version != version_code:
        return "ML_SKIPPED_APK_CHANGED_DURING_RUN", {
            "expected_version_code": version_code,
            "observed_version_code": target_version,
        }
    return None, None


def _normalize_hex_hash(value: object, *, expected_len: int) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw or len(raw) != int(expected_len):
        return None
    try:
        int(raw, 16)
    except Exception:
        return None
    return raw
