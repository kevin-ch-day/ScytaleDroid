"""CLI helper for verifying dynamic evidence packs (Paper #2).

This is an operator-facing wrapper around evidence-pack inspection logic.
It can optionally enrich output with app labels from the DB, but remains safe to
run DB-free (air-gapped) by disabling enrichment.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config


REQUIRED_FILES = [
    "run_manifest.json",
    "inputs/static_dynamic_plan.json",
    "analysis/summary.json",
    "analysis/pcap_report.json",
    "analysis/pcap_features.json",
]

OPTIONAL_FILES = [
    "analysis/static_dynamic_overlap.json",
]

PLAN_IDENTITY_KEYS = {
    "run_signature_version",
    "run_signature",
    "artifact_set_hash",
    "base_apk_sha256",
    "identity_valid",
}

RATIO_KEYS = ("tls_ratio", "quic_ratio", "tcp_ratio", "udp_ratio")
_RATIO_TOLERANCE = 0.02

_ML_AUDIT_COLUMNS = {
    "package_name",
    "model",
    "training_mode",
    "training_samples",
    "training_samples_warning",
    "threshold_equals_max",
    "feature_transform",
    "feature_scaling",
}


def _truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."  # noqa: E203


def _render_table(
    headers: list[str],
    rows: list[list[str]],
    *,
    max_widths: dict[int, int] | None = None,
    right_align: set[int] | None = None,
    padding: int = 2,
) -> None:
    if not headers:
        return
    max_widths = max_widths or {}
    right_align = right_align or set()

    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    for idx, limit in max_widths.items():
        if 0 <= idx < len(widths):
            widths[idx] = min(widths[idx], int(limit))

    def _fmt_cell(idx: int, cell: str) -> str:
        w = widths[idx]
        val = _truncate(cell, w)
        if idx in right_align:
            return val.rjust(w)
        return val.ljust(w)

    pad = " " * padding
    print(pad.join(_fmt_cell(i, h) for i, h in enumerate(headers)))
    print(pad.join("-" * w for w in widths))
    for row in rows:
        print(pad.join(_fmt_cell(i, row[i]) for i in range(len(headers))))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _load_ml_audit_rows() -> list[dict[str, Any]]:
    path = Path(app_config.DATA_DIR) / "ml_audit_per_app_model.csv"
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if not isinstance(row, dict):
                    continue
                rows.append({k: row.get(k) for k in _ML_AUDIT_COLUMNS})
    except Exception:
        return []
    return rows


def _fmt_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024.0:.1f}KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024.0 * 1024.0):.1f}MB"
    return f"{n / (1024.0 * 1024.0 * 1024.0):.1f}GB"


def _coerce_float(v: object) -> float | None:
    try:
        return float(v)  # type: ignore[arg-type]
    except Exception:
        return None


def _bounded_ratio(numer: int | None, denom: int | None) -> float | None:
    if numer is None or denom is None:
        return None
    if denom <= 0 or numer < 0:
        return None
    ratio = float(numer) / float(denom) if denom else None
    if ratio is None:
        return None
    if ratio < 0:
        return 0.0
    if ratio > 1:
        return 1.0
    return ratio


def _compute_transport_mix_from_report(report: dict[str, Any]) -> dict[str, float | None]:
    def _proto_key(value: object) -> str | None:
        if not value or not isinstance(value, str):
            return None
        key = value.strip().lower()
        return key or None

    proto_bytes: dict[str, int] = {}
    for row in report.get("protocol_hierarchy") or []:
        if not isinstance(row, dict):
            continue
        proto = _proto_key(row.get("protocol"))
        b = row.get("bytes")
        if not proto:
            continue
        try:
            bi = int(b)
        except Exception:
            continue
        proto_bytes[proto] = proto_bytes.get(proto, 0) + bi

    ip_bytes = proto_bytes.get("ip") or proto_bytes.get("frame") or None
    tcp_bytes = proto_bytes.get("tcp")
    udp_bytes = proto_bytes.get("udp")
    tls_bytes = proto_bytes.get("tls")
    quic_bytes = int((proto_bytes.get("quic") or 0) + (proto_bytes.get("gquic") or 0))

    tcp_ratio = _bounded_ratio(tcp_bytes, ip_bytes)
    udp_ratio = _bounded_ratio(udp_bytes, ip_bytes)
    quic_ratio = _bounded_ratio(quic_bytes, max(int(udp_bytes or 0), int(quic_bytes or 0)) or None)
    tls_bytes_capped = None
    if tls_bytes is not None and tcp_bytes is not None:
        tls_bytes_capped = min(int(tls_bytes), int(tcp_bytes))
    tls_ratio = _bounded_ratio(tls_bytes_capped, tcp_bytes)
    return {
        "tcp_ratio": tcp_ratio,
        "udp_ratio": udp_ratio,
        "quic_ratio": quic_ratio,
        "tls_ratio": tls_ratio,
    }


def _hostname_like(value: str) -> bool:
    # Lightweight sanity filter (no PSL / enrichment). This is for QA only.
    v = (value or "").strip().lower()
    if not v:
        return False
    v = v.rstrip(".")
    if "%" in v or " " in v or "/" in v or "\\" in v or "@" in v:
        return False
    if ":" in v:
        # reject host:port and ipv6-like (we expect names here)
        return False
    if ".." in v:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")
    if any(ch not in allowed for ch in v):
        return False
    # Domain names should have at least one dot for our purposes.
    if "." not in v:
        return False
    if v.startswith("-") or v.endswith("-") or v.startswith(".") or v.endswith("."):
        return False
    if len(v) > 253:
        return False
    return True


def _top_list_stats(items: object) -> dict[str, Any]:
    if not isinstance(items, list):
        return {"n": 0, "total": 0, "top1_share": None, "junk_n": 0, "junk_rate": None, "junk_samples": []}
    total = 0
    max_c = 0
    junk: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if isinstance(value, str) and value.strip():
            if not _hostname_like(value):
                junk.append(value.strip())
        c = item.get("count")
        try:
            ci = int(c) if c is not None else 0
        except Exception:
            ci = 0
        total += max(ci, 0)
        max_c = max(max_c, max(ci, 0))
    n = len([x for x in items if isinstance(x, dict) and isinstance(x.get("value"), str) and x.get("value").strip()])
    top1 = (float(max_c) / float(total)) if total > 0 else None
    junk_n = len(junk)
    junk_rate = float(junk_n) / float(n) if n > 0 else None
    return {
        "n": n,
        "total": total,
        "top1_share": top1,
        "junk_n": junk_n,
        "junk_rate": junk_rate,
        "junk_samples": junk[:5],
    }


@dataclass(frozen=True)
class PackRow:
    run_id: str
    package_name: str | None
    run_profile: str | None
    valid: bool | None
    invalid_reason: str | None
    countable: bool | None
    low_signal: bool | None
    sampling_duration_s: float | None
    pcap_size_bytes: int | None
    tls_ratio: float | None
    quic_ratio: float | None
    status: str  # OK/WARN/FAIL
    notes: list[str]


def _load_app_labels(packages: set[str]) -> dict[str, str]:
    """Best-effort map of package_name -> display_name from DB.

    This is optional enrichment. Any failure returns an empty mapping.
    """
    if not packages:
        return {}
    try:
        from scytaledroid.Database.db_core import run_sql
    except Exception:
        return {}
    try:
        placeholders = ",".join(["%s"] * len(packages))
        sql = f"SELECT package_name, display_name FROM apps WHERE package_name IN ({placeholders})"
        rows = run_sql(sql, tuple(sorted(packages)), fetch="all", dictionary=True)
    except Exception:
        return {}
    mapping: dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip()
        name = str(row.get("display_name") or "").strip()
        if pkg and name:
            mapping[pkg] = name
    return mapping


def _pcap_path_from_manifest(run_dir: Path, manifest: dict[str, Any]) -> Path | None:
    artifacts = manifest.get("artifacts") or []
    if isinstance(artifacts, list):
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "pcapdroid_capture":
                continue
            rel = item.get("relative_path")
            if isinstance(rel, str) and rel:
                candidate = run_dir / rel
                if candidate.exists():
                    return candidate
    candidates = list(run_dir.glob("**/*.pcap*"))
    return candidates[0] if candidates else None


def _dataset_block(manifest: dict[str, Any]) -> dict[str, Any] | None:
    ds = manifest.get("dataset")
    return ds if isinstance(ds, dict) else None


def _dataset_validity(manifest: dict[str, Any]) -> tuple[bool | None, str | None]:
    ds = _dataset_block(manifest)
    if ds is not None:
        return ds.get("valid_dataset_run"), ds.get("invalid_reason_code")
    return None, None


def _dataset_countable(manifest: dict[str, Any]) -> bool | None:
    ds = _dataset_block(manifest)
    if ds is not None:
        v = ds.get("countable")
        return v if isinstance(v, bool) else None
    return None


def _dataset_low_signal(manifest: dict[str, Any]) -> bool | None:
    ds = _dataset_block(manifest)
    if ds is not None:
        v = ds.get("low_signal")
        return v if isinstance(v, bool) else None
    return None


def _sampling_duration(manifest: dict[str, Any]) -> float | None:
    ds = _dataset_block(manifest)
    if ds is not None:
        return _coerce_float(ds.get("sampling_duration_seconds"))
    return None


def _plan_identity_issue(plan: dict[str, Any] | None) -> str | None:
    if not isinstance(plan, dict):
        return "plan_json_missing_or_invalid"
    ident = plan.get("run_identity") or {}
    if not isinstance(ident, dict):
        return "plan_run_identity_missing"
    missing = sorted(PLAN_IDENTITY_KEYS - set(ident.keys()))
    if missing:
        return f"plan_run_identity_missing_keys:{','.join(missing)}"
    if ident.get("identity_valid") is False:
        return "plan_identity_valid_false"
    return None


def _ratio_issues(features: dict[str, Any] | None) -> list[str]:
    if not isinstance(features, dict):
        return ["pcap_features_missing_or_invalid"]
    proxies = features.get("proxies") or {}
    if not isinstance(proxies, dict):
        return ["pcap_features_proxies_missing"]
    issues: list[str] = []
    for key in RATIO_KEYS:
        if key not in proxies:
            continue
        v = _coerce_float(proxies.get(key))
        if v is None:
            continue
        if v < 0.0 or v > 1.0:
            issues.append(f"ratio_out_of_bounds:{key}={v}")
    return issues


def _profile_bucket(run_profile: str | None) -> str:
    if not run_profile:
        return "unknown"
    p = run_profile.lower()
    if "baseline" in p or "idle" in p or "minimal" in p:
        return "baseline"
    if "interactive" in p:
        return "interactive"
    return "other"


@dataclass(frozen=True)
class AppSummary:
    package_name: str
    display_name: str
    total_runs: int
    valid_runs: int
    invalid_runs: int
    baseline_valid: int
    baseline_extra_valid: int
    interactive_valid: int
    interactive_extra_valid: int
    low_signal_countable_valid: int
    last_status: str
    last_run_id: str
    next_recommended: str
    ml_ready: bool


def _summarize_apps(
    rows: list[PackRow],
    *,
    baseline_required: int,
    interactive_required: int,
    valid_required_total: int,
    app_labels: dict[str, str] | None = None,
) -> list[AppSummary]:
    by_app: dict[str, list[PackRow]] = {}
    for r in rows:
        pkg = r.package_name or "_unknown"
        by_app.setdefault(pkg, []).append(r)
    app_labels = app_labels or {}

    out: list[AppSummary] = []
    for pkg, app_rows in sorted(by_app.items(), key=lambda item: item[0]):
        last = sorted(app_rows, key=lambda r: r.run_id)[-1]

        def _countable(r: PackRow) -> bool:
            return r.countable is not False

        def _extra(r: PackRow) -> bool:
            return r.countable is False

        valid_runs = sum(1 for r in app_rows if _countable(r) and r.valid is True)
        invalid_runs = sum(1 for r in app_rows if _countable(r) and r.valid is False)
        baseline_valid = sum(
            1 for r in app_rows if _countable(r) and r.valid is True and _profile_bucket(r.run_profile) == "baseline"
        )
        interactive_valid = sum(
            1 for r in app_rows if _countable(r) and r.valid is True and _profile_bucket(r.run_profile) == "interactive"
        )
        baseline_extra_valid = sum(
            1 for r in app_rows if _extra(r) and r.valid is True and _profile_bucket(r.run_profile) == "baseline"
        )
        interactive_extra_valid = sum(
            1 for r in app_rows if _extra(r) and r.valid is True and _profile_bucket(r.run_profile) == "interactive"
        )
        low_signal_countable_valid = sum(1 for r in app_rows if _countable(r) and r.valid is True and r.low_signal is True)

        if baseline_valid < baseline_required:
            next_rec = "baseline"
        elif interactive_valid < interactive_required:
            next_rec = "interactive"
        elif valid_runs < valid_required_total:
            next_rec = "either"
        else:
            next_rec = "complete"

        out.append(
            AppSummary(
                package_name=pkg,
                display_name=app_labels.get(pkg, pkg),
                total_runs=len(app_rows),
                valid_runs=valid_runs,
                invalid_runs=invalid_runs,
                baseline_valid=baseline_valid,
                baseline_extra_valid=baseline_extra_valid,
                interactive_valid=interactive_valid,
                interactive_extra_valid=interactive_extra_valid,
                low_signal_countable_valid=low_signal_countable_valid,
                last_status="VALID" if last.valid is True else ("INVALID" if last.valid is False else "UNKNOWN"),
                last_run_id=last.run_id[:8],
                next_recommended=next_rec,
                ml_ready=valid_runs >= 3,
            )
        )
    return out


def run_dynamic_evidence_verify(
    *,
    expect_ml: bool = True,
    write_json: bool = True,
    enrich_db_labels: bool = True,
    show_reason_column: bool = False,
) -> dict[str, Any]:
    """Run the verifier and print an operator-friendly summary.

    Returns the JSON report payload (also written to disk by default).
    """
    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    started_at = datetime.now(UTC).isoformat()

    ghost_dirs: list[str] = []
    failures: list[str] = []
    rows: list[PackRow] = []

    # Deterministic "countable" marking is owned by the dataset tracker (derived
    # from evidence packs). Use it to fill gaps in older manifests that predate
    # the dataset.countable field, and to detect drift if any.
    tracker_countable: dict[str, bool] = {}
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

        tracker = load_dataset_tracker()
        apps = tracker.get("apps") if isinstance(tracker, dict) else {}
        if isinstance(apps, dict):
            for _pkg, entry in apps.items():
                if not isinstance(entry, dict):
                    continue
                for r in entry.get("runs") or []:
                    if not isinstance(r, dict):
                        continue
                    rid = r.get("run_id")
                    if isinstance(rid, str) and rid:
                        c = r.get("countable")
                        if isinstance(c, bool):
                            tracker_countable[rid] = c
    except Exception:
        tracker_countable = {}

    if root.exists():
        packages_seen: set[str] = set()
        for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
            manifest_path = run_dir / "run_manifest.json"
            if not manifest_path.exists():
                ghost_dirs.append(run_dir.name)
                continue

            missing_required = [rel for rel in REQUIRED_FILES if not (run_dir / rel).exists()]
            notes: list[str] = []
            for rel in OPTIONAL_FILES:
                if not (run_dir / rel).exists():
                    notes.append(f"missing_optional:{rel}")

            manifest = _read_json(manifest_path) or {}
            target = manifest.get("target") or {}
            pkg = target.get("package_name") if isinstance(target, dict) else None
            if isinstance(pkg, str) and pkg.strip():
                packages_seen.add(pkg.strip())
            op = manifest.get("operator") or {}
            prof = op.get("run_profile") if isinstance(op, dict) else None

            valid, reason = _dataset_validity(manifest)
            countable = _dataset_countable(manifest)
            if countable is None:
                countable = tracker_countable.get(run_dir.name)
            else:
                t = tracker_countable.get(run_dir.name)
                if isinstance(t, bool) and t != countable:
                    # Prefer the deterministic tracker marking; keep a note so
                    # operators know there is a legacy manifest mismatch.
                    notes.append("countable_mismatch_manifest_vs_tracker")
                    countable = t
            sampling_s = _sampling_duration(manifest)

            pcap_path = _pcap_path_from_manifest(run_dir, manifest)
            pcap_size = pcap_path.stat().st_size if pcap_path and pcap_path.exists() else None

            plan = _read_json(run_dir / "inputs/static_dynamic_plan.json")
            plan_issue = _plan_identity_issue(plan)
            if plan_issue:
                notes.append(plan_issue)

            features = _read_json(run_dir / "analysis/pcap_features.json")
            notes.extend(_ratio_issues(features))

            tls_ratio = None
            quic_ratio = None
            if isinstance(features, dict):
                proxies = features.get("proxies") or {}
                if isinstance(proxies, dict):
                    tls_ratio = _coerce_float(proxies.get("tls_ratio"))
                    quic_ratio = _coerce_float(proxies.get("quic_ratio"))

            if expect_ml:
                ml_summary = run_dir / "analysis" / "ml_provisional" / "v1" / "ml_summary.json"
                if not ml_summary.exists():
                    notes.append("missing_ml:analysis/ml_provisional/v1/ml_summary.json")

            status = "OK"
            if missing_required:
                status = "FAIL"
                notes.append("missing_required:" + ",".join(missing_required))
            elif any(n.startswith("ratio_out_of_bounds") for n in notes) or any(n.startswith("plan_") for n in notes):
                status = "WARN"

            if status == "FAIL":
                failures.append(run_dir.name)

            rows.append(
                PackRow(
                    run_id=run_dir.name,
                    package_name=str(pkg) if isinstance(pkg, str) else None,
                    run_profile=str(prof) if isinstance(prof, str) else None,
                    valid=valid if isinstance(valid, bool) else None,
                    invalid_reason=str(reason) if isinstance(reason, str) else None,
                    countable=countable,
                    low_signal=_dataset_low_signal(manifest),
                    sampling_duration_s=sampling_s,
                    pcap_size_bytes=pcap_size,
                    tls_ratio=tls_ratio,
                    quic_ratio=quic_ratio,
                    status=status,
                    notes=notes,
                )
            )

        app_labels = _load_app_labels(packages_seen) if enrich_db_labels else {}
    else:
        app_labels = {}

    # Print run table.
    headers = ["Run", "App", "Profile", "Valid", "C", "LS", "Samp(s)", "PCAP", "TLS", "QUIC", "St"]
    if show_reason_column:
        headers = ["Run", "App", "Profile", "Valid", "Reason", "C", "LS", "Samp(s)", "PCAP", "TLS", "QUIC", "St"]
    table_rows: list[list[str]] = []
    for r in rows:
        app_name = app_labels.get(r.package_name or "", "") or (r.package_name or "—")
        valid_label = "VALID" if r.valid is True else ("INVALID" if r.valid is False else "—")
        ls_label = "Y" if r.low_signal is True else ("N" if r.low_signal is False else "—")
        table_rows.append(
            ([r.run_id[:8], app_name, r.run_profile or "—", valid_label]
             + ([r.invalid_reason or "—"] if show_reason_column else [])
             + [
                "Y" if r.countable is True else ("N" if r.countable is False else "—"),
                ls_label,
                f"{r.sampling_duration_s:.0f}" if r.sampling_duration_s else "—",
                _fmt_bytes(r.pcap_size_bytes),
                f"{r.tls_ratio:.2f}" if r.tls_ratio is not None else "—",
                f"{r.quic_ratio:.2f}" if r.quic_ratio is not None else "—",
                r.status,
            ])
        )
    # Keep "App" readable; use DB display_name when available.
    max_widths = {1: 22, 2: 14}
    if show_reason_column:
        max_widths[4] = 22
        right_align = {7, 8, 9, 10}
    else:
        right_align = {6, 7, 8, 9}
    _render_table(headers, table_rows, max_widths=max_widths, right_align=right_align)

    # Per-app summary.
    # Do not read env vars in deep tooling; keep this derived from config defaults.
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

        cfg = DatasetTrackerConfig()
        baseline_required = int(cfg.baseline_required)
        interactive_required = int(cfg.interactive_required)
        valid_required_total = int(cfg.repeats_per_app)
    except Exception:
        baseline_required = 1
        interactive_required = 2
        valid_required_total = 3
    apps = _summarize_apps(
        rows,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        valid_required_total=valid_required_total,
        app_labels=app_labels,
    )

    print()
    print("Per-app summary")
    print("---------------")
    app_headers = ["App", "Baseline", "Interactive", "Need", "Valid", "LS", "Runs", "Last", "Next", "ML"]
    app_rows: list[list[str]] = []
    for a in apps:
        need_parts: list[str] = []
        need_base = max(0, baseline_required - int(a.baseline_valid))
        need_inter = max(0, interactive_required - int(a.interactive_valid))
        if need_base:
            need_parts.append(f"B{need_base}")
        if need_inter:
            need_parts.append(f"I{need_inter}")
        need_label = " ".join(need_parts) if need_parts else "0"
        base_label = (
            str(a.baseline_valid)
            if a.baseline_extra_valid <= 0
            else f"{a.baseline_valid}(+{a.baseline_extra_valid})"
        )
        inter_label = (
            str(a.interactive_valid)
            if a.interactive_extra_valid <= 0
            else f"{a.interactive_valid}(+{a.interactive_extra_valid})"
        )
        app_rows.append(
            [
                a.display_name,
                base_label,
                inter_label,
                need_label,
                str(a.valid_runs),
                str(a.low_signal_countable_valid),
                str(a.total_runs),
                a.last_status,
                a.next_recommended,
                "READY" if a.ml_ready else "WAIT",
            ]
        )
    _render_table(app_headers, app_rows, max_widths={0: 28}, right_align={1, 2, 3, 4, 5, 6})

    # Suggested next actions.
    need_base = [a.display_name for a in apps if a.baseline_valid < baseline_required]
    need_inter = [
        a.display_name
        for a in apps
        if a.baseline_valid >= baseline_required and a.interactive_valid < interactive_required
    ]
    complete = [a.display_name for a in apps if a.next_recommended == "complete"]

    print()
    print("Suggested next actions")
    print("----------------------")
    if need_base:
        print("Baseline runs needed: " + ", ".join(need_base))
    if need_inter:
        print("Interactive runs needed: " + ", ".join(need_inter))
    if complete:
        print("Quota met (optional extra runs): " + ", ".join(complete))
    if not (need_base or need_inter or complete):
        print("No actions suggested.")

    print()
    print(f"[VERIFY] packs={len(rows)} ghosts={len(ghost_dirs)} failures={len(failures)} started={started_at}")
    if ghost_dirs:
        print("[VERIFY] Ghost dirs (no run_manifest.json): " + ", ".join(ghost_dirs))
    if failures:
        print("[VERIFY] FAIL packs: " + ", ".join(failures))

    report: dict[str, Any] = {
        "generated_at": started_at,
        "packs": [
            {
                "run_id": r.run_id,
                "package_name": r.package_name,
                "display_name": app_labels.get(r.package_name or "", None),
                "run_profile": r.run_profile,
                "valid_dataset_run": r.valid,
                "invalid_reason_code": r.invalid_reason,
                "countable": r.countable,
                "low_signal": r.low_signal,
                "sampling_duration_seconds": r.sampling_duration_s,
                "pcap_size_bytes": r.pcap_size_bytes,
                "tls_ratio": r.tls_ratio,
                "quic_ratio": r.quic_ratio,
                "status": r.status,
                "notes": r.notes,
            }
            for r in rows
        ],
        "ghost_dirs": ghost_dirs,
        "failures": failures,
    }

    if write_json:
        out_dir = Path(app_config.OUTPUT_DIR) / "batches" / "dynamic"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = out_dir / f"verify-dynamic-evidence-{stamp}.json"
        dest.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[VERIFY] Report written: {dest}")
    return report


def run_dynamic_evidence_quick_check(*, enrich_db_labels: bool = True) -> dict[str, Any]:
    """Run a compact operator health check (packs/missing/bad + PCAP sizes).

    This intentionally mirrors the ad-hoc shell one-liners operators used during
    Phase D hardening, but is now a first-class menu action.
    """
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import verify_dynamic_evidence_packs

    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    report = verify_dynamic_evidence_packs(root, dataset_only=False)

    runs = report.get("runs") or []
    packs = len(runs) if isinstance(runs, list) else 0

    missing_codes = {"missing_frozen_input", "pcap_artifact_missing", "pcap_file_missing"}
    missing = 0
    bad = 0
    if isinstance(runs, list):
        for r in runs:
            if not isinstance(r, dict):
                continue
            issues = r.get("issues") or []
            if not isinstance(issues, list):
                continue
            codes = {i.get("code") for i in issues if isinstance(i, dict)}
            if any(c in missing_codes for c in codes):
                missing += 1
            if issues:
                bad += 1

    # Optional DB enrichment: map package -> display name for readability.
    packages: set[str] = set()
    if isinstance(runs, list):
        for r in runs:
            if isinstance(r, dict) and isinstance(r.get("package_name"), str):
                packages.add(r["package_name"])
    labels = _load_app_labels(packages) if enrich_db_labels else {}

    print()
    print("Dynamic Evidence Quick Check")
    print("----------------------------")
    print(f"packs    : {packs}")
    print(f"missing  : {missing}")
    print(f"bad      : {bad}")
    if packs:
        valid_cnt = 0
        invalid_cnt = 0
        for r in runs if isinstance(runs, list) else []:
            if not isinstance(r, dict):
                continue
            if r.get("valid_dataset_run") is True:
                valid_cnt += 1
            elif r.get("valid_dataset_run") is False:
                invalid_cnt += 1
        print(f"valid    : {valid_cnt}")
        print(f"invalid  : {invalid_cnt}")

    # If this is a dataset collection workspace, show which dataset apps have no runs yet.
    try:
        from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages

        dataset_pkgs = {p.strip() for p in load_profile_packages("RESEARCH_DATASET_ALPHA") if str(p).strip()}
    except Exception:
        dataset_pkgs = set()
    if dataset_pkgs:
        present = {p for p in packages if p in dataset_pkgs}
        missing_apps = sorted([p for p in dataset_pkgs if p not in present])
        print(f"dataset  : {len(present)}/{len(dataset_pkgs)} apps have >=1 run")
        if missing_apps:
            preview = ", ".join(labels.get(p, p) for p in missing_apps[:8])
            suffix = " ..." if len(missing_apps) > 8 else ""
            print(f"no runs  : {preview}{suffix}")

    # Compact run table (more useful than a raw list). Includes transport-mix ratios when present.
    if root.exists():
        headers = ["Run", "App", "Profile", "Valid", "Samp(s)", "PCAP", "TLS", "QUIC"]
        rows = []
        sizes: list[int] = []
        samp_list: list[float] = []
        for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
            manifest_path = run_dir / "run_manifest.json"
            if not manifest_path.exists():
                continue
            manifest = _read_json(manifest_path) or {}
            target = manifest.get("target") or {}
            pkg = target.get("package_name") if isinstance(target, dict) else None
            pkg = pkg.strip() if isinstance(pkg, str) else None
            app = labels.get(pkg or "", "") or (pkg or "—")
            op = manifest.get("operator") or {}
            prof = op.get("run_profile") if isinstance(op, dict) else None
            valid, reason = _dataset_validity(manifest)
            ds = _dataset_block(manifest) or {}
            samp = _coerce_float(ds.get("sampling_duration_seconds")) if isinstance(ds, dict) else None
            if isinstance(samp, (int, float)) and samp >= 0:
                samp_list.append(float(samp))

            pcap_path = _pcap_path_from_manifest(run_dir, manifest)
            size = pcap_path.stat().st_size if pcap_path and pcap_path.exists() else None
            if isinstance(size, int) and size >= 0:
                sizes.append(size)
            rid = str(manifest.get("dynamic_run_id") or run_dir.name)[:8]

            tls_ratio = "—"
            quic_ratio = "—"
            feats = _read_json(run_dir / "analysis/pcap_features.json")
            if isinstance(feats, dict):
                proxies = feats.get("proxies") or {}
                if isinstance(proxies, dict):
                    tr = _coerce_float(proxies.get("tls_ratio"))
                    qr = _coerce_float(proxies.get("quic_ratio"))
                    if tr is not None:
                        tls_ratio = f"{tr:.2f}"
                    if qr is not None:
                        quic_ratio = f"{qr:.2f}"

            valid_label = "VALID" if valid is True else ("INVALID" if valid is False else "—")
            if valid is False and isinstance(reason, str) and reason:
                valid_label = "INVALID"
            rows.append(
                [
                    rid,
                    app,
                    str(prof or "—"),
                    valid_label,
                    f"{samp:.0f}" if samp is not None else "—",
                    _fmt_bytes(size),
                    tls_ratio,
                    quic_ratio,
                ]
            )
        _render_table(headers, rows, max_widths={1: 18, 2: 16}, right_align={4, 5, 6, 7})

        if sizes:
            sizes_sorted = sorted(sizes)
            smallest = sizes_sorted[0]
            median = sizes_sorted[len(sizes_sorted) // 2]
            largest = sizes_sorted[-1]
            print()
            print(f"pcap_min : {_fmt_bytes(smallest)}")
            print(f"pcap_med : {_fmt_bytes(median)}")
            print(f"pcap_max : {_fmt_bytes(largest)}")
        if samp_list:
            samp_sorted = sorted(samp_list)
            smallest = samp_sorted[0]
            median = samp_sorted[len(samp_sorted) // 2]
            largest = samp_sorted[-1]
            print(f"samp_min : {smallest:.0f}s")
            print(f"samp_med : {median:.0f}s")
            print(f"samp_max : {largest:.0f}s")

    return report


def run_dynamic_evidence_deep_checks(
    *,
    enrich_db_labels: bool = True,
    write_outputs: bool = True,
) -> dict[str, Any]:
    """Deep verification checks (DB reality + transport mix + indicator quality).

    - DB check: ensure manifest environment.db_persistence.ok matches DB reality.
    - Transport check: recompute ratios from pcap_report protocol_hierarchy and
      compare to pcap_features proxies.
    - Indicator quality: compute junk rate and top1 dominance from top_dns/top_sni.
    """
    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    started_at = datetime.now(UTC).isoformat()

    manifests = sorted(root.glob("*/run_manifest.json")) if root.exists() else []
    packs: list[dict[str, Any]] = []
    pkgs: set[str] = set()
    for mf in manifests:
        m = _read_json(mf)
        if not isinstance(m, dict):
            continue
        rid = str(m.get("dynamic_run_id") or mf.parent.name)
        target = m.get("target") if isinstance(m.get("target"), dict) else {}
        pkg = str((target or {}).get("package_name") or "").strip()
        if pkg:
            pkgs.add(pkg)
        packs.append({"run_id": rid, "run_dir": str(mf.parent), "manifest": m})

    labels = _load_app_labels(pkgs) if enrich_db_labels else {}

    # DB reality check (best-effort).
    db_available = False
    db_ids: set[str] = set()
    try:
        from scytaledroid.Database.db_core import run_sql

        db_available = True
        if packs:
            placeholders = ",".join(["%s"] * len(packs))
            rows = run_sql(
                f"SELECT dynamic_run_id FROM dynamic_sessions WHERE dynamic_run_id IN ({placeholders})",
                tuple(p["run_id"] for p in packs),
                fetch="all",
            )
            db_ids = {r[0] for r in rows or []}
    except Exception:
        db_available = False
        db_ids = set()

    db_mismatch: list[dict[str, Any]] = []
    db_notes: list[dict[str, Any]] = []
    ratio_mismatch: list[dict[str, Any]] = []
    indicator_warnings: list[dict[str, Any]] = []
    ml_audit_rows = _load_ml_audit_rows()
    ml_audit_summary: dict[str, Any] = {}

    if ml_audit_rows:
        warnings = [
            r for r in ml_audit_rows
            if str(r.get("training_samples_warning") or "").lower() in {"1", "true", "yes"}
            or str(r.get("threshold_equals_max") or "").lower() in {"1", "true", "yes"}
            or str(r.get("training_mode") or "") == "union_fallback"
        ]
        ml_audit_summary = {
            "rows": len(ml_audit_rows),
            "warnings": len(warnings),
            "union_fallback": sum(1 for r in ml_audit_rows if str(r.get("training_mode") or "") == "union_fallback"),
            "training_samples_warning": sum(
                1 for r in ml_audit_rows if str(r.get("training_samples_warning") or "").lower() in {"1", "true", "yes"}
            ),
            "threshold_equals_max": sum(
                1 for r in ml_audit_rows if str(r.get("threshold_equals_max") or "").lower() in {"1", "true", "yes"}
            ),
            "feature_transform": sorted({str(r.get("feature_transform") or "") for r in ml_audit_rows if r.get("feature_transform")}),
            "feature_scaling": sorted({str(r.get("feature_scaling") or "") for r in ml_audit_rows if r.get("feature_scaling")}),
        }

    for p in packs:
        rid = str(p["run_id"])
        run_dir = Path(str(p["run_dir"]))
        m = p["manifest"]
        target = m.get("target") if isinstance(m.get("target"), dict) else {}
        pkg = str((target or {}).get("package_name") or "").strip() or "_unknown"
        app = labels.get(pkg, pkg)

        env = m.get("environment") if isinstance(m.get("environment"), dict) else {}
        dbp = (env or {}).get("db_persistence") if isinstance(env, dict) else None
        if db_available and isinstance(dbp, dict):
            attempted = bool(dbp.get("attempted"))
            ok = bool(dbp.get("ok"))
            in_db = rid in db_ids

            # True inconsistencies:
            # - manifest says persistence OK but DB doesn't have the session row (DB loss / wrong DB).
            if ok and not in_db:
                db_mismatch.append({"run_id": rid[:8], "app": app, "issue": "manifest_ok_but_missing_in_db"})

            # Common, non-blocking situations:
            # - manifest recorded a runtime persistence failure, but the run was indexed later from evidence packs.
            # - manifest has no runtime persistence attempt, but the run exists in the DB because it was indexed later.
            if (not ok) and in_db:
                issue = "indexed_later_after_runtime_failure" if attempted else "indexed_from_evidence_only"
                db_notes.append({"run_id": rid[:8], "app": app, "issue": issue})
        elif db_available and not isinstance(dbp, dict):
            db_mismatch.append({"run_id": rid[:8], "app": app, "issue": "missing_manifest_db_persistence_block"})

        report = _read_json(run_dir / "analysis/pcap_report.json") or {}
        feats = _read_json(run_dir / "analysis/pcap_features.json") or {}
        proxies = feats.get("proxies") if isinstance(feats, dict) else None
        if isinstance(report, dict) and isinstance(proxies, dict):
            expected = _compute_transport_mix_from_report(report)
            for k, exp in expected.items():
                got = _coerce_float(proxies.get(k))
                if exp is None or got is None:
                    continue
                if abs(float(exp) - float(got)) > _RATIO_TOLERANCE:
                    ratio_mismatch.append(
                        {"run_id": rid[:8], "app": app, "key": k, "expected": exp, "got": got}
                    )

            dns_stats = _top_list_stats(report.get("top_dns"))
            sni_stats = _top_list_stats(report.get("top_sni"))
            junk_rate = 0.0
            denom = 0
            for st in (dns_stats, sni_stats):
                if st.get("junk_rate") is not None:
                    junk_rate += float(st["junk_rate"])
                    denom += 1
            avg_junk_rate = (junk_rate / float(denom)) if denom else None
            warn = False
            # Heuristics for operator QA: not gating; just signals.
            if avg_junk_rate is not None and avg_junk_rate >= 0.10:
                warn = True
            dns_top1 = dns_stats.get("top1_share")
            sni_top1 = sni_stats.get("top1_share")
            if (dns_top1 is not None and float(dns_top1) >= 0.85) or (sni_top1 is not None and float(sni_top1) >= 0.85):
                warn = True
            if warn:
                indicator_warnings.append(
                    {
                        "run_id": rid[:8],
                        "app": app,
                        "dns_top1": dns_top1,
                        "sni_top1": sni_top1,
                        "dns_junk_rate": dns_stats.get("junk_rate"),
                        "sni_junk_rate": sni_stats.get("junk_rate"),
                        "dns_junk_samples": dns_stats.get("junk_samples"),
                        "sni_junk_samples": sni_stats.get("junk_samples"),
                    }
                )

    print()
    print("Dynamic Evidence Deep Checks")
    print("----------------------------")
    print(f"packs           : {len(packs)}")
    print(f"db_available    : {int(db_available)}")
    print(f"db_mismatches   : {len(db_mismatch)}")
    print(f"db_notes        : {len(db_notes)}")
    print(f"ratio_mismatches: {len(ratio_mismatch)} (tolerance={_RATIO_TOLERANCE})")
    print(f"indicator_warns : {len(indicator_warnings)}")
    if db_mismatch:
        print()
        print("DB mismatches (sample)")
        for x in db_mismatch[:10]:
            print(f"- {x['run_id']} {x['app']}: {x['issue']}")
    if db_notes:
        print()
        print("DB notes (sample)")
        for x in db_notes[:10]:
            print(f"- {x['run_id']} {x['app']}: {x['issue']}")
    if ratio_mismatch:
        print()
        print("Transport ratio mismatches (sample)")
        for x in ratio_mismatch[:10]:
            print(f"- {x['run_id']} {x['app']}: {x['key']} expected={x['expected']:.3f} got={x['got']:.3f}")
    if indicator_warnings:
        print()
        print("Indicator quality warnings (sample)")
        for x in indicator_warnings[:10]:
            print(
                f"- {x['run_id']} {x['app']}: "
                f"dns_top1={x['dns_top1']} sni_top1={x['sni_top1']} "
                f"dns_junk_rate={x['dns_junk_rate']} sni_junk_rate={x['sni_junk_rate']}"
            )
    if ml_audit_rows:
        print()
        print("ML audit summary")
        print("----------------")
        print(f"rows                : {ml_audit_summary.get('rows', 0)}")
        print(f"union_fallback       : {ml_audit_summary.get('union_fallback', 0)}")
        print(f"training_warn        : {ml_audit_summary.get('training_samples_warning', 0)}")
        print(f"threshold_equals_max : {ml_audit_summary.get('threshold_equals_max', 0)}")
        if ml_audit_summary.get("feature_transform"):
            print(f"feature_transform    : {', '.join(ml_audit_summary['feature_transform'])}")
        if ml_audit_summary.get("feature_scaling"):
            print(f"feature_scaling      : {', '.join(ml_audit_summary['feature_scaling'])}")

    report = {
        "generated_at": started_at,
        "packs": len(packs),
        "db_available": db_available,
        "db_mismatches": db_mismatch,
        "db_notes": db_notes,
        "ratio_mismatches": ratio_mismatch,
        "indicator_warnings": indicator_warnings,
        "ml_audit_summary": ml_audit_summary,
    }
    if write_outputs:
        out_dir = Path(app_config.OUTPUT_DIR) / "batches" / "dynamic"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = out_dir / f"deep-check-dynamic-evidence-{stamp}.json"
        dest.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[DEEP] Report written: {dest}")
    return report


__all__ = ["run_dynamic_evidence_verify", "run_dynamic_evidence_quick_check", "run_dynamic_evidence_deep_checks"]
