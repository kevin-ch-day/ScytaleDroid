"""CLI helper for verifying dynamic evidence packs (Paper #2).

This is an operator-facing wrapper around evidence-pack inspection logic.
It can optionally enrich output with app labels from the DB, but remains safe to
run DB-free (air-gapped) by disabling enrichment.
"""

from __future__ import annotations

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


def _truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


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


@dataclass(frozen=True)
class PackRow:
    run_id: str
    package_name: str | None
    run_profile: str | None
    valid: bool | None
    invalid_reason: str | None
    countable: bool | None
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
    op = manifest.get("operator") or {}
    if isinstance(op, dict):
        legacy = op.get("dataset_validity")
        if isinstance(legacy, dict):
            return legacy.get("valid_dataset_run"), legacy.get("invalid_reason_code")
    return None, None


def _dataset_countable(manifest: dict[str, Any]) -> bool | None:
    ds = _dataset_block(manifest)
    if ds is not None:
        v = ds.get("countable")
        return v if isinstance(v, bool) else None
    op = manifest.get("operator") or {}
    if isinstance(op, dict):
        legacy = op.get("dataset_validity")
        if isinstance(legacy, dict):
            v = legacy.get("countable")
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
    interactive_valid: int
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

        valid_runs = sum(1 for r in app_rows if _countable(r) and r.valid is True)
        invalid_runs = sum(1 for r in app_rows if _countable(r) and r.valid is False)
        baseline_valid = sum(
            1 for r in app_rows if _countable(r) and r.valid is True and _profile_bucket(r.run_profile) == "baseline"
        )
        interactive_valid = sum(
            1
            for r in app_rows
            if _countable(r) and r.valid is True and _profile_bucket(r.run_profile) == "interactive"
        )

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
                interactive_valid=interactive_valid,
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
    headers = ["Run", "App", "Profile", "Valid", "C", "Samp(s)", "PCAP", "TLS", "QUIC", "St"]
    if show_reason_column:
        headers = ["Run", "App", "Profile", "Valid", "Reason", "C", "Samp(s)", "PCAP", "TLS", "QUIC", "St"]
    table_rows: list[list[str]] = []
    for r in rows:
        app_name = app_labels.get(r.package_name or "", "") or (r.package_name or "—")
        valid_label = "VALID" if r.valid is True else ("INVALID" if r.valid is False else "—")
        table_rows.append(
            ([r.run_id[:8], app_name, r.run_profile or "—", valid_label]
             + ([r.invalid_reason or "—"] if show_reason_column else [])
             + [
                "Y" if r.countable is True else ("N" if r.countable is False else "—"),
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
        right_align = {6, 7, 8, 9}
    else:
        right_align = {5, 6, 7, 8}
    _render_table(headers, table_rows, max_widths=max_widths, right_align=right_align)

    # Per-app summary.
    baseline_required = int(os.environ.get("SCYTALEDROID_DATASET_BASELINE_RUNS") or 1)
    interactive_required = int(os.environ.get("SCYTALEDROID_DATASET_INTERACTIVE_RUNS") or 2)
    valid_required_total = int(os.environ.get("SCYTALEDROID_DATASET_VALID_RUNS_PER_APP") or 3)
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
    app_headers = ["App", "Base", "Int", "Valid", "Runs", "Last", "Next", "ML"]
    app_rows: list[list[str]] = []
    for a in apps:
        app_rows.append(
            [
                a.display_name,
                f"{a.baseline_valid}/{baseline_required}",
                f"{a.interactive_valid}/{interactive_required}",
                str(a.valid_runs),
                str(a.total_runs),
                a.last_status,
                a.next_recommended,
                "READY" if a.ml_ready else "WAIT",
            ]
        )
    _render_table(app_headers, app_rows, max_widths={0: 28}, right_align={1, 2, 3, 4})

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
    print(
        f"[VERIFY] packs={len(rows)} ghosts={len(ghost_dirs)} failures={len(failures)} started={started_at}"
    )
    if ghost_dirs:
        print("[VERIFY] Ghost dirs (no run_manifest.json): " + ", ".join(ghost_dirs))
    if failures:
        print("[VERIFY] FAIL packs: " + ", ".join(failures))

    report: dict[str, Any] = {
        "generated_at": started_at,
        "root": str(root),
        "packs": [
            {
                "run_id": r.run_id,
                "package_name": r.package_name,
                "display_name": app_labels.get(r.package_name or "", "") if enrich_db_labels else None,
                "run_profile": r.run_profile,
                "valid_dataset_run": r.valid,
                "invalid_reason_code": r.invalid_reason,
                "countable": r.countable,
                "sampling_duration_seconds": r.sampling_duration_s,
                "pcap_size_bytes": r.pcap_size_bytes,
                "tls_ratio": r.tls_ratio,
                "quic_ratio": r.quic_ratio,
                "status": r.status,
                "notes": list(r.notes),
            }
            for r in rows
        ],
        "apps": [
            {
                "package_name": a.package_name,
                "display_name": a.display_name,
                "total_runs": a.total_runs,
                "valid_runs": a.valid_runs,
                "invalid_runs": a.invalid_runs,
                "baseline_valid": a.baseline_valid,
                "interactive_valid": a.interactive_valid,
                "last_status": a.last_status,
                "last_run_id": a.last_run_id,
                "next_recommended": a.next_recommended,
                "ml_ready": a.ml_ready,
            }
            for a in apps
        ],
        "quota": {
            "baseline_required": baseline_required,
            "interactive_required": interactive_required,
            "valid_required_total": valid_required_total,
        },
        "ghost_dirs": list(ghost_dirs),
        "failures": list(failures),
    }

    if write_json:
        out_dir = Path(app_config.OUTPUT_DIR) / "batches" / "dynamic"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        report_path = out_dir / f"verify-dynamic-evidence-{stamp}.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[VERIFY] Report written: {report_path}")

    return report


__all__ = ["run_dynamic_evidence_verify"]
