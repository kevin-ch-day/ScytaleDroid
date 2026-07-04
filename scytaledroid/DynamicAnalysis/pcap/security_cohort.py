"""Cohort-level PCAP security analysis from cached security_surface artifacts."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.pcap.security_surface import (
    compute_static_dynamic_cleartext_posture,
    rehydrate_security_surface,
    render_security_review_md,
)


@dataclass(frozen=True)
class CohortSecurityRunRow:
    run_id: str
    package_name: str | None
    app_label: str | None
    run_profile: str | None
    valid_dataset_run: bool | None
    surface_status: str | None
    visibility_class: str | None
    http_observed: bool | None
    cleartext_protocol_observed: bool | None
    plaintext_protocols: str
    decoded_protocols: str
    decoded_stream_count: int | None
    finding_count: int | None
    mismatch_class: str | None
    risk_flags: str


@dataclass
class CohortSecuritySummary:
    generated_at: str
    evidence_root: str
    runs_scanned: int = 0
    surface_ok: int = 0
    surface_missing: int = 0
    cleartext_surface_runs: int = 0
    http_metadata_runs: int = 0
    xmpp_cleartext_runs: int = 0
    mismatch_denied_observed: int = 0
    mismatch_allowed_not_observed: int = 0
    visibility_counts: dict[str, int] = field(default_factory=dict)
    mismatch_counts: dict[str, int] = field(default_factory=dict)
    plaintext_protocol_counts: dict[str, int] = field(default_factory=dict)
    risk_flag_counts: dict[str, int] = field(default_factory=dict)
    rows: list[CohortSecurityRunRow] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "evidence_root": self.evidence_root,
            "runs_scanned": self.runs_scanned,
            "surface_ok": self.surface_ok,
            "surface_missing": self.surface_missing,
            "cleartext_surface_runs": self.cleartext_surface_runs,
            "http_metadata_runs": self.http_metadata_runs,
            "xmpp_cleartext_runs": self.xmpp_cleartext_runs,
            "mismatch_denied_observed": self.mismatch_denied_observed,
            "mismatch_allowed_not_observed": self.mismatch_allowed_not_observed,
            "visibility_counts": dict(self.visibility_counts),
            "mismatch_counts": dict(self.mismatch_counts),
            "plaintext_protocol_counts": dict(self.plaintext_protocol_counts),
            "risk_flag_counts": dict(self.risk_flag_counts),
            "rows": [row.__dict__ for row in self.rows],
        }


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _manifest_from_run_dir(run_dir: Path) -> dict[str, Any]:
    return _read_json(run_dir / "run_manifest.json") or {}


def refresh_run_security_derivatives(run_dir: Path, *, apply: bool = True) -> str:
    """Rehydrate findings/review/features/overlap from cached security_surface.json (no tshark)."""
    from scytaledroid.DynamicAnalysis.pcap.correlate import write_static_dynamic_overlap
    from scytaledroid.DynamicAnalysis.pcap.features import write_pcap_features
    from scytaledroid.DynamicAnalysis.pcap.security_backfill import _manifest_from_json

    surface_path = run_dir / "analysis" / "security_surface.json"
    surface = _read_json(surface_path)
    if not surface:
        return "missing_surface"
    surface = rehydrate_security_surface(surface)
    manifest_data = _manifest_from_run_dir(run_dir)
    if not manifest_data:
        return "missing_manifest"
    manifest = _manifest_from_json(manifest_data)
    target = manifest.target if isinstance(manifest.target, dict) else {}
    package_label = str(
        target.get("display_name") or target.get("app_label") or target.get("package_name") or ""
    ).strip()
    report_path = run_dir / "analysis" / "pcap_report.json"
    report = _read_json(report_path) or {}
    if not apply:
        return "dry_run"
    surface_path.write_text(json.dumps(surface, indent=2, sort_keys=True), encoding="utf-8")
    report["security_surface"] = surface
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    (run_dir / "analysis" / "security_review.md").write_text(
        render_security_review_md(
            surface,
            package_name=package_label or None,
            dynamic_run_id=manifest.dynamic_run_id or run_dir.name,
        ),
        encoding="utf-8",
    )
    write_pcap_features(manifest, run_dir)
    write_static_dynamic_overlap(manifest, run_dir)
    return "ok"


def analyze_security_cohort(
    evidence_root: Path,
    *,
    run_ids: tuple[str, ...] = (),
) -> CohortSecuritySummary:
    summary = CohortSecuritySummary(
        generated_at=datetime.now(UTC).isoformat(),
        evidence_root=str(evidence_root.resolve()),
    )
    if not evidence_root.exists():
        return summary

    run_dirs = sorted([path for path in evidence_root.iterdir() if path.is_dir()], key=lambda p: p.name)
    if run_ids:
        wanted = {item.strip() for item in run_ids if item.strip()}
        run_dirs = [path for path in run_dirs if path.name in wanted]

    for run_dir in run_dirs:
        if not (run_dir / "run_manifest.json").exists():
            continue
        summary.runs_scanned += 1
        manifest = _manifest_from_run_dir(run_dir)
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        package_name = str(target.get("package_name") or "").strip() or None
        app_label = str(target.get("display_name") or target.get("app_label") or package_name or "").strip() or None
        run_id = str(manifest.get("dynamic_run_id") or run_dir.name)
        run_profile = str(operator.get("run_profile") or "").strip() or None
        valid = dataset.get("valid_dataset_run")
        valid_bool = valid if isinstance(valid, bool) else None

        surface = _read_json(run_dir / "analysis" / "security_surface.json")
        if not isinstance(surface, dict) or surface.get("status") != "ok":
            embedded = _read_json(run_dir / "analysis" / "pcap_report.json")
            if isinstance(embedded, dict):
                surface = embedded.get("security_surface")
        if not isinstance(surface, dict) or surface.get("status") != "ok":
            summary.surface_missing += 1
            summary.rows.append(
                CohortSecurityRunRow(
                    run_id=run_id,
                    package_name=package_name,
                    app_label=app_label,
                    run_profile=run_profile,
                    valid_dataset_run=valid_bool,
                    surface_status="missing",
                    visibility_class=None,
                    http_observed=None,
                    cleartext_protocol_observed=None,
                    plaintext_protocols="",
                    decoded_protocols="",
                    decoded_stream_count=None,
                    finding_count=None,
                    mismatch_class=None,
                    risk_flags="",
                )
            )
            continue

        summary.surface_ok += 1
        surface = rehydrate_security_surface(surface)
        cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
        visibility = str(cleartext.get("visibility_class") or "")
        summary.visibility_counts[visibility] = summary.visibility_counts.get(visibility, 0) + 1
        if visibility == "cleartext_surface_present":
            summary.cleartext_surface_runs += 1
        if cleartext.get("http_observed"):
            summary.http_metadata_runs += 1
        plain_protocols = cleartext.get("plaintext_protocols_observed") or []
        for protocol in plain_protocols:
            key = str(protocol)
            summary.plaintext_protocol_counts[key] = summary.plaintext_protocol_counts.get(key, 0) + 1
            if key == "xmpp":
                summary.xmpp_cleartext_runs += 1
        for flag in surface.get("risk_flags") or []:
            text = str(flag)
            summary.risk_flag_counts[text] = summary.risk_flag_counts.get(text, 0) + 1

        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json")
        report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
        mismatch_class = None
        if isinstance(plan, dict):
            mismatch_class = compute_static_dynamic_cleartext_posture(
                plan,
                {**report, "security_surface": surface},
            ).get("mismatch_class")
        if mismatch_class:
            summary.mismatch_counts[str(mismatch_class)] = summary.mismatch_counts.get(str(mismatch_class), 0) + 1
            if mismatch_class == "denied_but_observed":
                summary.mismatch_denied_observed += 1
            elif str(mismatch_class).startswith("allowed_not_observed"):
                summary.mismatch_allowed_not_observed += 1

        summary.rows.append(
            CohortSecurityRunRow(
                run_id=run_id,
                package_name=package_name,
                app_label=app_label,
                run_profile=run_profile,
                valid_dataset_run=valid_bool,
                surface_status="ok",
                visibility_class=visibility or None,
                http_observed=bool(cleartext.get("http_observed")),
                cleartext_protocol_observed=bool(cleartext.get("cleartext_protocol_observed")),
                plaintext_protocols=";".join(str(item) for item in plain_protocols),
                decoded_protocols=";".join(str(item) for item in (cleartext.get("decoded_protocols_observed") or [])),
                decoded_stream_count=int(cleartext.get("decoded_stream_count") or 0),
                finding_count=int(surface.get("finding_count") or 0),
                mismatch_class=str(mismatch_class) if mismatch_class else None,
                risk_flags=";".join(str(flag) for flag in (surface.get("risk_flags") or [])),
            )
        )
    return summary


def render_cohort_security_review_md(summary: CohortSecuritySummary) -> str:
    lines = [
        "# Cohort PCAP Security Review (metadata)",
        "",
        f"Generated: {summary.generated_at}",
        f"Evidence root: `{summary.evidence_root}`",
        "",
        "## Cohort totals",
        f"- Runs scanned: {summary.runs_scanned}",
        f"- Security surface OK: {summary.surface_ok}",
        f"- Missing surface: {summary.surface_missing}",
        f"- Cleartext surface present: {summary.cleartext_surface_runs}",
        f"- HTTP metadata observed: {summary.http_metadata_runs}",
        f"- XMPP cleartext signals: {summary.xmpp_cleartext_runs}",
        f"- Static denies but dynamic cleartext observed: {summary.mismatch_denied_observed}",
        f"- Static allows but no cleartext observed (encrypted capture): {summary.mismatch_allowed_not_observed}",
        "",
        "## Plaintext protocol prevalence",
    ]
    if summary.plaintext_protocol_counts:
        for protocol, count in sorted(summary.plaintext_protocol_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- `{protocol}`: {count} run(s)")
    else:
        lines.append("- none")
    lines.extend(["", "## Top risk flags"])
    if summary.risk_flag_counts:
        for flag, count in sorted(summary.risk_flag_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:12]:
            lines.append(f"- `{flag}`: {count}")
    else:
        lines.append("- none")
    lines.extend(["", "## Cleartext policy mismatches (denied but observed)"])
    denied = [row for row in summary.rows if row.mismatch_class == "denied_but_observed"]
    if denied:
        for row in denied:
            lines.append(
                f"- `{row.run_id[:8]}` **{row.app_label or row.package_name}** "
                f"protocols={row.plaintext_protocols or row.decoded_protocols or 'unknown'} "
                f"findings={row.finding_count}"
            )
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def build_app_security_rollup(rows: list[CohortSecurityRunRow]) -> list[dict[str, Any]]:
    grouped: dict[str, list[CohortSecurityRunRow]] = defaultdict(list)
    for row in rows:
        if row.package_name:
            grouped[row.package_name].append(row)
    out: list[dict[str, Any]] = []
    for package, package_rows in sorted(grouped.items()):
        app_label = next((r.app_label for r in package_rows if r.app_label), package)
        out.append(
            {
                "package": package,
                "app_label": app_label,
                "runs_scanned": len(package_rows),
                "surface_ok_runs": sum(1 for r in package_rows if r.surface_status == "ok"),
                "cleartext_surface_runs": sum(1 for r in package_rows if r.visibility_class == "cleartext_surface_present"),
                "http_metadata_runs": sum(1 for r in package_rows if r.http_observed),
                "xmpp_cleartext_runs": sum(1 for r in package_rows if "xmpp" in r.plaintext_protocols),
                "denied_but_observed_runs": sum(1 for r in package_rows if r.mismatch_class == "denied_but_observed"),
                "avg_finding_count": round(
                    sum(r.finding_count or 0 for r in package_rows) / float(len(package_rows)),
                    2,
                ),
                "top_risk_flags": ";".join(
                    flag
                    for flag, _count in Counter(
                        flag
                        for r in package_rows
                        for flag in (r.risk_flags or "").split(";")
                        if flag
                    ).most_common(5)
                ),
            }
        )
    return out


def generate_cohort_security_report(
    *,
    evidence_root: Path | None = None,
    output_dir: Path | None = None,
    run_ids: tuple[str, ...] = (),
    refresh_derived: bool = False,
    apply_refresh: bool = False,
) -> dict:
    from scytaledroid.Config import app_config

    root = evidence_root or (Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic")
    out = output_dir or (
        Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_pcap_security_cohort" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    )
    out.mkdir(parents=True, exist_ok=True)
    refresh_stats = {"ok": 0, "skipped": 0}
    if refresh_derived:
        run_dirs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
        if run_ids:
            wanted = {item.strip() for item in run_ids if item.strip()}
            run_dirs = [path for path in run_dirs if path.name in wanted]
        for run_dir in run_dirs:
            if not (run_dir / "run_manifest.json").exists():
                continue
            status = refresh_run_security_derivatives(run_dir, apply=apply_refresh)
            if status == "ok":
                refresh_stats["ok"] += 1
            else:
                refresh_stats["skipped"] += 1
    summary = analyze_security_cohort(root, run_ids=run_ids)
    per_run_rows = [row.__dict__ for row in summary.rows]
    app_rows = build_app_security_rollup(summary.rows)
    review_md = render_cohort_security_review_md(summary)
    import csv

    per_run_path = out / "per_run_security.csv"
    app_path = out / "app_security_rollup.csv"
    review_path = out / "cohort_security_review.md"
    summary_path = out / "summary.json"
    run_fields = list(per_run_rows[0].keys()) if per_run_rows else ["run_id", "package_name"]
    app_fields = list(app_rows[0].keys()) if app_rows else ["package", "app_label"]
    for path, rows, fields in (
        (per_run_path, per_run_rows, run_fields),
        (app_path, app_rows, app_fields),
    ):
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: row.get(key) for key in fields})
    review_path.write_text(review_md, encoding="utf-8")
    payload = summary.to_dict()
    payload["refresh_derived"] = refresh_derived
    payload["refresh_stats"] = refresh_stats
    payload["output_files"] = {
        "per_run_security_csv": str(per_run_path.resolve()),
        "app_security_rollup_csv": str(app_path.resolve()),
        "cohort_security_review_md": str(review_path.resolve()),
        "summary_json": str(summary_path.resolve()),
    }
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


__all__ = [
    "CohortSecurityRunRow",
    "CohortSecuritySummary",
    "analyze_security_cohort",
    "build_app_security_rollup",
    "generate_cohort_security_report",
    "refresh_run_security_derivatives",
    "render_cohort_security_review_md",
]
