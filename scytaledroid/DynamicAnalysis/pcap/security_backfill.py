"""Backfill security_surface artifacts for existing dynamic evidence packs."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.correlate import write_static_dynamic_overlap
from scytaledroid.DynamicAnalysis.pcap.features import write_pcap_features
from scytaledroid.DynamicAnalysis.pcap.report import _find_pcap_artifact
from scytaledroid.DynamicAnalysis.pcap.security_surface import (
    compute_static_dynamic_cleartext_posture,
    render_security_review_md,
    summarize_security_surface,
    SecuritySurfaceConfig,
)


@dataclass(frozen=True)
class SecurityBackfillRow:
    run_id: str
    package_name: str | None
    status: str
    reason: str | None = None
    finding_count: int | None = None
    http_observed: bool | None = None
    dynamic_cleartext_observed: bool | None = None
    visibility_class: str | None = None
    mismatch_class: str | None = None


@dataclass
class SecurityBackfillSummary:
    generated_at: str
    evidence_root: str
    apply: bool
    refresh_derived: bool
    scanned: int = 0
    ok: int = 0
    skipped: int = 0
    failed: int = 0
    cleartext_http_runs: int = 0
    cleartext_surface_runs: int = 0
    mismatch_denied_observed: int = 0
    mismatch_allowed_not_observed: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    rows: list[SecurityBackfillRow] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "evidence_root": self.evidence_root,
            "apply": self.apply,
            "refresh_derived": self.refresh_derived,
            "scanned": self.scanned,
            "ok": self.ok,
            "skipped": self.skipped,
            "failed": self.failed,
            "cleartext_http_runs": self.cleartext_http_runs,
            "cleartext_surface_runs": self.cleartext_surface_runs,
            "mismatch_denied_observed": self.mismatch_denied_observed,
            "mismatch_allowed_not_observed": self.mismatch_allowed_not_observed,
            "skip_reasons": dict(self.skip_reasons),
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


def _manifest_from_json(data: dict[str, Any]) -> RunManifest:
    artifacts: list[ArtifactRecord] = []
    for item in data.get("artifacts") or []:
        if not isinstance(item, dict) or not item.get("relative_path"):
            continue
        artifacts.append(
            ArtifactRecord(
                relative_path=str(item["relative_path"]),
                type=str(item.get("type") or "unknown"),
                produced_by=str(item.get("produced_by") or "unknown"),
                sha256=item.get("sha256") if isinstance(item.get("sha256"), str) else None,
                size_bytes=item.get("size_bytes") if isinstance(item.get("size_bytes"), int) else None,
                origin=item.get("origin") if isinstance(item.get("origin"), str) else None,
                device_path=item.get("device_path") if isinstance(item.get("device_path"), str) else None,
                pull_status=item.get("pull_status") if isinstance(item.get("pull_status"), str) else None,
            )
        )
    return RunManifest(
        run_manifest_version=int(data.get("run_manifest_version") or 1),
        dynamic_run_id=str(data.get("dynamic_run_id") or ""),
        created_at=str(data.get("created_at") or ""),
        target=data.get("target") if isinstance(data.get("target"), dict) else {},
        operator=data.get("operator") if isinstance(data.get("operator"), dict) else {},
        dataset=data.get("dataset") if isinstance(data.get("dataset"), dict) else {},
        artifacts=artifacts,
    )


def backfill_security_surface_for_run(
    run_dir: Path,
    *,
    apply: bool,
    refresh_derived: bool,
    timeout_s: int = 45,
) -> SecurityBackfillRow:
    manifest_data = _read_json(run_dir / "run_manifest.json")
    if not manifest_data:
        return SecurityBackfillRow(str(run_dir.name), None, "skipped", "missing_manifest")
    manifest = _manifest_from_json(manifest_data)
    run_id = manifest.dynamic_run_id or run_dir.name
    target = manifest.target if isinstance(manifest.target, dict) else {}
    package_name = str(target.get("package_name") or "").strip() or None
    package_label = str(
        target.get("display_name") or target.get("app_label") or target.get("label") or package_name or ""
    ).strip()

    report_path = run_dir / "analysis" / "pcap_report.json"
    report = _read_json(report_path)
    if not report:
        return SecurityBackfillRow(run_id, package_name, "skipped", "missing_pcap_report")

    report_status = str(report.get("report_status") or "").lower()
    if report_status in {"skip", "failed"}:
        return SecurityBackfillRow(run_id, package_name, "skipped", f"report_status_{report_status}")

    tshark_path = shutil.which("tshark") or ""
    if not tshark_path:
        return SecurityBackfillRow(run_id, package_name, "skipped", "tshark_missing")

    pcap_artifact = _find_pcap_artifact(manifest, run_dir)
    pcap_path = (run_dir / pcap_artifact.relative_path) if pcap_artifact else None
    if pcap_path is None or not pcap_path.exists() or pcap_path.stat().st_size <= 0:
        return SecurityBackfillRow(run_id, package_name, "skipped", "pcap_missing_or_empty")

    try:
        surface = summarize_security_surface(
            pcap_path,
            tshark_path=tshark_path,
            protocol_hierarchy=report.get("protocol_hierarchy") or [],
            flow_summary=report.get("flow_summary") or {},
            burst_summary=report.get("burst_summary") or {},
            config=SecuritySurfaceConfig(timeout_s=max(5, int(timeout_s))),
        )
    except Exception as exc:  # noqa: BLE001
        return SecurityBackfillRow(run_id, package_name, "failed", str(exc))

    status = str(surface.get("status") or "").lower()
    if status != "ok":
        return SecurityBackfillRow(
            run_id,
            package_name,
            "failed",
            str(surface.get("reason") or surface.get("error") or f"surface_status_{status}"),
        )

    cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
    http_observed = bool(cleartext.get("http_observed"))
    visibility_class = cleartext.get("visibility_class")
    finding_count = int(surface.get("finding_count") or 0)

    mismatch_class = None
    plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json")
    report_with_surface = {**report, "security_surface": surface}
    dynamic_cleartext_observed = None
    if isinstance(plan, dict):
        posture = compute_static_dynamic_cleartext_posture(plan, report_with_surface)
        mismatch_class = posture.get("mismatch_class")
        dynamic_cleartext_observed = posture.get("dynamic_http_observed")

    if apply:
        report["security_surface"] = surface
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        surface_path = run_dir / "analysis" / "security_surface.json"
        surface_path.write_text(json.dumps(surface, indent=2, sort_keys=True), encoding="utf-8")
        review_path = run_dir / "analysis" / "security_review.md"
        review_path.write_text(
            render_security_review_md(
                surface,
                package_name=package_label or package_name,
                dynamic_run_id=run_id,
            ),
            encoding="utf-8",
        )
        if refresh_derived:
            write_pcap_features(manifest, run_dir)
            write_static_dynamic_overlap(manifest, run_dir)

    return SecurityBackfillRow(
        run_id=run_id,
        package_name=package_name,
        status="ok",
        finding_count=finding_count,
        http_observed=http_observed,
        dynamic_cleartext_observed=bool(dynamic_cleartext_observed) if dynamic_cleartext_observed is not None else None,
        visibility_class=str(visibility_class) if visibility_class else None,
        mismatch_class=str(mismatch_class) if mismatch_class else None,
    )


def backfill_security_surface_cohort(
    evidence_root: Path,
    *,
    apply: bool = False,
    refresh_derived: bool = True,
    run_ids: tuple[str, ...] = (),
    timeout_s: int = 45,
) -> SecurityBackfillSummary:
    summary = SecurityBackfillSummary(
        generated_at=datetime.now(UTC).isoformat(),
        evidence_root=str(evidence_root.resolve()),
        apply=apply,
        refresh_derived=refresh_derived,
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
        summary.scanned += 1
        row = backfill_security_surface_for_run(
            run_dir,
            apply=apply,
            refresh_derived=refresh_derived,
            timeout_s=timeout_s,
        )
        summary.rows.append(row)
        if row.status == "ok":
            summary.ok += 1
            if row.http_observed:
                summary.cleartext_http_runs += 1
            if row.dynamic_cleartext_observed or row.visibility_class == "cleartext_surface_present":
                summary.cleartext_surface_runs += 1
            if row.mismatch_class == "denied_but_observed":
                summary.mismatch_denied_observed += 1
            elif row.mismatch_class and str(row.mismatch_class).startswith("allowed_not_observed"):
                summary.mismatch_allowed_not_observed += 1
        elif row.status == "skipped":
            summary.skipped += 1
            key = row.reason or "unknown"
            summary.skip_reasons[key] = summary.skip_reasons.get(key, 0) + 1
        else:
            summary.failed += 1
    return summary


__all__ = [
    "SecurityBackfillRow",
    "SecurityBackfillSummary",
    "backfill_security_surface_cohort",
    "backfill_security_surface_for_run",
]
