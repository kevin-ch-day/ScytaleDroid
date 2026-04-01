"""Action handlers triggered by the reporting menu."""

from __future__ import annotations

import csv
import json
import os
import shutil
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.menus import health_checks
from scytaledroid.DynamicAnalysis.exports.dataset_export import export_tier1_pack
from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
    index_dynamic_evidence_packs_to_db,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


def handle_dataset_readiness_dashboard() -> None:
    """Print a compact dataset readiness dashboard for RESEARCH_DATASET_ALPHA."""

    rows = core_q.run_sql(
        """
        WITH latest_snap AS (
          SELECT snapshot_id
          FROM device_inventory_snapshots
          ORDER BY captured_at DESC
          LIMIT 1
        ),
        repo_latest AS (
          SELECT package_name,
                 MAX(CAST(version_code AS UNSIGNED)) AS repo_version,
                 MAX(harvested_at) AS harvested_at
          FROM android_apk_repository
          GROUP BY package_name
        ),
        static_latest AS (
          SELECT a.package_name, MAX(sar.id) AS static_run_id
          FROM static_analysis_runs sar
          JOIN app_versions av ON av.id = sar.app_version_id
          JOIN apps a ON a.id = av.app_id
          GROUP BY a.package_name
        ),
        dyn_counts AS (
          SELECT package_name,
                 COUNT(*) AS total_runs,
                 SUM(CASE WHEN grade = 'PAPER_GRADE' THEN 1 ELSE 0 END) AS canonical_runs,
                 MAX(CASE WHEN pcap_valid = 1 THEN 1 ELSE 0 END) AS pcap_valid
          FROM dynamic_sessions
          GROUP BY package_name
        )
        SELECT
          a.display_name,
          a.package_name,
          CASE WHEN i.package_name IS NULL THEN 'N' ELSE 'Y' END AS installed,
          i.version_code,
          CASE WHEN r.package_name IS NULL THEN 'N' ELSE 'Y' END AS harvested,
          r.repo_version,
          r.harvested_at,
          CASE WHEN s.static_run_id IS NULL THEN 'N' ELSE 'Y' END AS static_ready,
          COALESCE(d.total_runs, 0) AS dyn_runs,
          COALESCE(d.canonical_runs, 0) AS canonical_runs,
          CASE
            WHEN d.pcap_valid IS NULL THEN 'N/A'
            WHEN d.pcap_valid = 1 THEN 'Y'
            ELSE 'N'
          END AS pcap_valid
        FROM apps a
        LEFT JOIN latest_snap ls ON 1=1
        LEFT JOIN device_inventory i
          ON LOWER(a.package_name) COLLATE utf8mb4_general_ci =
             LOWER(i.package_name) COLLATE utf8mb4_general_ci
         AND i.snapshot_id = ls.snapshot_id
        LEFT JOIN repo_latest r
          ON LOWER(r.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        LEFT JOIN static_latest s
          ON LOWER(s.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        LEFT JOIN dyn_counts d
          ON LOWER(d.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        WHERE a.profile_key = 'RESEARCH_DATASET_ALPHA'
        ORDER BY a.display_name
        """,
        fetch="all",
    ) or []

    print()
    menu_utils.print_header("Dataset readiness dashboard")
    # Host toolchain check (dataset-tier dynamic QA requires these).
    missing = [tool for tool in ("capinfos", "tshark") if not shutil.which(tool)]
    if missing:
        print(status_messages.status(f"Host tools missing: {', '.join(missing)}", level="warn"))
    else:
        print(status_messages.status("Host tools: capinfos OK, tshark OK", level="success"))
    print(
        status_messages.status(
            f"Dataset QA: MIN_PCAP_BYTES={getattr(app_config, 'DYNAMIC_MIN_PCAP_BYTES', 100000)}",
            level="info",
        )
    )
    headers = [
        "App",
        "Package",
        "Installed",
        "Inst Ver",
        "Harvested",
        "Repo Ver",
        "Static",
        "Dyn Runs",
        "Dataset",
        "PCAP",
        "Status",
    ]
    table_rows: list[list[str]] = []
    for row in rows:
        (
            display_name,
            package_name,
            installed,
            inst_ver,
            harvested,
            repo_ver,
            harvested_at,
            static_ready,
            dyn_runs,
            canonical_runs,
            pcap_valid,
        ) = row
        status = "DATASET_READY"
        if installed == "N":
            status = "BLOCKED_NOT_INSTALLED"
        elif harvested == "N":
            status = "NEEDS_HARVEST"
        elif static_ready == "N":
            status = "NEEDS_STATIC"
        elif int(canonical_runs or 0) == 0:
            status = "NEEDS_DYNAMIC"
        table_rows.append(
            [
                str(display_name or "—"),
                str(package_name or "—"),
                str(installed),
                str(inst_ver or "—"),
                str(harvested),
                str(repo_ver or "—"),
                str(static_ready),
                str(dyn_runs),
                str(canonical_runs),
                str(pcap_valid),
                status,
            ]
        )
    table_utils.render_table(headers, table_rows)
    print()
    prompt_utils.press_enter_to_continue()


def handle_write_canonical_publication_bundle() -> None:
    """Write a canonical `output/publication/` research bundle directory."""

    from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import output_phase_e_bundle_root
    from scytaledroid.Publication.canonical_bundle_writer import (
        write_canonical_publication_directory,
    )

    baseline_root = output_phase_e_bundle_root()
    if not baseline_root.exists():
        print(status_messages.status("Internal baseline deliverables bundle missing; generating it first.", level="warn"))
        ok = _write_phase_e_deliverables_bundle_from_pin()
        if not ok:
            prompt_utils.press_enter_to_continue()
            return

    # Choose snapshot to surface (optional).
    snaps_root = Path(app_config.OUTPUT_DIR) / "operational"
    snaps: list[Path] = []
    if snaps_root.exists():
        snaps = sorted([p for p in snaps_root.iterdir() if p.is_dir()])

    snapshot_dir: Path | None = None
    snapshot_id: str | None = None
    if snaps:
        use_latest = prompt_utils.prompt_yes_no(
            f"Surface latest operational snapshot into the research bundle path (output/publication)? ({snaps[-1].name})",
            default=True,
        )
        if use_latest:
            snapshot_dir = snaps[-1]
            snapshot_id = snapshot_dir.name
        else:
            sid = prompt_utils.prompt_text("Snapshot id under output/operational (blank=skip)", required=False, show_arrow=False).strip()
            if sid:
                cand = snaps_root / sid
                if not cand.exists():
                    print(status_messages.status(f"Snapshot not found: {cand}", level="warn"))
                else:
                    snapshot_dir = cand
                    snapshot_id = cand.name
    else:
        print(status_messages.status("No operational snapshots found under output/operational; exporting baseline only.", level="info"))

    print()
    menu_utils.print_header("Write Canonical Research Bundle")
    print(
        status_messages.status(
            "This surfaces the baseline bundle + (optional) snapshot into the research bundle path (output/publication/) with stable paths.",
            level="info",
        )
    )

    try:
        res = write_canonical_publication_directory(
            baseline_bundle_root=baseline_root,
            snapshot_dir=snapshot_dir,
            snapshot_id=snapshot_id,
            overwrite=True,
        )
    except Exception as exc:  # pragma: no cover
        print(status_messages.status(f"Canonical export failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status(f"Wrote: {relative_path(res.publication_root)}", level="success"))
    if getattr(res, "warnings_count", 0):
        print(
            status_messages.status(
                f"Warnings: {res.warnings_count} (see logs; optional provenance artifacts may be missing)",
                level="warn",
            )
        )
    prompt_utils.press_enter_to_continue()


def handle_lint_profile_v2_bundle() -> None:
    """Lint the frozen cohort archive bundle and print PASS/FAIL reasons.

    This is a visibility-only helper to avoid relying on the status card when
    debugging readiness.
    """

    from scytaledroid.Publication.publication_contract import lint_publication_bundle

    pub_root = Path(app_config.OUTPUT_DIR) / "publication"
    lint = lint_publication_bundle(pub_root)
    print()
    menu_utils.print_header("Lint · Frozen Cohort Archive")
    print(status_messages.status(f"Bundle root: {relative_path(pub_root)}", level="info"))
    if lint.ok:
        print(status_messages.status("LINT PASS", level="success"))
    else:
        print(status_messages.status("LINT FAIL", level="error"))
        for e in lint.errors[:12]:
            print(status_messages.status(f"- {e}", level="error"))
        if len(lint.errors) > 12:
            print(status_messages.status(f"... ({len(lint.errors)} errors total)", level="warn"))
    if lint.warnings:
        print(status_messages.status(f"Warnings: {len(lint.warnings)}", level="warn"))
        for w in lint.warnings[:12]:
            print(status_messages.status(f"- {w}", level="warn"))
        if len(lint.warnings) > 12:
            print(status_messages.status(f"... ({len(lint.warnings)} warnings total)", level="warn"))
    prompt_utils.press_enter_to_continue()


def _write_phase_e_deliverables_bundle_from_pin() -> bool:
    """Write the research baseline Phase E deliverable bundle under output/ (zip-and-share).

    Returns True on success, False on any failure/cancel.
    """

    from scytaledroid.DynamicAnalysis.ml.artifact_bundle_writer import (
        write_phase_e_deliverables_bundle,
    )
    from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import (
        freeze_anchor_path,
        output_phase_e_bundle_root,
    )
    from scytaledroid.DynamicAnalysis.ml.ml_parameters_profile import (
        EXEMPLAR_ALLOWED_INTERACTION_TAGS,
        FREEZE_CANONICAL_FILENAME,
        MESSAGING_PACKAGES,
    )

    archive_dir = Path(app_config.DATA_DIR) / "archive"
    freeze_path = archive_dir / FREEZE_CANONICAL_FILENAME
    if not freeze_path.exists():
        print(status_messages.status(f"Missing canonical freeze anchor: {relative_path(freeze_path)}", level="fail"))
        return False

    research_artifacts = archive_dir / "research_artifacts.json"
    legacy_artifacts = archive_dir / "paper_artifacts.json"
    artifacts_file = research_artifacts if research_artifacts.exists() else legacy_artifacts
    if not artifacts_file.exists():
        print(status_messages.status(f"Missing artifact lock file: {relative_path(research_artifacts)}", level="warn"))
        print(status_messages.status("Action: run research end-to-end (it generates/pins Fig B1).", level="info"))
        return False

    try:
        payload = json.loads(artifacts_file.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Failed to read artifact lock file: {exc}", level="fail"))
        return False
    rid = str(payload.get("fig_B1_run_id") or "").strip()
    tag = str(payload.get("interaction_tag") or "").strip() or None
    if not rid:
        print(status_messages.status("Artifact lock file missing fig_B1_run_id.", level="fail"))
        return False

    def _canonical_tag(raw: str | None) -> str | None:
        if not raw:
            return None
        s = str(raw).strip().lower()
        if not s:
            return None
        if "video" in s:
            return "video"
        if "voice" in s or "audio" in s:
            return "voice"
        return s

    def _pin_is_valid(run_id: str) -> tuple[bool, str]:
        run_dir = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / run_id
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            return False, "evidence_missing"
        try:
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return False, "manifest_unreadable"
        pkg = (m.get("target") or {}).get("package_name")
        if pkg not in MESSAGING_PACKAGES:
            return False, "not_messaging_app"
        ds = m.get("dataset") if isinstance(m.get("dataset"), dict) else {}
        if ds.get("low_signal") is True:
            return False, "low_signal"
        op = m.get("operator") if isinstance(m.get("operator"), dict) else {}
        tag_raw = op.get("messaging_activity") or op.get("interaction_level")
        tag_c = _canonical_tag(tag_raw)
        if tag_c not in EXEMPLAR_ALLOWED_INTERACTION_TAGS:
            return False, "not_call_tag"
        return True, "ok"

    ok, why = _pin_is_valid(rid)
    if not ok:
        print()
        menu_utils.print_header("Write baseline deliverables bundle")
        print(status_messages.status("Artifact lock pin is invalid under current PM policy.", level="warn"))
        print(status_messages.status(f"Reason: {why}", level="warn"))
        print(
            status_messages.status(
                "PM policy: Fig B1 exemplar must be frozen-only, messaging app, call (voice/video), and not low_signal.",
                level="info",
            )
        )
        if not prompt_utils.prompt_yes_no("Repin Fig B1 exemplar deterministically now?", default=False):
            print(status_messages.status("Cancelled.", level="info"))
            return False
        try:
            freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(status_messages.status(f"Failed to read freeze anchor: {exc}", level="fail"))
            return False
        from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
            _select_fig_b1_exemplar_from_existing_or_inputs,
        )

        exemplar = _select_fig_b1_exemplar_from_existing_or_inputs(
            evidence_root=Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic",
            freeze_apps=freeze.get("apps") or {},
            checksums=freeze.get("included_run_checksums") or {},
        )
        if not exemplar:
            print(status_messages.status("No eligible exemplar found in frozen dataset.", level="fail"))
            return False
        backup = archive_dir / f"research_artifacts.prev-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
        backup.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        payload = {
            "freeze_anchor": str(freeze_path),
            "fig_B1_run_id": exemplar.run_id,
            "package_name": exemplar.package_name,
            "interaction_tag": exemplar.interaction_tag,
            "ended_at": exemplar.ended_at,
            "selection_metric": "sustained_bytes_per_sec_k6",
            "tie_breakers": ["iforest_prevalence", "ocsvm_prevalence", "ended_at"],
            "metrics": {
                "sustained_bytes_per_sec_k6": float(exemplar.sustained_bytes_per_sec_k6),
                "iforest_flagged_pct": float(exemplar.iforest_flagged_pct),
                "ocsvm_flagged_pct": float(exemplar.ocsvm_flagged_pct),
            },
            "repinned_from": {"fig_B1_run_id": str(rid), "interaction_tag": str(tag or "")},
            "repinned_at": datetime.now(UTC).isoformat(),
        }
        # Write the new canonical filename and refresh the legacy filename for compatibility.
        content = json.dumps(payload, indent=2, sort_keys=True)
        research_artifacts.write_text(content, encoding="utf-8")
        legacy_artifacts.write_text(content, encoding="utf-8")
        rid = str(payload.get("fig_B1_run_id") or "").strip()
        tag = str(payload.get("interaction_tag") or "").strip() or None

    print()
    menu_utils.print_header("Write baseline deliverables bundle")
    print(status_messages.status("This packages already-derived tables + one flagship timeline figure.", level="info"))
    print(status_messages.status(f"Freeze anchor (copied into bundle): {relative_path(freeze_anchor_path())}", level="info"))
    print(status_messages.status(f"Fig B1 exemplar: {rid[:8]} ({tag or 'interactive'})", level="info"))
    if not prompt_utils.prompt_yes_no("Write/refresh bundle under output/?", default=True):
        print(status_messages.status("Cancelled.", level="info"))
        return False

    try:
        artifacts = write_phase_e_deliverables_bundle(fig_b1_run_id=rid, interaction_tag=tag)
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Bundle generation failed: {exc}", level="fail"))
        return False

    print(status_messages.status(f"Wrote baseline bundle: {relative_path(output_phase_e_bundle_root())}", level="success"))
    print(status_messages.status(f"Manifest: {relative_path(artifacts.artifacts_manifest_json)}", level="info"))
    try:
        required_payload = json.loads(artifacts.required_fields_validation_json.read_text(encoding="utf-8"))
        if bool(required_payload.get("paper_grade_ready")):
            print(status_messages.status("Freeze contract: READY (strict)", level="success"))
        else:
            missing = required_payload.get("missing_by_run") if isinstance(required_payload.get("missing_by_run"), dict) else {}
            first_missing = []
            if missing:
                rid, fields = next(iter(missing.items()))
                if isinstance(fields, list):
                    first_missing = [str(x) for x in fields[:3]]
                missing_hint = ", ".join(first_missing) if first_missing else rid
            else:
                missing_hint = "required field gaps"
            print(
                status_messages.status(
                    f"Freeze contract: DOWNGRADED -> EXPERIMENTAL (missing: {missing_hint})",
                    level="warn",
                )
            )
    except Exception:
        print(status_messages.status("Freeze contract: DOWNGRADED -> EXPERIMENTAL (missing: validation state)", level="warn"))
    # Keep output short; deep audit paths live in the bundle manifest + pipeline audit.
    return True


def view_saved_reports() -> None:
    """Browse and preview generated markdown reports."""

    base_dir = Path(app_config.OUTPUT_DIR) / "reports"
    if not base_dir.exists():
        print(status_messages.status("No reports have been generated yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    files = sorted(base_dir.rglob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not files:
        print(status_messages.status("No markdown reports found in the output directory.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    visible = files[:20]
    print()
    menu_utils.print_header("Saved reports", f"Showing {len(visible)} of {len(files)}")

    rows: list[list[str]] = []
    for index, path in enumerate(visible, start=1):
        report_type = classify_report(path, base_dir)
        modified = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        rows.append([str(index), report_type, path.name, modified])

    table_utils.render_table(["#", "Type", "File", "Modified"], rows)
    if len(files) > len(visible):
        remaining = len(files) - len(visible)
        print(status_messages.status(f"+ {remaining} more report(s) available.", level="info"))

    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(visible) + 1)] + ["0"],
        prompt="Preview report #: ",
        default="0",
    )
    if choice == "0":
        return

    selected = visible[int(choice) - 1]
    preview_report_file(selected)


def summarise_severity(findings: Iterable[object]) -> str:
    """Summarise static-analysis findings by severity level."""

    from scytaledroid.StaticAnalysis.core import Finding, SeverityLevel

    counts = {level: 0 for level in (SeverityLevel.P0, SeverityLevel.P1, SeverityLevel.P2)}
    total_notes = 0
    for entry in findings:
        if isinstance(entry, Finding):
            if entry.severity_gate in counts:
                counts[entry.severity_gate] += 1
            else:
                total_notes += 1

    parts = [f"{level.value}:{count}" for level, count in counts.items() if count]
    if total_notes:
        parts.append(f"NOTE:{total_notes}")
    return ", ".join(parts) if parts else "None"


def classify_report(path: Path, base_dir: Path) -> str:
    """Classify a report based on its location and name."""

    try:
        relative = path.relative_to(base_dir)
    except ValueError:  # pragma: no cover - defensive
        return "Report"

    parts = list(relative.parts)
    if parts and parts[0] == "static_analysis":
        return "Static analysis"
    if path.name.startswith("device_report_"):
        return "Device"
    return "Report"


def preview_report_file(path: Path) -> None:
    """Display a short preview of a markdown report."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:  # pragma: no cover - filesystem errors
        print(status_messages.status(f"Unable to read {path.name}: {exc}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Report preview", path.name)
    preview_limit = 40
    for line in lines[:preview_limit]:
        print(line)
    if len(lines) > preview_limit:
        print(f"... (+{len(lines) - preview_limit} more lines)")

    print()
    resolved = relative_path(path)
    print(status_messages.status(f"Full report available at {resolved}", level="info"))
    prompt_utils.press_enter_to_continue()


def handle_tier1_export_pack() -> None:
    """Export the Baseline dataset pack (manifest + telemetry + summary)."""

    from scytaledroid.Database.db_utils import schema_gate

    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Baseline schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    default_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
    print(status_messages.status(f"Export directory: {default_dir}", level="info"))
    if not prompt_utils.prompt_yes_no("Generate Baseline export pack now?", default=True):
        return
    outputs = export_tier1_pack(default_dir)
    print(status_messages.status(f"Manifest written: {outputs['manifest']}", level="success"))
    print(status_messages.status(f"Summary written: {outputs['summary']}", level="success"))
    print(status_messages.status(f"Rollup written: {outputs['rollup']}", level="success"))
    print(status_messages.status(f"Telemetry dir: {outputs['telemetry_dir']}", level="success"))
    feature_health = outputs.get("feature_health") or {}
    if feature_health:
        print(
            status_messages.status(
                f"Feature health ({feature_health.get('status')}): {feature_health.get('json_path')}",
                level="success",
            )
        )
    _print_export_validation(outputs)
    prompt_utils.press_enter_to_continue()


def _print_export_validation(outputs: dict) -> None:
    manifest_path = outputs.get("manifest")
    telemetry_dir = outputs.get("telemetry_dir")
    if not manifest_path:
        return
    total_rows = 0
    included_rows = 0
    net_included = 0
    try:
        with open(manifest_path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                total_rows += 1
                inclusion = (row.get("inclusion_status") or "").strip().lower()
                if inclusion == "include":
                    included_rows += 1
                net_status = (row.get("network_inclusion_status") or "").strip().lower()
                if net_status in {"netstats_ok", "netstats_partial"}:
                    net_included += 1
    except OSError:
        return

    network_files = 0
    if telemetry_dir:
        try:
            network_files = sum(1 for _ in Path(telemetry_dir).glob("*-network.csv"))
        except OSError:
            network_files = 0

    print(
        status_messages.status(
            f"Export validation: runs={total_rows}, included={included_rows}, "
            f"network_eligible={net_included}, network_files={network_files}",
            level="info",
        )
    )


def handle_tier1_audit_report() -> None:
    """Run Baseline dataset readiness audit."""

    health_checks.run_tier1_audit_report()


def _rebuild_dynamic_db_index_from_evidence(root: Path) -> dict[str, object]:
    """Return indexer results for a dynamic evidence-pack root."""

    result = index_dynamic_evidence_packs_to_db(root)
    # Normalize keys we print repeatedly.
    return {
        "raw": result,
        "scanned": int(result.get("scanned") or 0),
        "ok": int(result.get("ok") or 0),
        "network_features_upserted": int(result.get("network_features_upserted") or 0),
        "indicators_indexed": int(result.get("indicators_indexed") or 0),
        "errors": result.get("errors") or [],
    }


def handle_tier1_quick_fix() -> None:
    """One-shot helper: rebuild DB index from evidence packs and rerun Baseline checks."""

    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not root.exists():
        print(status_messages.status("Dynamic evidence root not found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Baseline quick fix")
    print(status_messages.status("This does not modify evidence packs; it rebuilds derived DB tables.", level="info"))
    print(status_messages.status(f"Root: {root}", level="info"))
    if not prompt_utils.prompt_yes_no("Rebuild DB index now?", default=True):
        return

    outcome = _rebuild_dynamic_db_index_from_evidence(root)
    scanned = int(outcome.get("scanned") or 0)
    ok = int(outcome.get("ok") or 0)
    features = int(outcome.get("network_features_upserted") or 0)
    indexed = int(outcome.get("indicators_indexed") or 0)
    errors = outcome.get("errors") or []
    print(
        status_messages.status(
            f"Reindex complete: scanned={scanned} ok={ok} network_features_upserted={features} indicators_indexed={indexed}",
            level="success" if scanned and scanned == ok else "warn",
        )
    )
    if errors:
        print(status_messages.status(f"Errors (sample): {', '.join(str(e) for e in errors[:5])}", level="warn"))

    print()
    if prompt_utils.prompt_yes_no("Run Baseline audit report now?", default=True):
        health_checks.run_tier1_audit_report()

    print()
    if prompt_utils.prompt_yes_no(
        "Generate Baseline export pack now? (populates Feature Health)", default=False
    ):
        handle_tier1_export_pack()

    prompt_utils.press_enter_to_continue()


def handle_tier1_end_to_end() -> None:
    """One-button Baseline run: rebuild DB index + audit + export."""

    from scytaledroid.Database.db_utils import schema_gate

    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Baseline schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not root.exists():
        print(status_messages.status("Dynamic evidence root not found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Baseline end-to-end")
    print(status_messages.status("Rebuild DB index from evidence packs → audit → export pack.", level="info"))
    result = index_dynamic_evidence_packs_to_db(root)
    scanned = int(result.get("scanned") or 0)
    ok_n = int(result.get("ok") or 0)
    print(
        status_messages.status(
            f"Reindex: scanned={scanned} ok={ok_n}",
            level="success" if scanned and scanned == ok_n else "warn",
        )
    )
    health_checks.run_tier1_audit_report()
    default_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
    outputs = export_tier1_pack(default_dir)
    print(status_messages.status(f"Export written: {outputs.get('manifest')}", level="success"))
    prompt_utils.press_enter_to_continue()


def fetch_tier1_status() -> dict[str, object]:
    """Return a compact Baseline readiness snapshot for the reporting menu."""

    status: dict[str, object] = {
        "schema_version": None,
        "expected_schema": "0.2.6",
        "tier1_ready_runs": 0,
        "last_export_path": None,
        "last_export_at": None,
        "pcap_valid_runs": 0,
        "pcap_total_runs": 0,
        # DB tracking state (some workflows are evidence-pack-first).
        "db_dynamic_sessions_total": 0,
        "db_dynamic_sessions_dataset": 0,
        # Evidence-pack-derived counts (DB-free; aligns with research baseline contract).
        "evidence_packs_total": 0,
        "evidence_dataset_packs": 0,
        "evidence_dataset_valid": 0,
        # Export-derived health signals (post-export).
        "feature_health_status": None,
        "feature_health_at": None,
    }
    try:
        row = core_q.run_sql(
            "SELECT version FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1",
            fetch="one",
            dictionary=True,
        )
        if row:
            status["schema_version"] = row.get("version")
    except Exception:
        status["schema_version"] = None

    # Dynamic DB row counts (used to detect when the DB isn't tracking runs).
    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) AS cnt FROM dynamic_sessions",
            fetch="one",
            dictionary=True,
        )
        if row:
            status["db_dynamic_sessions_total"] = int(row.get("cnt") or 0)
    except Exception:
        status["db_dynamic_sessions_total"] = 0

    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) AS cnt FROM dynamic_sessions WHERE tier='dataset'",
            fetch="one",
            dictionary=True,
        )
        if row:
            status["db_dynamic_sessions_dataset"] = int(row.get("cnt") or 0)
    except Exception:
        status["db_dynamic_sessions_dataset"] = 0

    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*) AS cnt
            FROM dynamic_sessions ds
            WHERE ds.tier='dataset'
              AND ds.status='success'
              AND ds.captured_samples / NULLIF(ds.expected_samples,0) >= 0.90
              AND ds.sample_max_gap_s <= (ds.sampling_rate_s * 2)
              AND NOT EXISTS (
                SELECT 1
                FROM dynamic_session_issues i
                WHERE i.dynamic_run_id = ds.dynamic_run_id
                  AND i.issue_code = 'telemetry_partial_samples'
              )
            """,
            fetch="one",
            dictionary=True,
        )
        if row:
            status["tier1_ready_runs"] = int(row.get("cnt") or 0)
    except Exception:
        status["tier1_ready_runs"] = 0

    try:
        row = core_q.run_sql(
            """
            SELECT
              SUM(CASE WHEN pcap_valid = 1 THEN 1 ELSE 0 END) AS valid_count,
              SUM(CASE WHEN pcap_relpath IS NOT NULL THEN 1 ELSE 0 END) AS linked_count
            FROM dynamic_sessions
            WHERE tier='dataset'
            """,
            fetch="one",
            dictionary=True,
        )
        if row:
            status["pcap_valid_runs"] = int(row.get("valid_count") or 0)
            status["pcap_total_runs"] = int(row.get("linked_count") or 0)
    except Exception:
        status["pcap_valid_runs"] = 0
        status["pcap_total_runs"] = 0

    # Evidence-pack-derived counts (authoritative for research baseline / ML).
    try:
        import json
        from pathlib import Path

        root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
        total = dataset_total = dataset_valid = 0
        if root.exists():
            for mf in root.glob("*/run_manifest.json"):
                total += 1
                try:
                    payload = json.loads(mf.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                ds = payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {}
                tier = ds.get("tier")
                if str(tier or "").lower() != "dataset":
                    continue
                if ds.get("countable") is False:
                    continue
                dataset_total += 1
                if ds.get("valid_dataset_run") is True:
                    dataset_valid += 1
        status["evidence_packs_total"] = total
        status["evidence_dataset_packs"] = dataset_total
        status["evidence_dataset_valid"] = dataset_valid
    except Exception:
        status["evidence_packs_total"] = 0
        status["evidence_dataset_packs"] = 0
        status["evidence_dataset_valid"] = 0

    try:
        export_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
        manifest_path = export_dir / "scytaledroid_dyn_v1_manifest.csv"
        if manifest_path.exists():
            status["last_export_path"] = relative_path(manifest_path)
            status["last_export_at"] = datetime.fromtimestamp(
                manifest_path.stat().st_mtime
            ).strftime("%Y-%m-%d %H:%M")
    except Exception:
        status["last_export_path"] = None
        status["last_export_at"] = None

    # Feature health status (only exists after export).
    try:
        export_analysis_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1" / "analysis"
        fh_path = export_analysis_dir / "feature_health.json"
        if fh_path.exists():
            import json

            payload = json.loads(fh_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                status["feature_health_status"] = payload.get("status")
            status["feature_health_at"] = datetime.fromtimestamp(fh_path.stat().st_mtime).strftime(
                "%Y-%m-%d %H:%M"
            )
    except Exception:
        status["feature_health_status"] = None
        status["feature_health_at"] = None

    return status


def fetch_publication_status() -> dict[str, object]:
    """Return a compact publication status snapshot.

    This intentionally avoids DB-derived metrics. Evidence packs + freeze + publication
    bundle are the authoritative sources for publication exports.
    """

    from scytaledroid.DynamicAnalysis.tools.evidence.paper_readiness_audit import (
        run_paper_readiness_audit,
    )

    status: dict[str, object] = {
        "paper_audit_result": "unknown",
        "can_freeze": False,
        "evidence_quota_counted": None,
        "evidence_quota_expected": None,
        "freeze_dataset_hash": None,
        "publication_ready": False,
        "publication_root_label": "output/publication",
        "publication_tables_label": "0",
        "publication_figures_label": "0",
        "results_numbers_label": "missing",
        "exports_label": "missing",
        "qa_label": "missing",
        "footer": "",
    }

    # Freeze readiness audit (authoritative).
    try:
        audit = run_paper_readiness_audit()
        status["paper_audit_result"] = str(audit.result)
        status["can_freeze"] = bool(audit.can_freeze)
        # The audit module knows expected counts; surface them for the UI.
        try:
            status["evidence_quota_expected"] = int(audit.expected_valid_runs)
        except Exception:
            status["evidence_quota_expected"] = None
        # Countable quota is tracked in the freeze manifest (if present) or by exports.
    except Exception:
        audit = None

    # Freeze anchor (canonical for publication exports).
    freeze_path = Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"
    if freeze_path.exists():
        try:
            payload = json.loads(freeze_path.read_text(encoding="utf-8"))
            status["freeze_dataset_hash"] = payload.get("freeze_dataset_hash")
            included = payload.get("included_run_ids") or []
            status["evidence_quota_counted"] = int(len(included)) if isinstance(included, list) else None
        except Exception:
            status["freeze_dataset_hash"] = None

    # Publication bundle surface.
    pub_root = Path(app_config.OUTPUT_DIR) / "publication"
    status["publication_root_label"] = str(relative_path(pub_root))
    from scytaledroid.Publication.publication_contract import lint_publication_bundle
    lint = lint_publication_bundle(pub_root)
    tables_dir = pub_root / "tables"
    figs_dir = pub_root / "figures"
    results_numbers = pub_root / "appendix" / "results_section_V.md"
    paste_blocks = pub_root / "appendix" / "publication_paste_blocks.md"
    paste_blocks_legacy = pub_root / "appendix" / "paper2_ieee_paste_blocks.md"
    qa_dir = pub_root / "qa"
    exports = [
        Path(app_config.DATA_DIR) / "archive" / "dynamic_run_summary.csv",
        Path(app_config.DATA_DIR) / "archive" / "pcap_features.csv",
        Path(app_config.DATA_DIR) / "archive" / "protocol_ledger.csv",
    ]

    if tables_dir.exists():
        # Paper assembly needs all surfaced CSVs (not only `table_*.csv`).
        status["publication_tables_label"] = str(len(list(tables_dir.glob("*.csv"))))
    if figs_dir.exists():
        # Paper-facing figures live under output/publication/figures. Exploratory/post-paper
        # figures should live under output/publication/explore/ and must not inflate the
        # paper status snapshot.
        paper_figs = []
        for p in figs_dir.glob("*.png"):
            stem = p.stem.lower()
            if stem.startswith(("fig_b1", "fig_b2", "fig_b3", "fig_b4")):
                paper_figs.append(p)
        status["publication_figures_label"] = str(len(paper_figs))
    # Legacy paste blocks remain readable for older runs, but new runs should not
    # write them unless explicitly enabled.
    if results_numbers.exists() or paste_blocks.exists() or paste_blocks_legacy.exists():
        status["results_numbers_label"] = "present"
    if all(p.exists() for p in exports):
        status["exports_label"] = "present"
    if qa_dir.exists() and (qa_dir / "qa_stats_validation.json").exists():
        status["qa_label"] = "present"

    status["publication_ready"] = bool(lint.ok)

    if not status["publication_ready"]:
        # Keep it short; detailed reasons exist in saved reports / audits.
        first = lint.errors[0] if lint.errors else "unknown"
        status["footer"] = f"Publication bundle NOT READY ({first}). Run: 1) Regenerate artifacts, then 5) Write bundle."
    else:
        status["footer"] = ""

    return status


def handle_export_freeze_anchored_csvs() -> None:
    """Export archived frozen-cohort CSVs from the freeze anchor."""

    from scytaledroid.DynamicAnalysis.pcap.aggregate import (
        export_dynamic_run_summary_csv,
        export_pcap_features_csv,
        export_protocol_ledger_csv,
    )

    freeze_path = Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"
    if not freeze_path.exists():
        print(status_messages.status(f"Missing freeze anchor: {relative_path(freeze_path)}", level="error"))
        return

    print()
    menu_utils.print_header("Frozen Cohort CSV Exports")
    summary = export_dynamic_run_summary_csv(freeze_path=freeze_path, require_freeze=True)
    feats = export_pcap_features_csv(freeze_path=freeze_path, require_freeze=True)
    ledger = export_protocol_ledger_csv(freeze_path=freeze_path, require_freeze=True)
    for label, path in (("dynamic_run_summary.csv", summary), ("pcap_features.csv", feats), ("protocol_ledger.csv", ledger)):
        if path:
            print(status_messages.status(f"Wrote: {relative_path(path)} ({label})", level="success"))
        else:
            print(status_messages.status(f"Export missing: {label}", level="warn"))


def handle_generate_publication_results_numbers() -> None:
    """Generate archived CSV/JSON exports plus frozen-cohort results numbers.

    This is intentionally deterministic and freeze-anchored. The goal is to give
    the manuscript a single source of truth:
    - output/publication/tables/*_summary*.csv
    - output/publication/manifests/paper_results_v1.json
    - output/publication/manifests/publication_results_numbers.json
    - output/publication/appendix/results_section_V.md
    """

    exports_script = Path(__file__).resolve().parents[2] / "scripts" / "publication" / "publication_exports.py"
    results_script = Path(__file__).resolve().parents[2] / "scripts" / "publication" / "publication_results_numbers.py"
    for script in (exports_script, results_script):
        if not script.exists():
            print(status_messages.status(f"Missing script: {relative_path(script)}", level="error"))
            return

    import runpy

    print()
    menu_utils.print_header("Generate Frozen Archive Results Numbers")
    try:
        runpy.run_path(str(exports_script), run_name="__main__")
        runpy.run_path(str(results_script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Generation failed: exit={exc.code}", level="error"))
            return
    out_tables = Path(app_config.OUTPUT_DIR) / "publication" / "tables"
    out_results_json = Path(app_config.OUTPUT_DIR) / "publication" / "manifests" / "paper_results_v1.json"
    out_md = Path(app_config.OUTPUT_DIR) / "publication" / "appendix" / "results_section_V.md"
    out_json = Path(app_config.OUTPUT_DIR) / "publication" / "manifests" / "publication_results_numbers.json"
    out_json_legacy = Path(app_config.OUTPUT_DIR) / "publication" / "manifests" / "paper2_results_numbers.json"
    for name in (
        "paper_cohort_summary_v1.csv",
        "baseline_stability_summary.csv",
        "interaction_delta_summary.csv",
        "static_dynamic_correlation.csv",
    ):
        p = out_tables / name
        if p.exists():
            print(status_messages.status(f"Wrote: {relative_path(p)}", level="success"))
    if out_results_json.exists():
        print(status_messages.status(f"Wrote: {relative_path(out_results_json)}", level="success"))
    if out_md.exists():
        print(status_messages.status(f"Wrote: {relative_path(out_md)}", level="success"))
    if out_json.exists():
        print(status_messages.status(f"Wrote: {relative_path(out_json)}", level="success"))
    # Legacy alias is opt-in; do not advertise it unless it was explicitly written.
    import os

    legacy_enabled = str(os.environ.get("SCYTALEDROID_WRITE_LEGACY_ALIASES") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if legacy_enabled and out_json_legacy.exists():
        print(status_messages.status(f"Wrote: {relative_path(out_json_legacy)} (legacy alias)", level="info"))


def handle_generate_profile_v3_exports() -> None:
    """Generate structural archive exports."""

    script = Path(__file__).resolve().parents[2] / "scripts" / "publication" / "profile_v3_exports.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {relative_path(script)}", level="error"))
        return

    import runpy

    print()
    menu_utils.print_header("Generate Structural Archive Exports")
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Generation failed: exit={exc.code}", level="error"))
            return
    out_root = Path(app_config.OUTPUT_DIR) / "publication" / "profile_v3"
    print(status_messages.status(f"Wrote: {relative_path(out_root)}", level="success"))
    prompt_utils.press_enter_to_continue()


def handle_generate_profile_v3_phase2_exports() -> None:
    """Generate structural archive draft exports from current runs."""

    script = Path(__file__).resolve().parents[2] / "scripts" / "publication" / "profile_v3_phase2_exports.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {relative_path(script)}", level="error"))
        return

    import runpy

    print()
    menu_utils.print_header("Generate Structural Archive Draft Exports")
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Generation failed: exit={exc.code}", level="error"))
            return
    out_root = Path(app_config.OUTPUT_DIR) / "audit" / "profile_v3" / "phase2_exports"
    print(status_messages.status(f"Wrote: {relative_path(out_root)}", level="success"))
    prompt_utils.press_enter_to_continue()


def handle_profile_v3_integrity_gates() -> None:
    """Run structural archive integrity gates."""

    print()
    menu_utils.print_header("Structural Archive Integrity Gates")
    script = Path(__file__).resolve().parents[2] / "scripts" / "profile_tools" / "profile_v3_integrity_gates.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {relative_path(script)}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    import runpy

    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Gates failed: exit={exc.code}", level="error"))
            prompt_utils.press_enter_to_continue()
            return

    print(status_messages.status("Structural archive gates: PASS", level="success"))
    prompt_utils.press_enter_to_continue()

def handle_generate_exploratory_risk_scoring() -> None:
    """Generate exploratory risk scoring artifacts (neutral filenames).

    These are intentionally not wired into the paper bundle's canonical filenames
    until the authors sign off on naming, interpretation, and placement.
    """

    script = Path(__file__).resolve().parents[2] / "scripts" / "publication" / "exploratory_risk_scoring.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {relative_path(script)}", level="error"))
        return

    import runpy

    print()
    menu_utils.print_header("Exploratory Risk Scoring (Not Paper-Named)")
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Generation failed: exit={exc.code}", level="error"))
            return

    # New location is paper-neutral; keep legacy path readable for one major cycle.
    # Legacy path removal is planned in v4.0.
    explore_dir = Path(app_config.OUTPUT_DIR) / "experimental" / "analysis" / "risk_scoring"
    legacy_dir = Path(app_config.OUTPUT_DIR) / "experimental" / "paper2"
    if not explore_dir.exists() and legacy_dir.exists():
        explore_dir = legacy_dir
    for name in (
        "risk_scores_v1.csv",
        "risk_scores_v1.json",
        "risk_scores_v1.tex",
        "risk_scores_v1_sorted_by_frs.csv",
        "risk_scores_v1_sorted_by_drs.csv",
        "risk_scores_v1_sorted_by_srs.csv",
        "scatter_static_vs_dynamic_scores.pdf",
        "ranked_fused_scores.pdf",
    ):
        p = explore_dir / name
        if p.exists():
            print(status_messages.status(f"Wrote: {relative_path(p)}", level="success"))

def handle_generate_publication_scientific_qa() -> None:
    """Generate scientific QA reports for the frozen archive."""

    script = Path(__file__).resolve().parents[2] / "scripts" / "publication" / "publication_scientific_qa.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {relative_path(script)}", level="error"))
        return

    import runpy

    print()
    menu_utils.print_header("Generate Scientific QA (Frozen Archive)")
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"QA generation failed: exit={exc.code}", level="error"))
            return
    out_dir = Path(app_config.OUTPUT_DIR) / "publication" / "qa"
    if out_dir.exists():
        print(status_messages.status(f"Wrote QA reports under: {relative_path(out_dir)}", level="success"))
    prompt_utils.press_enter_to_continue()

def handle_generate_publication_pipeline_audit() -> None:
    """Generate a deep ML+dynamic pipeline audit for the frozen archive."""

    script = Path(__file__).resolve().parents[2] / "scripts" / "publication" / "publication_pipeline_audit.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {relative_path(script)}", level="error"))
        return

    import runpy

    print()
    menu_utils.print_header("Pipeline Audit (ML + Dynamic)")
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Audit completed with errors: exit={exc.code}", level="error"))
            prompt_utils.press_enter_to_continue()
            return

    out = Path(app_config.OUTPUT_DIR) / "publication" / "qa" / "pipeline_audit_v1.json"
    if out.exists():
        print(status_messages.status(f"Wrote: {relative_path(out)}", level="success"))
    prompt_utils.press_enter_to_continue()

def handle_print_manuscript_snapshot() -> None:
    """Print a one-screen archive snapshot for meetings/reviews."""

    import json
    from pathlib import Path

    print()
    menu_utils.print_header("Manuscript Snapshot")
    pub_root = Path(app_config.OUTPUT_DIR) / "publication"
    results_path = pub_root / "manifests" / "paper_results_v1.json"
    if not results_path.exists():
        print(status_messages.status(f"Missing: {relative_path(results_path)}", level="error"))
        print(status_messages.status("Fix: Reporting → Generate Results (Section V)", level="info"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        payload = json.loads(results_path.read_text(encoding="utf-8"))
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        print(status_messages.status("paper_results_v1.json parse failed.", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    freeze_hash = str(payload.get("freeze_dataset_hash") or "")
    freeze_short = freeze_hash[:12] if freeze_hash else "missing"
    n_apps = int(payload.get("n_apps") or 0)
    runs_total = int(payload.get("n_runs_total") or 0)
    runs_idle = int(payload.get("n_runs_idle") or 0)
    runs_interactive = int(payload.get("n_runs_interactive") or 0)
    windows_total = int(payload.get("windows_total") or 0)
    windows_idle = int(payload.get("windows_idle_total") or 0)
    windows_interactive = int(payload.get("windows_interactive_total") or 0)

    mu = payload.get("if_idle_mean")
    sd = payload.get("if_idle_sd_sample")
    delta = payload.get("if_delta_mean")
    w_p = payload.get("wilcoxon_p_value")
    rho = payload.get("spearman_rho_static_vs_if_interactive")
    pval = payload.get("spearman_p_static_vs_if_interactive")

    # Keep it short and copy/paste friendly.
    print(
        f"Cohort: {n_apps} apps | {runs_total} runs ({runs_idle} idle, {runs_interactive} interactive) | {windows_total} windows ({windows_idle} idle, {windows_interactive} interactive)"
    )
    if mu is not None and sd is not None:
        print(f"Baseline RDI (IF): mu={mu:.4f} sd={sd:.4f}")
    if delta is not None and w_p is not None:
        print(f"Interaction effect (IF): delta_mean={delta:.4f} | Wilcoxon p={w_p}")
    if rho is not None and pval is not None:
        print(f"Static vs Dynamic (Spearman): rho={rho} p={pval}")
    print(f"Freeze: {freeze_short}")
    print(status_messages.status(f"Source: {relative_path(results_path)}", level="info"))
    prompt_utils.press_enter_to_continue()


def handle_refresh_phase_e_bundle() -> None:
    """Run ML over the frozen cohort and refresh publication artifacts inputs."""

    from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
        run_ml_on_evidence_packs,
        _select_fig_b1_exemplar_from_existing_or_inputs,
    )
    from scytaledroid.DynamicAnalysis.ml.artifact_bundle_writer import write_phase_e_deliverables_bundle

    archive_dir = Path(app_config.DATA_DIR) / "archive"
    freeze_path = archive_dir / "dataset_freeze.json"
    if not freeze_path.exists():
        print(status_messages.status(f"Missing freeze anchor: {relative_path(freeze_path)}", level="error"))
        return
    try:
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(status_messages.status(f"Failed to read freeze anchor: {exc}", level="error"))
        return

    print()
    menu_utils.print_header("Regenerate Publication Artifacts")
    print(status_messages.status("Running ML over frozen evidence packs.", level="info"))
    run_ml_on_evidence_packs(freeze_manifest_path=freeze_path, reuse_existing_outputs=True)

    # Ensure Fig B1 exemplar pin points at a real run with ML outputs.
    artifacts_path = archive_dir / "paper_artifacts.json"
    rid = None
    tag = None
    if artifacts_path.exists():
        try:
            payload = json.loads(artifacts_path.read_text(encoding="utf-8"))
            rid = str(payload.get("fig_B1_run_id") or "").strip() or None
            tag = str(payload.get("interaction_tag") or "").strip() or None
        except Exception:
            rid = None

    def _pin_ok(run_id: str | None) -> bool:
        if not run_id:
            return False
        run_dir = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / run_id
        if not (run_dir / "run_manifest.json").exists():
            return False
        out_dir = run_dir / "analysis" / "ml" / "v1"
        return (out_dir / "anomaly_scores_iforest.csv").exists() and (out_dir / "anomaly_scores_ocsvm.csv").exists()

    if not _pin_ok(rid):
        exemplar = _select_fig_b1_exemplar_from_existing_or_inputs(
            evidence_root=Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic",
            freeze_apps=freeze.get("apps") or {},
            checksums=freeze.get("included_run_checksums") or {},
        )
        if not exemplar:
            print(status_messages.status("No eligible Fig B1 exemplar found.", level="error"))
            return
        rid = exemplar.run_id
        tag = exemplar.interaction_tag
        backup = archive_dir / f"paper_artifacts.prev-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
        if artifacts_path.exists():
            backup.write_text(artifacts_path.read_text(encoding="utf-8"), encoding="utf-8")
        payload = {
            "freeze_anchor": str(freeze_path),
            "fig_B1_run_id": rid,
            "package_name": exemplar.package_name,
            "interaction_tag": tag,
            "ended_at": exemplar.ended_at,
            "selection_metric": "sustained_bytes_per_sec_k6",
            "tie_breakers": ["iforest_prevalence", "ocsvm_prevalence", "ended_at"],
            "metrics": {
                "sustained_bytes_per_sec_k6": float(exemplar.sustained_bytes_per_sec_k6),
                "iforest_flagged_pct": float(exemplar.iforest_flagged_pct),
                "ocsvm_flagged_pct": float(exemplar.ocsvm_flagged_pct),
            },
            "repinned_from": None,
            "repinned_at": datetime.now(UTC).isoformat(),
        }
        artifacts_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(status_messages.status(f"Repinned Fig B1 exemplar: {rid[:8]} ({tag})", level="info"))

    # Ensure the bundle copies the current freeze anchor.
    os.environ["SCYTALEDROID_FREEZE_ANCHOR_PATH"] = str(freeze_path)
    artifacts = write_phase_e_deliverables_bundle(fig_b1_run_id=str(rid), interaction_tag=tag)
    print(status_messages.status(f"Wrote: {relative_path(artifacts.out_root)}", level="success"))


def relative_path(path: Path) -> Path:
    """Return the path relative to the current working directory if possible."""

    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


def format_timestamp(value: str) -> str:
    """Normalise ISO timestamps for display."""

    try:
        normalised = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalised)
    except Exception:  # pragma: no cover - fallback path
        return value
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


__all__ = [
    "classify_report",
    "format_timestamp",
    "preview_report_file",
    "relative_path",
    "summarise_severity",
    "view_saved_reports",
    "fetch_publication_status",
    "handle_export_freeze_anchored_csvs",
    "handle_generate_publication_results_numbers",
    "handle_generate_publication_scientific_qa",
    "handle_generate_publication_pipeline_audit",
    "handle_generate_exploratory_risk_scoring",
    "handle_generate_profile_v3_exports",
    "handle_profile_v3_integrity_gates",
    "handle_refresh_phase_e_bundle",
]
