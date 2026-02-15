"""Action handlers triggered by the reporting menu."""

from __future__ import annotations

import csv
import json
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
                 SUM(CASE WHEN grade = 'PAPER_GRADE' THEN 1 ELSE 0 END) AS paper_runs,
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
          COALESCE(d.paper_runs, 0) AS paper_runs,
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
            paper_runs,
            pcap_valid,
        ) = row
        status = "DATASET_READY"
        if installed == "N":
            status = "BLOCKED_NOT_INSTALLED"
        elif harvested == "N":
            status = "NEEDS_HARVEST"
        elif static_ready == "N":
            status = "NEEDS_STATIC"
        elif int(paper_runs or 0) == 0:
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
                str(paper_runs),
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
        print(status_messages.status("Internal Phase E baseline bundle missing; generating it first.", level="warn"))
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
        print(status_messages.status("No operational snapshots found under output/operational; exporting Phase E only.", level="info"))

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
    from scytaledroid.DynamicAnalysis.ml.ml_parameters_paper2 import (
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
        menu_utils.print_header("Write Phase E deliverables bundle")
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
    menu_utils.print_header("Write Phase E deliverables bundle")
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

    print(status_messages.status(f"Wrote internal baseline bundle: {relative_path(output_phase_e_bundle_root())}", level="success"))
    print(status_messages.status(f"Manifest: {relative_path(artifacts.artifacts_manifest_json)}", level="info"))
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
]
