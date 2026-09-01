"""Action handlers triggered by the reporting menu."""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import (
    db_queries as core_q,  # noqa: F401 - public monkeypatch seam in tests
)
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    resolve_dataset_freeze_read_path,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    dynamic_evidence_root,
    resolve_dynamic_run_dir,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from .dynamic_export_menu import (
    fetch_tier1_status,
    handle_tier1_audit_report,
    handle_tier1_end_to_end,
    handle_tier1_export_pack,
    handle_tier1_quick_fix,
)
from .menu_actions_cross_analysis_helpers import compact_gap, compact_regime, compact_runtime_state
from .publication_status_menu import fetch_publication_status
from .saved_reports_menu import (
    classify_report,
    preview_report_file,
    summarise_severity,
    view_saved_reports,
)
from .static_exposure_menu import handle_generate_static_exposure_privacy_report


def _choose_reporting_research_cohort() -> dict[str, object]:
    from scytaledroid.Database.db_func.research_cohorts import (
        list_active_research_cohorts,
        resolve_preferred_research_cohort_key,
        resolve_research_cohort_context,
    )

    cohorts = list_active_research_cohorts()
    if not cohorts:
        return resolve_research_cohort_context()

    preferred_key = resolve_preferred_research_cohort_key()
    if len(cohorts) == 1:
        return resolve_research_cohort_context(str(cohorts[0].get("cohort_key") or ""))

    print()
    menu_utils.print_header(
        "Select Research Cohort",
        "Choose the DB-backed cohort used by this reporting view.",
    )
    rows = [
        [
            str(idx),
            str(row.get("display_name") or row.get("cohort_key") or ""),
            str(int(row.get("active_member_count") or 0)),
        ]
        for idx, row in enumerate(cohorts, start=1)
    ]
    table_utils.render_table(["#", "Research cohort", "Apps"], rows, compact=True, padding=2)
    default_choice = "1"
    for idx, row in enumerate(cohorts, start=1):
        if str(row.get("cohort_key") or "").strip().lower() == str(preferred_key or "").strip().lower():
            default_choice = str(idx)
            break
    print()
    print(f"Research cohorts: {len(rows)}")
    choice = prompt_utils.menu_choice(
        [str(index) for index in range(1, len(rows) + 1)] + ["0"],
        default=default_choice,
    )
    if choice == "0":
        return {}
    selected = cohorts[int(choice) - 1]
    return resolve_research_cohort_context(str(selected.get("cohort_key") or ""))


def handle_dataset_readiness_dashboard() -> None:
    """Print a compact research cohort readiness dashboard."""

    from scytaledroid.Reporting.services.dataset_readiness import (
        fetch_dataset_readiness_dashboard,
    )

    cohort_ctx = _choose_reporting_research_cohort()
    if not cohort_ctx:
        return
    analysis_snapshot, rows = fetch_dataset_readiness_dashboard(
        profile_key=str(cohort_ctx.get("profile_key") or "") or None,
        cohort_key=str(cohort_ctx.get("cohort_key") or "") or None,
    )

    print()
    menu_utils.print_header(
        "Dataset readiness dashboard",
        str(cohort_ctx.get("display_name") or "Research cohort"),
    )
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
    if analysis_snapshot:
        cohort = str(analysis_snapshot.get("cohort_id") or "unknown")
        label = str(analysis_snapshot.get("summary_label") or "missing")
        ready = bool(analysis_snapshot.get("ready"))
        level = "success" if ready else "warn"
        print(status_messages.status(f"Latest analysis cohort: {cohort} ({label})", level=level))
    else:
        print(status_messages.status("Latest analysis cohort: missing", level="warn"))
    headers = [
        "App",
        "Package",
        "Installed",
        "Inst Ver",
        "Harvested",
        "Repo Ver",
        "Static",
        "Dyn Runs",
        "Quota valid",
        "Analysis",
        "PCAP",
        "Status",
    ]
    table_rows: list[list[str]] = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("display_name") or "—"),
                str(row.get("package_name") or "—"),
                str(row.get("installed") or "N"),
                str(row.get("version_code") or "—"),
                str(row.get("harvested") or "N"),
                str(row.get("repo_version") or "—"),
                str(row.get("static_ready") or "N"),
                str(row.get("dyn_runs") or 0),
                str(row.get("quota_valid_runs") or 0),
                str(row.get("analysis_runs") or 0),
                str(row.get("pcap_valid") or "N/A"),
                str(row.get("status") or "UNKNOWN"),
            ]
        )
    table_utils.render_table(headers, table_rows)
    print()
    prompt_utils.press_enter_to_continue()


def handle_cross_analysis_summary() -> None:
    """Print the static/dynamic cross-analysis summary for the research cohort."""

    from scytaledroid.Reporting.services.cross_analysis_summary import (
        current_cross_analysis_summary_source,
        fetch_cross_analysis_summary_rows,
    )

    cohort_ctx = _choose_reporting_research_cohort()
    if not cohort_ctx:
        return
    source_relation = current_cross_analysis_summary_source()
    rows = fetch_cross_analysis_summary_rows(
        profile_key=str(cohort_ctx.get("profile_key") or "") or None,
        cohort_key=str(cohort_ctx.get("cohort_key") or "") or None,
    )

    print()
    menu_utils.print_header(
        "Cross-Analysis Summary",
        str(cohort_ctx.get("display_name") or "Research cohort"),
    )
    print(
        status_messages.status(
            f"Source: {source_relation} (transitional DB read contract)",
            level="info",
        )
    )
    if not rows:
        print(status_messages.status("No rows found for the active research cohort selection.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    headers = [
        "App",
        "Perm",
        "Runtime",
        "Gap",
        "Regime",
    ]
    table_rows: list[list[str]] = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("app_label") or "—"),
                str(row.get("permission_audit_grade") or "—"),
                compact_runtime_state(
                    row.get("dynamic_technical_validity_state"),
                    row.get("dynamic_quota_state"),
                ),
                compact_gap(row.get("dynamic_feature_recency_state")),
                compact_regime(row.get("regime_final_label")),
            ]
        )
    table_utils.render_table(headers, table_rows)
    print()
    menu_utils.print_section("Per-App Details")
    for row in rows:
        app_label = str(row.get("app_label") or "—")
        package_name = str(row.get("package_name") or "—")
        dyn_run = str(row.get("latest_dynamic_run_id") or "—")
        feat_run = str(row.get("latest_feature_dynamic_run_id") or "—")
        print(f"{app_label} | {package_name}")
        print(
            "  "
            f"static_run={str(row.get('latest_static_run_id') or '—')} "
            f"dyn_run={dyn_run[:8] if dyn_run != '—' else dyn_run} "
            f"feat_run={feat_run[:8] if feat_run != '—' else feat_run}"
        )
        print(
            "  "
            f"runtime={compact_runtime_state(row.get('dynamic_technical_validity_state'), row.get('dynamic_quota_state'))} "
            f"cohort={str(row.get('dynamic_cohort_eligibility_state') or '—')} "
            f"feature={str(row.get('dynamic_feature_state') or '—')}"
        )
        print(
            "  "
            f"gap={str(row.get('dynamic_feature_recency_state') or '—')} "
            f"summary={str(row.get('summary_state') or '—')}"
        )
        print("  " f"regime={str(row.get('regime_final_label') or '—')}")
    prompt_utils.press_enter_to_continue()


def handle_write_canonical_publication_bundle() -> None:
    """Retired v1 archive bundle writer."""

    print()
    menu_utils.print_header("Canonical Research Bundle (Retired)")
    print(
        status_messages.status(
            "The legacy output/publication bundle writer is retired for Paper 2 v2 work.",
            level="warn",
        )
    )
    print(
        status_messages.status(
            "Use Generate Paper 2 v2 results package for the current locked-runtime result set.",
            level="info",
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
        output_locked_runtime_bundle_root,
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
        run_dir = resolve_dynamic_run_dir(run_id)
        if run_dir is None:
            return False, "evidence_missing"
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
            evidence_root=dynamic_evidence_root(),
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

    print(status_messages.status(f"Wrote baseline bundle: {relative_path(output_locked_runtime_bundle_root())}", level="success"))
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


def handle_export_freeze_anchored_csvs() -> None:
    """Export archived frozen-cohort CSVs from the freeze anchor."""

    from scytaledroid.DynamicAnalysis.pcap.aggregate import (
        export_dynamic_run_summary_csv,
        export_pcap_features_csv,
        export_protocol_ledger_csv,
    )

    freeze_path = resolve_dataset_freeze_read_path()
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


def handle_generate_paper2_results_v2_package() -> None:
    """Generate the canonical Paper 2 v2 locked-runtime results package."""

    from scytaledroid.Reporting.services.paper2_results_v2_service import (
        generate_paper2_results_v2,
    )

    print()
    menu_utils.print_header("Generate Paper 2 v2 Results Package")
    try:
        result = generate_paper2_results_v2()
    except Exception as exc:
        print(status_messages.status(f"Generation failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    for key in ("publication_results_v2", "paper2_qa_v2", "hash_manifest"):
        path = result.get(key)
        if path:
            print(status_messages.status(f"Wrote: {relative_path(Path(path))}", level="success"))
    print(
        status_messages.status(
            f"Apps: {result.get('apps')} · runs: {result.get('runs')} · QA: {result.get('qa_status')}",
            level="info",
        )
    )
    prompt_utils.press_enter_to_continue()


def handle_generate_profile_v3_exports() -> None:
    """Generate structural archive exports."""
    from scytaledroid.Reporting.services.profile_v3_exports_service import main

    print()
    menu_utils.print_header("Generate Structural Archive Exports")
    try:
        main([])
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Generation failed: exit={exc.code}", level="error"))
            return
    except Exception as exc:
        print(status_messages.status(f"Generation failed: {exc}", level="error"))
        return
    out_root = Path(app_config.OUTPUT_DIR) / "publication" / "profile_v3"
    print(status_messages.status(f"Wrote: {relative_path(out_root)}", level="success"))
    prompt_utils.press_enter_to_continue()


def handle_generate_profile_v3_phase2_exports() -> None:
    """Generate structural archive draft exports from current runs."""
    from scytaledroid.Reporting.services.profile_v3_phase2_exports_service import main

    print()
    menu_utils.print_header("Generate Structural Archive Draft Exports")
    try:
        main([])
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Generation failed: exit={exc.code}", level="error"))
            return
    except Exception as exc:
        print(status_messages.status(f"Generation failed: {exc}", level="error"))
        return
    out_root = Path(app_config.OUTPUT_DIR) / "audit" / "profile_v3" / "phase2_exports"
    print(status_messages.status(f"Wrote: {relative_path(out_root)}", level="success"))
    prompt_utils.press_enter_to_continue()


def handle_profile_v3_integrity_gates() -> None:
    """Run structural archive integrity gates."""
    from scytaledroid.Reporting.services.profile_v3_integrity_gates_service import main

    print()
    menu_utils.print_header("Structural Archive Integrity Gates")
    try:
        main([])
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Gates failed: exit={exc.code}", level="error"))
            prompt_utils.press_enter_to_continue()
            return
    except Exception as exc:
        print(status_messages.status(f"Gates failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status("Structural archive gates: PASS", level="success"))
    prompt_utils.press_enter_to_continue()

def handle_generate_exploratory_risk_scoring() -> None:
    """Retired exploratory risk scoring action."""

    print()
    menu_utils.print_header("Exploratory Risk Scoring (Retired)")
    print(
        status_messages.status(
            "Exploratory risk scoring artifacts are retired from active menu workflows.",
            level="warn",
        )
    )
    print(
        status_messages.status(
            "Use the Paper 2 v2 results package and ML QA outputs for supported review artifacts.",
            level="info",
        )
    )
    prompt_utils.press_enter_to_continue()

def handle_print_manuscript_snapshot() -> None:
    """Retired manuscript snapshot action."""

    print()
    menu_utils.print_header("Manuscript Snapshot (Retired)")
    print(
        status_messages.status(
            "Manuscript snapshot output is retired from active menu workflows.",
            level="warn",
        )
    )
    print(
        status_messages.status(
            "Use Generate Results and publication QA/audit actions for supported review outputs.",
            level="info",
        )
    )
    prompt_utils.press_enter_to_continue()

def handle_refresh_phase_e_bundle() -> None:
    """Run ML over the frozen cohort and refresh publication artifacts inputs."""

    from scytaledroid.DynamicAnalysis.ml.artifact_bundle_writer import (
        write_phase_e_deliverables_bundle,
    )
    from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
        _select_fig_b1_exemplar_from_existing_or_inputs,
        run_ml_on_evidence_packs,
    )

    archive_dir = Path(app_config.DATA_DIR) / "archive"
    freeze_path = resolve_dataset_freeze_read_path()
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
        run_dir = resolve_dynamic_run_dir(run_id)
        if run_dir is None:
            return False
        if not (run_dir / "run_manifest.json").exists():
            return False
        out_dir = run_dir / "analysis" / "ml" / "v1"
        return (out_dir / "anomaly_scores_iforest.csv").exists() and (out_dir / "anomaly_scores_ocsvm.csv").exists()

    if not _pin_ok(rid):
        exemplar = _select_fig_b1_exemplar_from_existing_or_inputs(
            evidence_root=dynamic_evidence_root(),
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
    "fetch_tier1_status",
    "handle_cross_analysis_summary",
    "handle_export_freeze_anchored_csvs",
    "handle_generate_static_exposure_privacy_report",
    "handle_generate_paper2_results_v2_package",
    "handle_generate_exploratory_risk_scoring",
    "handle_generate_profile_v3_exports",
    "handle_profile_v3_integrity_gates",
    "handle_refresh_phase_e_bundle",
    "handle_tier1_audit_report",
    "handle_tier1_end_to_end",
    "handle_tier1_export_pack",
    "handle_tier1_quick_fix",
]
