"""Interactive launcher for Runtime Network Behavior Analysis reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml import status as ml_status
from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import (
    dataset_level_table_names,
    dataset_tables_dir,
    output_locked_runtime_bundle_root,
    output_publication_qa_dir,
)
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
    default_freeze_manifest_path,
    paper_artifacts_path,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards


def handle_runtime_network_behavior_analysis() -> None:
    """Report-only runtime network behavior launcher.

    Model lifecycle work stays in Machine Learning. This menu consumes existing
    locked runtime-ML outputs to generate report bundles, audits, and output maps.
    """

    while True:
        status = _runtime_status_snapshot()
        print()
        menu_utils.print_header("Runtime Network Behavior Analysis")
        print(
            summary_cards.format_summary_card(
                "Report Generation",
                [
                    summary_cards.summary_item("Evidence", str(status.get("locked_dataset") or "unknown"), value_style="accent"),
                    summary_cards.summary_item("QA", str(status.get("qa") or "unknown"), value_style="accent"),
                    summary_cards.summary_item("Bundle", str(status.get("bundle") or "unknown"), value_style="info"),
                    summary_cards.summary_item("Next", _recommended_runtime_next_step(status), value_style="hint"),
                ],
                footer="Model scoring and operational snapshots stay under Machine Learning; this screen generates report artifacts.",
            )
        )
        options = [
            menu_utils.MenuOption("1", "Generate locked runtime report bundle"),
            menu_utils.MenuOption("2", "Generate runtime behavior report"),
            menu_utils.MenuOption("3", "Run report QA check"),
            menu_utils.MenuOption("4", "Show output map"),
        ]
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", compact=True)
        choice = prompt_utils.menu_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if choice == "0":
            return
        if choice == "1":
            _generate_locked_runtime_bundle()
        elif choice == "2":
            _generate_runtime_behavior_report()
        elif choice == "3":
            _run_report_qa_check()
        elif choice == "4":
            _show_runtime_output_map()


def _runtime_status_snapshot() -> dict[str, object]:
    snapshot = ml_status.runtime_ml_status_snapshot()
    return {
        "locked_dataset": ml_status.freeze_status_summary(str(snapshot.get("freeze_status") or "")),
        "qa": str(snapshot.get("qa_status") or "unknown"),
        "bundle": str(snapshot.get("bundle_status") or "unknown"),
        "lockfile_state": str(snapshot.get("lockfile_state") or "unknown"),
        "ml_tables_ready": (
            int(snapshot.get("required_tables") or 0) > 0
            and int(snapshot.get("existing_tables") or 0) == int(snapshot.get("required_tables") or 0)
            and int(snapshot.get("stale_tables") or 0) == 0
        ),
    }


def _recommended_runtime_next_step(status: dict[str, object]) -> str:
    locked = str(status.get("locked_dataset") or "")
    lockfile_state = str(status.get("lockfile_state") or "")
    qa = str(status.get("qa") or "")
    bundle = str(status.get("bundle") or "")
    if not locked.startswith("ready"):
        return "Use Machine Learning to build the locked dataset"
    if lockfile_state != "ready" or not bool(status.get("ml_tables_ready")):
        return "Use Machine Learning to score the locked dataset"
    if qa.startswith(("missing", "stale", "blocked")):
        return "3) Run report QA check"
    if bundle.startswith(("missing", "stale")):
        return "1) Generate locked runtime report bundle"
    return "Ready for writing"


def _runtime_outputs_ready_for_bundle() -> tuple[bool, str]:
    status = _runtime_status_snapshot()
    next_step = _recommended_runtime_next_step(status)
    if next_step.startswith("Use Machine Learning"):
        return False, next_step
    if next_step.startswith("3)"):
        return False, "Run report QA check first"
    return True, ""


def _generate_locked_runtime_bundle() -> None:
    ok, blocker = _runtime_outputs_ready_for_bundle()
    if not ok:
        print(status_messages.status(f"Runtime report bundle is blocked: {blocker}.", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    freeze_path = default_freeze_manifest_path()
    artifacts_path = paper_artifacts_path(freeze_path)
    payload = _read_json(artifacts_path) or {}
    run_id = str(payload.get("fig_B1_run_id") or "").strip()
    interaction_tag = str(payload.get("interaction_tag") or "").strip() or None
    if not run_id:
        print(status_messages.status(f"Missing exemplar lockfile field in {artifacts_path}.", level="error"))
        print(status_messages.status("Use Machine Learning -> Score locked dataset first.", level="info"))
        prompt_utils.press_enter_to_continue()
        return
    print()
    menu_utils.print_section("Locked Runtime Report Bundle")
    menu_utils.print_metrics(
        [
            ("Input", freeze_path),
            ("Output", output_locked_runtime_bundle_root()),
            ("Contents", "tables, figures, appendix, manifests, source data hashes"),
        ]
    )
    if not prompt_utils.prompt_yes_no("Generate locked runtime report bundle now?", default=True):
        print(status_messages.status("Runtime report bundle generation canceled.", level="info"))
        return
    try:
        from scytaledroid.DynamicAnalysis.ml.artifact_bundle_writer import write_locked_runtime_deliverables_bundle

        artifacts = write_locked_runtime_deliverables_bundle(fig_b1_run_id=run_id, interaction_tag=interaction_tag)
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Runtime report bundle generation failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status(f"Wrote bundle: {artifacts.out_root}", level="success"))
    print(status_messages.status(f"Manifest: {artifacts.artifacts_manifest_json}", level="info"))
    prompt_utils.press_enter_to_continue()


def _generate_runtime_behavior_report() -> None:
    output_dir = _runtime_report_output_dir()
    print()
    menu_utils.print_section("Runtime Behavior Report")
    menu_utils.print_metrics(
        [
            ("Output", output_dir),
            ("Inputs", "dynamic evidence, PCAP-derived features, derived service context"),
            ("Mutation", "read-only report generation"),
        ]
    )
    if not prompt_utils.prompt_yes_no("Generate runtime behavior report now?", default=True):
        print(status_messages.status("Runtime behavior report generation canceled.", level="info"))
        return
    try:
        from scripts.db.report_dynamic_pcap_behavior_ml import generate_report

        summary = generate_report(output_dir=output_dir)
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Runtime behavior report generation failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    summary_path = str((summary.get("output_files") or {}).get("summary_json") or output_dir / "summary.json")
    print(status_messages.status(f"Wrote report: {summary_path}", level="success"))
    prompt_utils.press_enter_to_continue()


def _run_report_qa_check() -> None:
    print()
    menu_utils.print_section("Runtime Report QA")
    try:
        from scripts.publication.publication_ml_audit_report import main as audit_main

        result = audit_main()
    except SystemExit as exc:
        code = getattr(exc, "code", 1)
        if code not in (0, None):
            print(status_messages.status(f"Runtime report QA failed: {code}", level="error"))
            prompt_utils.press_enter_to_continue()
            return
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Runtime report QA failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    if result not in (None, 0):
        print(status_messages.status(f"Runtime report QA failed: exit={result}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status("Runtime report QA complete.", level="success"))
    prompt_utils.press_enter_to_continue()


def _show_runtime_output_map() -> None:
    print()
    menu_utils.print_header("Runtime Network Output Map")
    menu_utils.print_metrics(
        [
            ("Locked dataset anchor", default_freeze_manifest_path()),
            ("Locked dataset metadata", paper_artifacts_path(default_freeze_manifest_path())),
            ("Dataset ML tables", _dataset_tables_output_label()),
            ("Runtime bundle", output_locked_runtime_bundle_root()),
            ("Runtime QA", output_publication_qa_dir()),
            ("Runtime reports", Path(app_config.OUTPUT_DIR) / "reports" / "runtime_network_behavior"),
        ]
    )
    prompt_utils.press_enter_to_continue()


def _dataset_tables_output_label() -> str:
    names = dataset_level_table_names()
    preview = ", ".join(names[:3])
    if len(names) > 3:
        preview += ", ..."
    return f"{dataset_tables_dir()} ({len(names)} CSVs: {preview})"


def _runtime_report_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return Path(app_config.OUTPUT_DIR) / "reports" / "runtime_network_behavior" / stamp


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


__all__ = ["handle_runtime_network_behavior_analysis"]
