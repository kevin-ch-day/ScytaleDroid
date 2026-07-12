"""Operator menu for unsupervised ML and static/dynamic scoring workflows."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import (
    dataset_tables_dir,
    output_phase_e_bundle_root,
    output_publication_qa_dir,
)
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
    default_freeze_manifest_path,
    paper_artifacts_path,
    run_ml_on_evidence_packs,
)
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    active_dataset_freeze_path,
    active_dataset_plan_path,
    active_research_cohort_archive_dir,
)
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_manifest import (
    write_dataset_freeze_manifest,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards


def machine_learning_menu() -> None:
    """Render the Machine Learning menu."""

    while True:
        print()
        menu_utils.print_header("Machine Learning")
        print(
            summary_cards.format_summary_card(
                "Unsupervised Runtime Analysis",
                [
                    summary_cards.summary_item("Runtime", "Isolation Forest / One-Class SVM over PCAP windows", value_style="accent"),
                    summary_cards.summary_item("Static context", "Paper 1 style static posture and MASVS-derived scores", value_style="accent"),
                    summary_cards.summary_item("Fusion", "static score + dynamic behavior score for app-level interpretation", value_style="info"),
                ],
                footer="Use this menu for Paper 2 style ML, QA, and static/dynamic scoring outputs.",
            )
        )
        _print_ml_status(compact=True)
        options = [
            menu_utils.MenuOption("1", "Show ML readiness and output paths"),
            menu_utils.MenuOption("2", "Build dataset freeze anchor"),
            menu_utils.MenuOption("3", "Run freeze-anchored unsupervised ML scoring"),
            menu_utils.MenuOption("4", "Generate Paper 2 ML deliverable bundle"),
            menu_utils.MenuOption("5", "Run ML QA audit"),
            menu_utils.MenuOption("6", "Generate runtime behavior ML report"),
            menu_utils.MenuOption("7", "Generate static + dynamic ML score report"),
            menu_utils.MenuOption("8", "Show commands and output map"),
        ]
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        choice = prompt_utils.menu_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if choice == "0":
            return
        action = _ACTIONS.get(choice)
        if action is None:
            print(status_messages.status("Invalid selection.", level="warn"))
            prompt_utils.press_enter_to_continue()
            continue
        action()


def _print_ml_status(*, compact: bool = False) -> None:
    freeze_path = _display_freeze_anchor_path()
    artifacts_path = paper_artifacts_path(freeze_path)
    evidence_root = dynamic_evidence_root()
    plan_path = active_dataset_plan_path()
    dataset_tables = dataset_tables_dir()
    required_tables = (
        "anomaly_prevalence_per_app_phase.csv",
        "model_overlap_per_run.csv",
        "transport_mix_by_phase.csv",
        "static_dynamic_stratification_per_app.csv",
    )
    existing_tables = sum(1 for name in required_tables if (dataset_tables / name).exists())
    metrics = [
        ("Freeze anchor", _yes_no_path(freeze_path)),
        ("Dataset plan", _yes_no_path(plan_path)),
        ("Evidence root", _yes_no_path(evidence_root)),
        ("ML lockfile", _yes_no_path(artifacts_path)),
        ("Dataset ML tables", f"{existing_tables}/{len(required_tables)}"),
    ]
    if not compact:
        metrics.extend(
            [
                ("Internal bundle", _yes_no_path(output_phase_e_bundle_root())),
                ("QA outputs", _yes_no_path(output_publication_qa_dir())),
            ]
        )
    menu_utils.print_section("Status")
    menu_utils.print_metrics(metrics)


def _show_status() -> None:
    print()
    menu_utils.print_header("Machine Learning Status")
    _print_ml_status(compact=False)
    prompt_utils.press_enter_to_continue()


def _build_freeze_anchor() -> None:
    freeze_path = _display_freeze_anchor_path()
    plan_path = active_dataset_plan_path()
    evidence_root = dynamic_evidence_root()
    if freeze_path.exists():
        print(status_messages.status(f"Freeze anchor already exists: {_relative_path(freeze_path)}", level="info"))
        print(status_messages.status("Existing freeze anchors are not overwritten from this menu.", level="info"))
        prompt_utils.press_enter_to_continue()
        return
    missing: list[str] = []
    if not plan_path.exists():
        missing.append(f"dataset plan: {_relative_path(plan_path)}")
    if not evidence_root.exists():
        missing.append(f"evidence root: {_relative_path(evidence_root)}")
    if missing:
        print(status_messages.status("Cannot build ML freeze anchor; required input is missing.", level="error"))
        for item in missing:
            print(status_messages.status(item, level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    menu_utils.print_header("Build Dataset Freeze Anchor")
    menu_utils.print_metrics(
        [
            ("Dataset plan", _relative_path(plan_path)),
            ("Evidence root", _relative_path(evidence_root)),
            ("Output dir", _relative_path(active_research_cohort_archive_dir())),
            ("Canonical freeze", _relative_path(freeze_path)),
        ]
    )
    if not prompt_utils.prompt_yes_no(
        "Build the ML freeze anchor now? This writes derived freeze metadata under data/archive.",
        default=False,
    ):
        print(status_messages.status("Freeze anchor build canceled.", level="info"))
        return
    try:
        out_path = write_dataset_freeze_manifest(
            evidence_root=evidence_root,
            out_dir=active_research_cohort_archive_dir(),
            also_write_canonical=True,
        )
    except Exception as exc:
        print(status_messages.status(f"Freeze anchor build failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status(f"Wrote timestamped freeze: {_relative_path(out_path)}", level="success"))
    print(status_messages.status(f"Canonical freeze: {_relative_path(freeze_path)}", level="success"))
    prompt_utils.press_enter_to_continue()


def _run_freeze_scoring() -> None:
    freeze_path = default_freeze_manifest_path()
    if not freeze_path.exists():
        print(status_messages.status(f"Missing freeze anchor: {_relative_path(freeze_path)}", level="error"))
        print(status_messages.status("Use Machine Learning -> 2 to build the dataset freeze anchor first.", level="info"))
        prompt_utils.press_enter_to_continue()
        return
    if not prompt_utils.prompt_yes_no(
        "Run freeze-anchored unsupervised ML scoring now? This writes derived ML outputs.",
        default=False,
    ):
        print(status_messages.status("ML scoring canceled.", level="info"))
        return
    try:
        stats = run_ml_on_evidence_packs(freeze_manifest_path=freeze_path, reuse_existing_outputs=True)
    except Exception as exc:
        print(status_messages.status(f"ML scoring failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status("ML scoring finished.", level="success"))
    menu_utils.print_metrics(
        [
            ("Apps seen", stats.apps_seen),
            ("Apps trained", stats.apps_trained),
            ("Runs scored", stats.runs_scored),
            ("Runs reused", stats.runs_reused),
            ("Runs skipped", stats.runs_skipped),
        ]
    )
    prompt_utils.press_enter_to_continue()


def _generate_phase_e_bundle() -> None:
    freeze_path = default_freeze_manifest_path()
    artifacts_path = paper_artifacts_path(freeze_path)
    if not freeze_path.exists():
        print(status_messages.status(f"Missing freeze anchor: {_relative_path(freeze_path)}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    payload = _read_json(artifacts_path)
    run_id = str((payload or {}).get("fig_B1_run_id") or "").strip()
    interaction_tag = str((payload or {}).get("interaction_tag") or "").strip() or None
    if not run_id:
        print(status_messages.status(f"Missing Fig B1 exemplar lock: {_relative_path(artifacts_path)}", level="error"))
        print(status_messages.status("Run freeze-anchored ML scoring first so the exemplar lock can be selected.", level="info"))
        prompt_utils.press_enter_to_continue()
        return
    try:
        from scytaledroid.DynamicAnalysis.ml.artifact_bundle_writer import (
            write_phase_e_deliverables_bundle,
        )

        artifacts = write_phase_e_deliverables_bundle(
            fig_b1_run_id=run_id,
            interaction_tag=interaction_tag,
        )
    except Exception as exc:
        print(status_messages.status(f"Bundle generation failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status(f"Wrote bundle: {_relative_path(artifacts.out_root)}", level="success"))
    print(status_messages.status(f"Manifest: {_relative_path(artifacts.artifacts_manifest_json)}", level="info"))
    prompt_utils.press_enter_to_continue()


def _run_ml_qa_audit() -> None:
    _run_action(
        title="ML QA Audit",
        action=lambda: __import__(
            "scripts.publication.publication_ml_audit_report",
            fromlist=["main"],
        ).main(),
        success_path=output_publication_qa_dir(),
    )


def _run_runtime_behavior_ml_report() -> None:
    _run_action(
        title="Runtime Behavior ML Report",
        action=lambda: __import__(
            "scripts.db.report_dynamic_pcap_behavior_ml",
            fromlist=["main"],
        ).main([]),
    )


def _run_static_dynamic_score_report() -> None:
    _run_action(
        title="Static + Dynamic ML Score Report",
        action=lambda: __import__(
            "scripts.db.report_multimodal_static_dynamic_ml",
            fromlist=["main"],
        ).main([]),
    )


def _show_command_map() -> None:
    print()
    menu_utils.print_header("Machine Learning Commands")
    rows = [
        ("Build freeze anchor", "Machine Learning -> 2"),
        ("Freeze scoring", "Machine Learning -> 3"),
        ("Phase E bundle", "Machine Learning -> 4"),
        ("ML QA audit", "PYTHONPATH=. python scripts/publication/publication_ml_audit_report.py"),
        ("Runtime behavior ML", "PYTHONPATH=. python scripts/db/report_dynamic_pcap_behavior_ml.py"),
        ("Static + dynamic ML", "PYTHONPATH=. python scripts/db/report_multimodal_static_dynamic_ml.py"),
    ]
    menu_utils.print_metrics(rows)
    print()
    menu_utils.print_section("Key Outputs")
    menu_utils.print_metrics(
        [
            ("Per-run ML", f"{dynamic_evidence_root()}/<run_id>/analysis/ml/v1"),
            ("Dataset tables", dataset_tables_dir()),
            ("Internal bundle", output_phase_e_bundle_root()),
            ("QA reports", output_publication_qa_dir()),
            ("Audit reports", Path(app_config.OUTPUT_DIR) / "audit"),
        ]
    )
    prompt_utils.press_enter_to_continue()


def _run_action(*, title: str, action: Callable[[], object], success_path: Path | None = None) -> None:
    print()
    menu_utils.print_header(title)
    try:
        result = action()
    except SystemExit as exc:
        code = _system_exit_code(exc)
        if code != 0:
            detail = str(getattr(exc, "code", "") or "").strip()
            suffix = f": {detail}" if detail and not detail.isdigit() else f": exit={code}"
            print(status_messages.status(f"{title} failed{suffix}", level="error"))
            prompt_utils.press_enter_to_continue()
            return
    except Exception as exc:
        print(status_messages.status(f"{title} failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    if success_path is not None:
        print(status_messages.status(f"Wrote: {_relative_path(success_path)}", level="success"))
    elif result not in (None, 0):
        print(status_messages.status(f"Completed: {result}", level="success"))
    else:
        print(status_messages.status(f"{title} complete.", level="success"))
    prompt_utils.press_enter_to_continue()


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _system_exit_code(exc: SystemExit) -> int:
    raw = getattr(exc, "code", 1)
    if raw is None:
        return 0
    if isinstance(raw, int):
        return int(raw)
    try:
        return int(str(raw).strip())
    except Exception:
        return 1


def _relative_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


def _yes_no_path(path: Path) -> str:
    prefix = "yes" if path.exists() else "no"
    return f"{prefix} - {_relative_path(path)}"


def _display_freeze_anchor_path() -> Path:
    resolved = default_freeze_manifest_path()
    if resolved.exists():
        return resolved
    return active_dataset_freeze_path()


_ACTIONS: dict[str, Callable[[], None]] = {
    "1": _show_status,
    "2": _build_freeze_anchor,
    "3": _run_freeze_scoring,
    "4": _generate_phase_e_bundle,
    "5": _run_ml_qa_audit,
    "6": _run_runtime_behavior_ml_report,
    "7": _run_static_dynamic_score_report,
    "8": _show_command_map,
}


__all__ = ["machine_learning_menu"]
