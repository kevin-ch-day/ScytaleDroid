"""Operator menu for unsupervised ML and static/dynamic scoring workflows."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml import status as ml_status
from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import (
    dataset_level_table_names,
    dataset_tables_dir,
    output_locked_runtime_bundle_artifacts_manifest_path,
    output_locked_runtime_bundle_root,
    output_publication_qa_dir,
)
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
    default_freeze_manifest_path,
    paper_artifacts_path,
    run_ml_on_evidence_packs,
)
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import (
    get_sampling_duration_seconds,
    load_run_inputs,
)
from scytaledroid.DynamicAnalysis.run_duration_tiers import classify_duration_tier
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    active_dataset_freeze_path,
    active_dataset_plan_path,
    active_research_cohort_archive_dir,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_manifest import (
    FreezeConfig,
    build_dataset_freeze_manifest,
    write_dataset_freeze_manifest,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards


def machine_learning_menu() -> None:
    """Render the Machine Learning menu."""

    while True:
        status = _ml_status_snapshot()
        print()
        menu_utils.print_header("Machine Learning")
        print(
            summary_cards.format_summary_card(
                "Runtime ML",
                [
                    summary_cards.summary_item("Dataset", _dataset_readiness_line(status), value_style="accent"),
                    summary_cards.summary_item("Models", "Isolation Forest + One-Class SVM", value_style="accent"),
                    summary_cards.summary_item("Inputs", "PCAP windows + static context", value_style="info"),
                    summary_cards.summary_item("Next", _recommended_next_step(status), value_style="hint"),
                ],
                footer="Locked dataset mode is for publication sets; operational snapshots are for current evidence review.",
            )
        )
        _print_ml_status(compact=True, snapshot=status)
        options = _menu_options()
        _print_ml_action_menu(options)
        choice = prompt_utils.menu_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if choice == "0":
            return
        action = _ACTIONS.get(choice)
        if action is None:
            print(status_messages.status("Invalid selection.", level="warn"))
            prompt_utils.press_enter_to_continue()
            continue
        action()


def _menu_options() -> list[menu_utils.MenuOption]:
    return [
        menu_utils.MenuOption("1", "Readiness and paths"),
        menu_utils.MenuOption("2", "Build locked dataset anchor"),
        menu_utils.MenuOption("3", "Score locked dataset"),
        menu_utils.MenuOption("4", "Run operational snapshot"),
        menu_utils.MenuOption("5", "Generate locked dataset bundle"),
        menu_utils.MenuOption("6", "QA audit"),
        menu_utils.MenuOption("7", "Runtime behavior report"),
        menu_utils.MenuOption("8", "Static + dynamic score report"),
        menu_utils.MenuOption("9", "Commands and output map"),
    ]


def _print_ml_action_menu(options: list[menu_utils.MenuOption]) -> None:
    by_key = {option.key: option for option in options}
    menu_utils.print_section("Publication Dataset")
    menu_utils.print_menu(
        [by_key[key] for key in ("1", "2", "3", "5", "6")],
        show_exit=False,
        show_descriptions=False,
        compact=True,
    )
    print()
    menu_utils.print_section("Operational Review")
    menu_utils.print_menu(
        [by_key[key] for key in ("4", "7", "8", "9")],
        show_exit=True,
        exit_label="Back",
        show_descriptions=False,
        compact=True,
    )


def _print_ml_status(*, compact: bool = False, snapshot: dict[str, object] | None = None) -> None:
    status = snapshot or _ml_status_snapshot()
    freeze_path = status["freeze_path"]
    artifacts_path = status["artifacts_path"]
    evidence_root = status["evidence_root"]
    plan_path = status["plan_path"]
    dataset_tables = status["dataset_tables"]
    required_tables = status["required_tables"]
    existing_tables = status["existing_tables"]
    stale_tables = status["stale_tables"]
    lockfile_state = str(status["lockfile_state"])
    qa_status = str(status["qa_status"])
    bundle_status = str(status["bundle_status"])
    freeze_status = str(status["freeze_status"])
    duration_status = str(status["duration_status"])
    if compact:
        metrics = _compact_status_metrics(
            freeze_path=freeze_path,
            plan_path=plan_path,
            evidence_root=evidence_root,
            freeze_status=freeze_status,
            duration_status=duration_status,
            artifacts_path=artifacts_path,
            existing_tables=int(existing_tables),
            required_tables=int(required_tables),
            stale_tables=int(stale_tables),
            lockfile_state=lockfile_state,
            qa_status=qa_status,
            bundle_status=bundle_status,
        )
    else:
        metrics = [
            ("Dataset anchor", _yes_no_path(freeze_path)),
            ("Dataset plan", _yes_no_path(plan_path)),
            ("Evidence root", _yes_no_path(evidence_root)),
            ("Locked dataset", _freeze_status_summary(freeze_status)),
            ("Run lengths", duration_status),
            ("Operational snapshots", _operational_snapshot_status()),
            ("ML lockfile", _path_state_label(artifacts_path, state=lockfile_state)),
            ("Dataset ML tables", _table_state_label(int(existing_tables), int(required_tables), int(stale_tables))),
            ("QA", qa_status),
            ("Locked bundle", bundle_status),
        ]
        metrics.extend(
            [
                ("Bundle root", _yes_no_path(output_locked_runtime_bundle_root())),
                ("QA outputs", _yes_no_path(output_publication_qa_dir())),
            ]
        )
    menu_utils.print_section("Status")
    menu_utils.print_metrics(metrics)
    if not compact:
        details = _freeze_status_details(freeze_status)
        if details:
            print()
            menu_utils.print_section("Dataset Blocker Detail")
            for line in details:
                print(f"  {line}")


def _ml_status_snapshot() -> dict[str, object]:
    freeze_path = _display_freeze_anchor_path()
    artifacts_path = paper_artifacts_path(freeze_path)
    qa_path = output_publication_qa_dir() / "ml_audit_report_v1.json"
    bundle_manifest = output_locked_runtime_bundle_artifacts_manifest_path()
    evidence_root = dynamic_evidence_root()
    plan_path = active_dataset_plan_path()
    dataset_tables = dataset_tables_dir()
    required_tables = dataset_level_table_names()
    existing_tables, stale_tables = _dataset_table_counts(
        dataset_tables=dataset_tables,
        required_tables=required_tables,
        anchor_path=freeze_path,
    )
    freeze_status = _freeze_build_status(freeze_path=freeze_path, plan_path=plan_path, evidence_root=evidence_root)
    duration_status = _duration_tier_status(freeze_path=freeze_path, evidence_root=evidence_root)
    return {
        "freeze_path": freeze_path,
        "artifacts_path": artifacts_path,
        "evidence_root": evidence_root,
        "plan_path": plan_path,
        "dataset_tables": dataset_tables,
        "required_tables": len(required_tables),
        "existing_tables": existing_tables,
        "stale_tables": stale_tables,
        "lockfile_state": _current_file_state(artifacts_path, anchor_path=freeze_path),
        "qa_status": _qa_status_label(qa_path, anchor_path=freeze_path),
        "bundle_status": _bundle_status_label(bundle_manifest, anchor_path=freeze_path, artifacts_path=artifacts_path),
        "freeze_status": freeze_status,
        "duration_status": duration_status,
    }


def _show_status() -> None:
    print()
    menu_utils.print_header("Machine Learning Status")
    _print_ml_status(compact=False)
    prompt_utils.press_enter_to_continue()


def _dataset_readiness_line(status: dict[str, object]) -> str:
    summary = _freeze_status_summary(str(status.get("freeze_status") or ""))
    if summary.startswith("ready"):
        return summary.replace("ready - ", "ready: ", 1)
    return summary


def _recommended_next_step(status: dict[str, object]) -> str:
    freeze_path = status.get("freeze_path")
    artifacts_path = status.get("artifacts_path")
    existing_tables = int(status.get("existing_tables") or 0)
    required_tables = int(status.get("required_tables") or 0)
    stale_tables = int(status.get("stale_tables") or 0)
    lockfile_state = str(status.get("lockfile_state") or "")
    qa_status = str(status.get("qa_status") or "")
    bundle_status = str(status.get("bundle_status") or "")
    freeze_summary = _freeze_status_summary(str(status.get("freeze_status") or ""))
    if not isinstance(freeze_path, Path) or not freeze_path.exists():
        return "2) Build locked dataset anchor"
    if not freeze_summary.startswith("ready"):
        return "1) Review readiness blockers"
    if not isinstance(artifacts_path, Path) or lockfile_state != "ready":
        return "3) Score locked dataset"
    if required_tables and (existing_tables < required_tables or stale_tables):
        return "3) Score locked dataset"
    if qa_status.startswith(("missing", "stale", "blocked")):
        return "6) QA audit"
    if bundle_status.startswith(("missing", "stale")):
        return "5) Generate locked dataset bundle"
    if qa_status.startswith("ready"):
        return "Ready for review"
    return "6) QA audit"


def _build_freeze_anchor() -> None:
    freeze_path = _display_freeze_anchor_path()
    plan_path = active_dataset_plan_path()
    evidence_root = dynamic_evidence_root()
    missing: list[str] = []
    if not plan_path.exists():
        missing.append(f"dataset plan: {_relative_path(plan_path)}")
    if not evidence_root.exists():
        missing.append(f"evidence root: {_relative_path(evidence_root)}")
    if missing:
        print(status_messages.status("Cannot build locked ML dataset anchor; required input is missing.", level="error"))
        for item in missing:
            print(status_messages.status(item, level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    alignment_ok, alignment_message = _plan_cohort_alignment(plan_path)
    if not alignment_ok:
        print(status_messages.status("Cannot build locked ML dataset anchor; dataset plan does not match the active cohort.", level="error"))
        print(status_messages.status(alignment_message, level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    menu_utils.print_header("Build Locked ML Dataset Anchor")
    rows = [
        ("Dataset plan", _relative_path(plan_path)),
        ("Evidence root", _relative_path(evidence_root)),
        ("Output dir", _relative_path(active_research_cohort_archive_dir())),
        ("Canonical anchor", _relative_path(freeze_path)),
        ("Current anchor", _freeze_status_summary(_freeze_build_status(freeze_path=freeze_path, plan_path=plan_path, evidence_root=evidence_root)) if freeze_path.exists() else "missing"),
    ]
    menu_utils.print_metrics(rows)
    if freeze_path.exists():
        print(status_messages.status("A new timestamped anchor will be written and the canonical anchor will be updated.", level="info"))
    if not prompt_utils.prompt_yes_no(
        "Build the locked ML dataset anchor now? This writes derived metadata under data/archive.",
        default=False,
    ):
        print(status_messages.status("Locked dataset anchor build canceled.", level="info"))
        return
    try:
        out_path = write_dataset_freeze_manifest(
            evidence_root=evidence_root,
            out_dir=active_research_cohort_archive_dir(),
            also_write_canonical=True,
            cfg=_ml_freeze_config(),
        )
    except Exception as exc:
        print(status_messages.status(f"Locked dataset anchor build failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status(f"Wrote timestamped anchor: {_relative_path(out_path)}", level="success"))
    print(status_messages.status(f"Canonical anchor: {_relative_path(freeze_path)}", level="success"))
    prompt_utils.press_enter_to_continue()


def _run_freeze_scoring() -> None:
    freeze_path = default_freeze_manifest_path()
    if not freeze_path.exists():
        print(status_messages.status(f"Missing locked dataset anchor: {_relative_path(freeze_path)}", level="error"))
        print(status_messages.status("Use Machine Learning -> 2 to build the locked dataset anchor first.", level="info"))
        prompt_utils.press_enter_to_continue()
        return
    if not prompt_utils.prompt_yes_no(
        "Run locked-dataset unsupervised ML scoring now? This writes derived ML outputs.",
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


def _run_operational_snapshot() -> None:
    evidence_root = dynamic_evidence_root()
    if not evidence_root.exists():
        print(status_messages.status(f"Missing evidence root: {_relative_path(evidence_root)}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print()
    menu_utils.print_header("Operational ML Snapshot")
    menu_utils.print_metrics(
        [
            ("Evidence root", _relative_path(evidence_root)),
            ("Selector", "dataset-tier valid evidence packs"),
            ("Output", Path(app_config.OUTPUT_DIR) / "operational" / "<snapshot_id>"),
            ("Mode", "operational/query; not a locked dataset"),
        ]
    )
    if not prompt_utils.prompt_yes_no(
        "Run operational ML snapshot now? This writes derived outputs under output/operational.",
        default=False,
    ):
        print(status_messages.status("Operational ML snapshot canceled.", level="info"))
        return
    try:
        from scytaledroid.DynamicAnalysis.ml.query_mode_runner import run_ml_query_mode
        from scytaledroid.DynamicAnalysis.ml.selectors import QueryParams, QuerySelector

        selector = QuerySelector(
            evidence_root=evidence_root,
            params=QueryParams(
                tier="dataset",
                include_unknown_mode=False,
                pool_versions=False,
                require_valid_dataset_run=True,
            ),
            allow_db_index=False,
        )
        selection = selector.select()
        stats = run_ml_query_mode(selection=selection, reuse_existing_outputs=True)
    except Exception as exc:
        print(status_messages.status(f"Operational ML snapshot failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status("Operational ML snapshot finished.", level="success"))
    menu_utils.print_metrics(
        [
            ("Groups seen", stats.groups_seen),
            ("Groups trained", stats.groups_trained),
            ("Runs scored", stats.runs_scored),
            ("Runs skipped", stats.runs_skipped),
            ("Snapshot", _relative_path(stats.snapshot_dir)),
        ]
    )
    prompt_utils.press_enter_to_continue()


def _generate_phase_e_bundle() -> None:
    freeze_path = default_freeze_manifest_path()
    artifacts_path = paper_artifacts_path(freeze_path)
    if not freeze_path.exists():
        print(status_messages.status(f"Missing locked dataset anchor: {_relative_path(freeze_path)}", level="error"))
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
            write_locked_runtime_deliverables_bundle,
        )

        artifacts = write_locked_runtime_deliverables_bundle(
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
        ("Build locked dataset anchor", "Machine Learning -> 2"),
        ("Locked dataset scoring", "Machine Learning -> 3"),
        ("Operational snapshot", "Machine Learning -> 4"),
        ("Locked dataset bundle", "Machine Learning -> 5"),
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
            ("Dataset tables", _dataset_tables_output_label()),
            ("Operational snapshots", Path(app_config.OUTPUT_DIR) / "operational"),
            ("Locked dataset bundle", output_locked_runtime_bundle_root()),
            ("QA reports", output_publication_qa_dir()),
            ("Audit reports", Path(app_config.OUTPUT_DIR) / "audit"),
        ]
    )
    prompt_utils.press_enter_to_continue()


def _dataset_tables_output_label() -> str:
    names = dataset_level_table_names()
    preview = ", ".join(names[:3])
    if len(names) > 3:
        preview += ", ..."
    return f"{dataset_tables_dir()} ({len(names)} CSVs: {preview})"


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


def _compact_status_metrics(
    *,
    freeze_path: Path,
    plan_path: Path,
    evidence_root: Path,
    freeze_status: str,
    duration_status: str,
    artifacts_path: Path,
    existing_tables: int,
    required_tables: int,
    stale_tables: int = 0,
    lockfile_state: str | None = None,
    qa_status: str | None = None,
    bundle_status: str | None = None,
) -> list[tuple[str, object]]:
    return [
        ("Dataset anchor", _present_or_missing(freeze_path)),
        ("Inputs", f"plan {_present_or_missing(plan_path)} · evidence {_present_or_missing(evidence_root)}"),
        ("Locked dataset", _freeze_status_summary(freeze_status)),
        ("Run lengths", duration_status),
        ("Operational", _operational_snapshot_status(compact=True)),
        ("ML lockfile", str(lockfile_state or _current_file_state(artifacts_path, anchor_path=freeze_path))),
        ("ML tables", _table_state_label(existing_tables, required_tables, stale_tables)),
        ("QA", str(qa_status or "unknown")),
        ("Bundle", str(bundle_status or "unknown")),
    ]


def _present_or_missing(path: Path) -> str:
    return "ready" if path.exists() else "missing"


def _current_file_state(path: Path, *, anchor_path: Path) -> str:
    return ml_status.current_file_state(path, anchor_path=anchor_path)


def _path_state_label(path: Path, *, state: str) -> str:
    state_text = str(state or "unknown").strip()
    if state_text == "ready":
        return f"ready - {_relative_path(path)}"
    if state_text == "missing":
        return f"missing - {_relative_path(path)}"
    if state_text == "stale":
        return "stale - rerun locked dataset scoring"
    return f"{state_text} - {_relative_path(path)}"


def _dataset_table_counts(
    *,
    dataset_tables: Path,
    required_tables: tuple[str, ...],
    anchor_path: Path,
) -> tuple[int, int]:
    return ml_status.dataset_table_counts(
        dataset_tables=dataset_tables,
        required_tables=required_tables,
        anchor_path=anchor_path,
    )


def _table_state_label(existing_tables: int, required_tables: int, stale_tables: int) -> str:
    return ml_status.table_state_label(existing_tables, required_tables, stale_tables)


def _qa_status_label(path: Path, *, anchor_path: Path) -> str:
    return ml_status.qa_status_label(path, anchor_path=anchor_path)


def _bundle_status_label(path: Path, *, anchor_path: Path, artifacts_path: Path) -> str:
    return ml_status.bundle_status_label(path, anchor_path=anchor_path, artifacts_path=artifacts_path)


def _freeze_status_summary(status: str) -> str:
    return ml_status.freeze_status_summary(status)


def _duration_tier_status(*, freeze_path: Path, evidence_root: Path) -> str:
    return ml_status.duration_tier_status(freeze_path=freeze_path, evidence_root=evidence_root)


def _freeze_status_details(status: str) -> list[str]:
    return ml_status.freeze_status_details(status)


def _extract_app_count(status: str) -> int | None:
    return ml_status.extract_app_count(status)


def _ml_freeze_config() -> FreezeConfig:
    return ml_status.ml_freeze_config()


def _operational_snapshot_status(*, compact: bool = False) -> str:
    root = Path(app_config.OUTPUT_DIR) / "operational"
    if not root.exists():
        return "none" if compact else f"none - {_relative_path(root)}"
    snapshots = [p for p in root.iterdir() if p.is_dir()]
    if not snapshots:
        return "none" if compact else f"none - {_relative_path(root)}"
    latest = max(snapshots, key=lambda p: p.stat().st_mtime)
    if compact:
        return f"{len(snapshots)} snapshot(s) · latest {latest.name}"
    return f"{len(snapshots)} snapshot(s), latest {_relative_path(latest)}"


def _plan_packages(path: Path) -> set[str] | None:
    payload = _read_json(path)
    apps = payload.get("apps") if isinstance(payload, dict) else None
    if not isinstance(apps, dict):
        return None
    return {str(pkg).strip().lower() for pkg in apps if str(pkg).strip()}


def _plan_cohort_alignment(plan_path: Path) -> tuple[bool, str]:
    plan_packages = _plan_packages(plan_path)
    if plan_packages is None:
        return False, f"invalid dataset plan: {_relative_path(plan_path)}"
    expected = {str(pkg).strip().lower() for pkg in active_research_cohort_packages() if str(pkg).strip()}
    if not expected:
        return True, "unknown - active cohort packages unavailable"
    extra = sorted(plan_packages - expected)
    missing = sorted(expected - plan_packages)
    if not extra and not missing:
        return True, f"ok - {len(plan_packages)} app(s)"
    parts: list[str] = []
    if extra:
        suffix = "..." if len(extra) > 3 else ""
        parts.append(f"extra={len(extra)} ({', '.join(extra[:3])}{suffix})")
    if missing:
        suffix = "..." if len(missing) > 3 else ""
        parts.append(f"missing={len(missing)} ({', '.join(missing[:3])}{suffix})")
    return False, "blocked - " + "; ".join(parts)


def _freeze_build_status(*, freeze_path: Path, plan_path: Path, evidence_root: Path) -> str:
    if freeze_path.exists():
        payload = _read_json(freeze_path) or {}
        run_count = len(payload.get("included_run_ids") or []) if isinstance(payload.get("included_run_ids"), list) else 0
        app_count = len(payload.get("apps") or {}) if isinstance(payload.get("apps"), dict) else 0
        max_age_days = None
        quota = payload.get("quota_policy") if isinstance(payload.get("quota_policy"), dict) else {}
        if isinstance(quota, dict):
            max_age_days = quota.get("max_age_days")
        if app_count and run_count:
            suffix = f" · {max_age_days}-day window" if max_age_days else ""
            return f"ready - {app_count} apps · {run_count} runs{suffix} · selected build groups"
        return "ready - anchor exists"
    if not plan_path.exists():
        return "blocked - dataset plan missing"
    if not evidence_root.exists():
        return "blocked - evidence root missing"
    alignment_ok, alignment_message = _plan_cohort_alignment(plan_path)
    if not alignment_ok:
        return alignment_message
    try:
        payload = build_dataset_freeze_manifest(
            dataset_plan_path=plan_path,
            evidence_root=evidence_root,
            cfg=_ml_freeze_config(),
        )
    except Exception as exc:
        return f"blocked - {exc}"
    run_count = len(payload.get("included_run_ids") or [])
    app_count = len(payload.get("apps") or {})
    return f"ready - {app_count} apps · {run_count} runs · selected build groups"


def _display_freeze_anchor_path() -> Path:
    resolved = default_freeze_manifest_path()
    if resolved.exists():
        return resolved
    return active_dataset_freeze_path()


_ACTIONS: dict[str, Callable[[], None]] = {
    "1": _show_status,
    "2": _build_freeze_anchor,
    "3": _run_freeze_scoring,
    "4": _run_operational_snapshot,
    "5": _generate_phase_e_bundle,
    "6": _run_ml_qa_audit,
    "7": _run_runtime_behavior_ml_report,
    "8": _run_static_dynamic_score_report,
    "9": _show_command_map,
}


__all__ = ["machine_learning_menu"]
