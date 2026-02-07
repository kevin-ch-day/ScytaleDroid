"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

import os
import io
import json
import contextlib
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuItemSpec, MenuSpec
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .static_analysis_menu_helpers import (
    apply_command_overrides,
    ask_run_controls,
    choose_scope,
    collect_view_options,
    confirm_reset,
    prompt_session_label,
    render_reset_outcome,
    render_version_diff,
    resolve_last_selection,
)

if TYPE_CHECKING:
    from ..commands.models import Command



def static_analysis_menu() -> None:
    from scytaledroid.Database.db_utils import schema_gate
    from scytaledroid.Database.db_utils.menus import query_runner
    from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data
    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from scytaledroid.StaticAnalysis.services import static_service
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    from ..commands import COMMANDS, get_command, iter_commands
    from ..core.models import RunParameters
    from ..core.run_prompts import default_custom_tests, prompt_advanced_options

    ok, message, detail = schema_gate.static_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Tier-1 schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    base_dir = Path(app_config.DATA_DIR) / "device_apks"
    groups = tuple(group_artifacts(base_dir))
    if not groups:
        print(
            status_messages.status(
                "No harvested APK groups found. Run Device Analysis → 2 to pull artifacts.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    workflow_commands = tuple(cmd for cmd in iter_commands("scan") if cmd.section == "workflow")
    selectable_ids = [cmd.id for cmd in workflow_commands]

    if not selectable_ids:
        print(status_messages.status("No static analysis commands are registered.", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    default_key = workflow_commands[0].id if workflow_commands else None
    default_choice = default_key or selectable_ids[0]

    while True:
        print()
        menu_utils.print_header("Android APK Static Analysis")
        selected_apks = static_scope_service.count()
        if selected_apks:
            print(
                status_messages.status(
                    f"Library selection: {selected_apks} APKs marked. You can run scans on this selection.",
                    level="info",
                )
            )
        workflow_spec = MenuSpec(
            items=[_command_option(cmd) for cmd in workflow_commands],
            show_exit=False,
            show_descriptions=False,
        )
        if workflow_commands:
            print("Primary actions")
            print("---------------")
        menu_utils.render_menu(workflow_spec)
        print()
        back_spec = MenuSpec(
            items=[],
            exit_label="Back",
            show_exit=True,
            show_descriptions=False,
        )
        menu_utils.render_menu(back_spec)
        choice_pool = selectable_ids + ["0"]
        choice = prompt_utils.get_choice(choice_pool, default=default_choice)
        if choice == "6" and "5" in selectable_ids:
            choice = "5"

        if choice == "0":
            break

        command = get_command(choice)
        if command is None:
            print(status_messages.status("Unsupported option selected.", level="warn"))
            continue

        if command.kind == "readonly":
            if command.handler:
                command.handler()
            else:
                print(status_messages.status(f"{command.title} not yet implemented.", level="warn"))
            continue

        if not command.profile:
            print(status_messages.status("Command missing run profile.", level="error"))
            continue

        selection = None
        if command.id == "5":
            _run_dataset_batch(
                groups,
                base_dir,
                command,
                static_service,
                query_runner,
                reset_static_analysis_data,
            )
            continue
        if command.id == "3":
            selection = resolve_last_selection(groups)
            if selection is None:
                prompt_utils.press_enter_to_continue()
                continue
        elif command.id == "4":
            selection = resolve_last_selection(groups)
            if selection is None:
                prompt_utils.press_enter_to_continue()
                continue
            render_version_diff(selection.label)
            prompt_utils.press_enter_to_continue()
            continue
        else:
            selection = choose_scope(groups)
            if selection is None:
                continue
            if command.force_app_scope and selection.scope != "app":
                print(status_messages.status("This workflow requires choosing a single app.", level="warn"))
                continue

        _show_details, show_splits, show_artifacts, return_to_menu = collect_view_options(command)
        if return_to_menu:
            continue

        params = RunParameters(
            profile=command.profile,
            scope=selection.scope,
            scope_label=selection.label,
            selected_tests=(
                default_custom_tests() if command.profile == "custom" else tuple()
            ),
        )
        if show_artifacts:
            params = replace(params, artifact_detail=True)
        params = replace(params, show_split_summaries=show_splits)

        while True:
            action = ask_run_controls()
            if action == "back":
                break
            if action == "advanced":
                params = prompt_advanced_options(params)
                continue

            effective_params = apply_command_overrides(params, command)

            if command.prompt_reset and confirm_reset():
                render_reset_outcome(reset_static_analysis_data(include_harvest=False))

            if command.persist and not effective_params.dry_run:
                effective_params = prompt_session_label(effective_params)

            try:
                spec = build_static_run_spec(
                    selection=selection,
                    params=effective_params,
                    base_dir=base_dir,
                    run_mode="interactive",
                    quiet=False,
                    noninteractive=False,
                )
                outcome = execute_run_spec(spec)
            except static_service.StaticServiceError as exc:
                print(status_messages.status(f"Static analysis failed: {exc}", level="error"))
                log.error(f"Static analysis run failed: {exc}", category="static")
                prompt_utils.press_enter_to_continue()
                break

            if command.auto_verify and not effective_params.dry_run:
                session_key = getattr(outcome, "session_stamp", None) if outcome else None
                if not session_key:
                    session_key = effective_params.session_stamp
                if session_key:
                    query_runner.render_session_digest(session_key)
                prompt_utils.press_enter_to_continue("Press Enter to continue…")
            break


def _command_option(command: Command) -> menu_utils.MenuOption:
    return MenuItemSpec(
        key=command.id,
        label=command.title,
        description=command.description,
        badge=None,
        hint=None,
    )



__all__ = ["static_analysis_menu"]


def _resolve_batch_groups(groups, dataset_pkgs: set[str]) -> list[object]:
    # Batch determinism: select one "best" artifact group per package (newest by session stamp + mtime).
    # We explicitly avoid env-driven selection here to keep batch behavior stable and reviewable.
    def _artifact_mtime(artifact) -> float:
        path_obj = getattr(artifact, "path", None)
        if isinstance(path_obj, Path):
            target = path_obj
        elif isinstance(path_obj, str):
            target = Path(path_obj)
        else:
            return 0.0
        try:
            return float(target.stat().st_mtime)
        except (OSError, ValueError):
            return 0.0

    def _group_latest_mtime(group) -> float:
        return max((_artifact_mtime(a) for a in getattr(group, "artifacts", []) or []), default=0.0)

    def _group_recency_key(group) -> tuple[int, str, float]:
        stamp = str(getattr(group, "session_stamp", None) or "")
        return (1 if stamp else 0, stamp, _group_latest_mtime(group))

    def _group_has_any_existing_artifact(group) -> bool:
        for artifact in getattr(group, "artifacts", []) or []:
            path_obj = getattr(artifact, "path", None)
            try:
                if isinstance(path_obj, Path) and path_obj.exists():
                    return True
                if isinstance(path_obj, str) and Path(path_obj).exists():
                    return True
            except Exception:
                continue
        return False

    by_pkg: dict[str, object] = {}
    for group in groups:
        pkg = getattr(group, "package_name", None)
        if not pkg:
            continue
        pkg_l = str(pkg).lower()
        if pkg_l not in dataset_pkgs:
            continue
        if not _group_has_any_existing_artifact(group):
            continue
        cur = by_pkg.get(pkg_l)
        if cur is None or _group_recency_key(group) > _group_recency_key(cur):
            by_pkg[pkg_l] = group
    return list(by_pkg.values())


def _derive_persistence_audit(outcome, static_run_id: int | None) -> dict[str, object]:
    persistence_failed = bool(getattr(outcome, "persistence_failed", False))
    canonical_failed = bool(getattr(outcome, "canonical_failed", False))
    paper_grade_status = getattr(outcome, "paper_grade_status", "ok")
    evidence_path = (
        str(Path("evidence") / "static_runs" / str(static_run_id))
        if static_run_id is not None
        else None
    )
    return {
        "paper_grade": paper_grade_status,
        "persistence_failed": persistence_failed,
        "canonical_failed": canonical_failed,
        "evidence_path": evidence_path,
        "audit_notes": list(getattr(outcome, "audit_notes", []) or []),
    }


def _write_batch_summary(
    *,
    batch_summary_path: Path,
    batch_id: str,
    batch_rows: list[dict[str, object]],
    apps_total: int,
    apps_completed: int,
    apps_failed: int,
    ended_at: str | None,
) -> None:
    payload = {
        "batch_id": batch_id,
        "started_at": batch_rows[0]["started_at"] if batch_rows else None,
        "ended_at": ended_at,
        "apps_total": apps_total,
        "apps_completed": apps_completed,
        "apps_failed": apps_failed,
        "rows": batch_rows,
    }
    batch_summary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _execute_batch_run(
    *,
    group: object,
    selection_label: str,
    selection: ScopeSelection,
    effective_params: RunParameters,
    base_dir: Path,
    batch_id: str,
):
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec

    buffer_out = io.StringIO()
    buffer_err = io.StringIO()
    with contextlib.redirect_stdout(buffer_out), contextlib.redirect_stderr(buffer_err):
        spec = build_static_run_spec(
            selection=selection,
            params=effective_params,
            base_dir=base_dir,
            run_mode="batch",
            quiet=True,
            noninteractive=True,
            batch_id=batch_id,
        )
        outcome = execute_run_spec(spec)
    return outcome


def _run_dataset_batch(
    groups,
    base_dir: Path,
    command,
    static_service,
    query_runner,
    reset_static_analysis_data,
) -> None:
    from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
    from scytaledroid.StaticAnalysis.session import normalize_session_stamp
    from datetime import datetime, timezone
    import sys
    import threading

    dataset_pkgs = {pkg.lower() for pkg in load_profile_packages("RESEARCH_DATASET_ALPHA")}
    if not dataset_pkgs:
        print(status_messages.status("Research Dataset Alpha profile has no apps.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    batch_groups = _resolve_batch_groups(groups, dataset_pkgs)
    if not batch_groups:
        print(
            status_messages.status(
                "No APK artifacts found for Research Dataset Alpha in the local library.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    quiet = True

    batch_id = datetime.now(timezone.utc).strftime("static-batch-%Y%m%dT%H%M%SZ")
    batch_out_dir = Path("output") / "batches" / "static"
    batch_out_dir.mkdir(parents=True, exist_ok=True)
    batch_summary_path = batch_out_dir / f"{batch_id}.json"
    batch_rows: list[dict[str, object]] = []

    failures = []
    total = len(batch_groups)
    completed = 0
    batch_start = time.monotonic()
    for group in batch_groups:
        app_started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        # Batch determinism + canonical correctness:
        # Use a batch-unique session stamp so rerunning batch does not collide on session_label/canonical rows.
        session_stamp = normalize_session_stamp(f"{batch_id}-{group.package_name}")
        display_name = ""
        for artifact in group.artifacts:
            label = artifact.metadata.get("app_label")
            if isinstance(label, str) and label.strip():
                display_name = label.strip()
                break
        selection_label = f"{display_name} ({group.package_name})" if display_name else group.package_name
        selection = ScopeSelection(scope="app", label=selection_label, groups=(group,))
        index = completed + 1
        print(
            status_messages.status(
                f"Batch {index}/{total}: {selection_label} | done={completed} fail={len(failures)}",
                level="info",
            )
        )
        print(status_messages.status("Status: running (quiet batch mode)", level="info"))

        params = RunParameters(
            profile=command.profile,
            scope=selection.scope,
            scope_label=selection.label,
            selected_tests=tuple(),
            session_stamp=session_stamp,
            session_label=session_stamp,
            canonical_action="first_run",
            show_split_summaries=False,
        )
        effective_params = apply_command_overrides(params, command)

        # Batch mode: no reset prompts; keep state deterministic.

        try:
            # Heartbeat: keep operators confident the batch is still making progress even in quiet mode.
            # Print to sys.__stdout__ so it stays visible even when stdout is redirected for per-app quieting.
            hb_stop = threading.Event()
            hb_started = time.monotonic()

            def _heartbeat() -> None:
                while not hb_stop.wait(15.0):
                    elapsed = time.monotonic() - hb_started
                    msg = status_messages.status(
                        f"Heartbeat: {selection_label} | elapsed={elapsed:.0f}s",
                        level="info",
                    )
                    try:
                        sys.__stdout__.write(msg + "\n")
                        sys.__stdout__.flush()
                    except Exception:
                        pass

            hb_thread = threading.Thread(target=_heartbeat, name="static-batch-heartbeat", daemon=True)
            hb_thread.start()

            outcome = _execute_batch_run(
                group=group,
                selection_label=selection_label,
                selection=selection,
                effective_params=effective_params,
                base_dir=base_dir,
                batch_id=batch_id,
            )
            hb_stop.set()
            hb_thread.join(timeout=1.0)
        except static_service.StaticServiceError as exc:
            try:
                hb_stop.set()
            except Exception:
                pass
            failures.append(f"{selection.label}: {exc}")
            print(status_messages.status(f"Static analysis failed: {exc}", level="error"))
            log.error(f"Static analysis run failed: {exc}", category="static")
            batch_rows.append(
                {
                    "package_name": group.package_name,
                    "selection_label": selection_label,
                    "session_stamp": session_stamp,
                    "static_run_id": None,
                    "status": "error",
                    "error": str(exc),
                    "started_at": app_started_at,
                    "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                }
            )
            continue
        except Exception:
            try:
                hb_stop.set()
                hb_thread.join(timeout=1.0)
            except Exception:
                pass
            raise
        duration = None
        status_label = "ok"
        failure_note: str | None = None
        if outcome is None:
            status_label = "unknown"
            failure_note = "no outcome returned"
            failures.append(f"{selection.label}: {failure_note}")
        else:
            duration = getattr(outcome, "duration_seconds", None)
            if getattr(outcome, "aborted", False):
                status_label = "aborted"
                abort_reason = getattr(outcome, "abort_reason", None)
                failure_note = f"aborted: {abort_reason}" if abort_reason else "aborted"
                failures.append(f"{selection.label}: {failure_note}")
            elif getattr(outcome, "failures", None):
                status_label = "failed"
                first_failure = None
                try:
                    first_failure = outcome.failures[0] if outcome.failures else None  # type: ignore[attr-defined]
                except Exception:
                    first_failure = None
                if first_failure:
                    failure_note = f"{len(outcome.failures)} failure(s): {first_failure}"  # type: ignore[arg-type]
                else:
                    failure_note = "failures recorded (details unavailable)"
                failures.append(f"{selection.label}: {failure_note}")
        duration_label = f"{duration:.1f}s" if isinstance(duration, (int, float)) else "n/a"
        static_run_id = None
        plan_path = None
        try:
            if outcome and getattr(outcome, "results", None):
                first = outcome.results[0]
                static_run_id = getattr(first, "static_run_id", None)
                plan_path = getattr(first, "dynamic_plan_path", None)
        except Exception:
            static_run_id = None
            plan_path = None
        audit = _derive_persistence_audit(outcome, static_run_id)
        paper_grade_status = audit["paper_grade"]
        if status_label != "ok" and paper_grade_status == "ok":
            paper_grade_status = "warn"
        print(
            status_messages.status(
                (
                    f"Completed: {selection_label} | status={status_label} | duration={duration_label}"
                    + (f" | static_run_id={static_run_id}" if static_run_id is not None else " | static_run_id=—")
                    + f" | paper_grade={paper_grade_status}"
                    + (f" | note={failure_note}" if failure_note and status_label != "ok" else "")
                ),
                level="success" if status_label == "ok" else "warn",
            )
        )
        if paper_grade_status != "ok" and static_run_id is not None:
            print(
                status_messages.status(
                    (
                        "Artifacts exist, but this run is not paper-grade. "
                        f"See {audit['evidence_path']}; fix canonical/session policy."
                    ),
                    level="warn",
                )
            )
        batch_rows.append(
            {
                "package_name": group.package_name,
                "selection_label": selection_label,
                "session_stamp": session_stamp,
                "static_run_id": static_run_id,
                "status": status_label,
                "paper_grade": paper_grade_status,
                "persistence_failed": audit["persistence_failed"],
                "canonical_failed": audit["canonical_failed"],
                "evidence_path": audit["evidence_path"],
                "audit_notes": audit["audit_notes"],
                "plan_path": plan_path,
                "failures_count": len(getattr(outcome, "failures", []) or []) if outcome else 0,
                "failures_sample": (getattr(outcome, "failures", []) or [])[:3] if outcome else [],
                "aborted": bool(getattr(outcome, "aborted", False)) if outcome else False,
                "abort_reason": getattr(outcome, "abort_reason", None) if outcome else None,
                "started_at": app_started_at,
                "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        )
        completed += 1
        elapsed = time.monotonic() - batch_start
        avg = elapsed / completed if completed else 0.0
        remaining = total - completed
        eta = avg * remaining if avg > 0 else 0.0
        print(
            status_messages.status(
                f"Progress: {completed}/{total} | fail={len(failures)} | ETA {eta:.1f}s",
                level="info",
            )
        )
        # Persist an incremental batch summary so an interrupted batch still leaves an audit trail.
        try:
            _write_batch_summary(
                batch_summary_path=batch_summary_path,
                batch_id=batch_id,
                batch_rows=batch_rows,
                apps_total=total,
                apps_completed=completed,
                apps_failed=len(failures),
                ended_at=None,
            )
        except Exception:
            pass

        if command.auto_verify and not effective_params.dry_run and not quiet:
            session_key = getattr(outcome, "session_stamp", None) if outcome else None
            if not session_key:
                session_key = effective_params.session_stamp
            if session_key:
                query_runner.render_session_digest(session_key)

    if failures:
        print()
        menu_utils.print_section("Batch summary")
        for failure in failures:
            print(status_messages.status(f"Failed: {failure}", level="warn"))
    else:
        print()
        menu_utils.print_section("Batch summary")
        print(status_messages.status("All batch runs completed.", level="success"))
    elapsed = time.monotonic() - batch_start
    try:
        _write_batch_summary(
            batch_summary_path=batch_summary_path,
            batch_id=batch_id,
            batch_rows=batch_rows,
            apps_total=total,
            apps_completed=completed,
            apps_failed=len(failures),
            ended_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
    except Exception as exc:
        print(status_messages.status(f"Failed to write batch summary: {exc}", level="warn"))
    print(status_messages.status(f"Completed {completed}/{total} apps in {elapsed:.1f}s.", level="info"))
    print(status_messages.status(f"Batch summary → {batch_summary_path}", level="info"))
    # Batch mode should return to the menu without blocking on an extra prompt.
    return
