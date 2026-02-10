"""Batch static analysis runner and utilities.

This module intentionally contains no interactive menu logic. It can be called by
CLI menus and headless entrypoints.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _format_eta(seconds: float | int | None) -> str:
    if seconds is None:
        return "n/a"
    try:
        total = int(round(float(seconds)))
    except (TypeError, ValueError):
        return "n/a"
    if total <= 0:
        return "0s"
    mins, secs = divmod(total, 60)
    if mins <= 0:
        return f"{secs}s"
    return f"{mins}m {secs}s"


def _safe_split_token(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token:
        return None
    # Avoid leaking full paths into batch logs.
    token = token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if token.lower().endswith(".apk"):
        token = token[:-4]
    return token if token else None


def _artifact_set_for_batch_log(artifact: object) -> str:
    """Resolve artifact set for batch logs ("base" or a split token)."""
    from scytaledroid.StaticAnalysis.cli.views.view_sections import extract_integrity_profiles

    artifact_set = "base"
    try:
        _, _, artifact_profile, _ = extract_integrity_profiles(getattr(artifact, "report", None))
        role = str((artifact_profile or {}).get("role") or "").lower()
        if role and role != "base":
            meta = artifact.metadata if isinstance(getattr(artifact, "metadata", None), dict) else {}
            artifact_set = (
                _safe_split_token(meta.get("split_name"))
                or _safe_split_token(meta.get("split"))
                or _safe_split_token(meta.get("artifact"))
                or _safe_split_token(getattr(artifact, "label", None))
                or "split"
            )
        else:
            artifact_set = "base"
    except Exception:
        meta = artifact.metadata if isinstance(getattr(artifact, "metadata", None), dict) else {}
        artifact_set = (
            _safe_split_token(meta.get("split_name"))
            or _safe_split_token(getattr(artifact, "label", None))
            or "base"
        )
    return artifact_set


def _resolve_batch_groups(groups, dataset_pkgs: set[str]) -> list[object]:
    # Batch determinism: select one "best" artifact group per package (newest by session stamp + mtime).
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
    # Deterministic order: stable across runs given the same library state.
    return sorted(by_pkg.values(), key=lambda g: str(getattr(g, "package_name", "")).lower())


def _derive_persistence_audit(outcome, static_run_id: int | None) -> dict[str, object]:
    persistence_failed = bool(getattr(outcome, "persistence_failed", False))
    canonical_failed = bool(getattr(outcome, "canonical_failed", False))
    paper_grade_status = getattr(outcome, "paper_grade_status", "ok")
    errors = list(getattr(outcome, "errors", []) or [])
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
        "errors_sample": errors[-3:],
    }


def _format_audit_notes(notes: object, *, limit: int = 3) -> str | None:
    if not isinstance(notes, list) or not notes:
        return None
    parts: list[str] = []
    for item in notes[: max(1, int(limit))]:
        if isinstance(item, dict):
            code = str(item.get("code") or "").strip() or "note"
            msg = str(item.get("message") or "").strip()
            if msg:
                parts.append(f"{code}: {msg}")
            else:
                parts.append(code)
        else:
            text = str(item).strip()
            if text:
                parts.append(text)
    return "; ".join(parts) if parts else None


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
    selection,
    effective_params,
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


def _select_active_device_serial() -> str | None:
    """Return active device serial for noninteractive batch operations.

    Batch static may need to auto-harvest APKs. We only support this when:
    - an active device is set, or
    - exactly one connected adb device is present (auto-select).
    """
    try:
        from scytaledroid.DeviceAnalysis import device_manager
        from scytaledroid.DeviceAnalysis.adb import devices as adb_devices

        serial = device_manager.get_active_serial()
        if serial:
            return serial
        devices = adb_devices.list_devices()
        connected = [
            d for d in devices
            if str(d.get("state") or "").lower() == "device" and d.get("serial")
        ]
        if len(connected) == 1:
            return str(connected[0].get("serial"))
        return None
    except Exception:
        return None


def _auto_harvest_dataset_apks(*, dataset_pkgs: set[str], base_dir: Path) -> bool:
    """Best-effort quick harvest of dataset APKs into the local library.

    Returns True if we attempted a harvest. It may still result in zero packages
    pulled (e.g., packages not installed or inventory missing).
    """
    try:
        from scytaledroid.Config import app_config
        from scytaledroid.DeviceAnalysis import harvest, inventory
        from scytaledroid.DeviceAnalysis.adb import client as adb_client
        from scytaledroid.DeviceAnalysis.harvest import planner as harvest_planner
        from scytaledroid.DeviceAnalysis.services import inventory_service
        from scytaledroid.Utils.DisplayUtils import status_messages, text_blocks
    except Exception:
        return False

    serial = _select_active_device_serial()
    if not serial:
        print(
            status_messages.status(
                "No active adb device available for auto-harvest. "
                "Fix: Device Analysis → select device (or connect exactly one device), then retry.",
                level="warn",
            )
        )
        return False

    adb_path = adb_client.get_adb_binary()
    if not adb_path:
        print(status_messages.status("adb not available; cannot auto-harvest APKs.", level="warn"))
        return False

    # Load (or create) a recent inventory snapshot for this device.
    snapshot = inventory.load_latest_inventory(serial)
    if not snapshot or not snapshot.get("packages"):
        try:
            inventory_service.run_full_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
        except Exception as exc:
            print(status_messages.status(f"Inventory sync failed ({exc.__class__.__name__}).", level="warn"))
            return True
        snapshot = inventory.load_latest_inventory(serial)

    packages_raw = snapshot.get("packages", []) if isinstance(snapshot, dict) else []
    rows = harvest.build_inventory_rows(packages_raw) if packages_raw else []
    if not rows:
        print(status_messages.status("No inventory rows available; cannot auto-harvest APKs.", level="warn"))
        return True

    # Filter to dataset packages only (non-root mode will auto-filter system partitions).
    filtered = [row for row in rows if str(row.package_name).lower() in dataset_pkgs]
    if not filtered:
        print(status_messages.status("Dataset packages not present in device inventory; nothing to harvest.", level="warn"))
        return True

    plan = harvest_planner.build_harvest_plan(filtered, include_system_partitions=False)
    # Align with existing on-disk library structure: data/device_apks/<serial>/<YYYYMMDD>/...
    from datetime import UTC, datetime

    session_stamp = datetime.now(UTC).strftime("%Y%m%d")
    dest_root = (Path(app_config.DATA_DIR) / "device_apks" / serial / session_stamp).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)

    print(
        status_messages.status(
            f"Auto-harvest: pulling {len(plan.packages)} dataset package(s) from {serial} into {dest_root}.",
            level="info",
        )
    )
    try:
        harvest.quick_harvest(
            plan.packages,
            adb_path=adb_path,
            dest_root=dest_root,
            session_stamp=session_stamp,
            config=app_config,
            serial=serial,
            verbose=False,
        )
    except Exception as exc:
        print(status_messages.status(f"Auto-harvest failed ({exc.__class__.__name__}).", level="warn"))
    return True


def run_dataset_static_batch(
    *,
    groups,
    base_dir: Path,
    command,
    static_service,
    query_runner,
    reset_static_analysis_data,
) -> None:
    """Run static analysis for Research Dataset Alpha packages (batch, quiet console)."""
    from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
    from scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu_helpers import (
        apply_command_overrides,
    )
    from scytaledroid.StaticAnalysis.session import normalize_session_stamp
    from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils

    dataset_pkgs = {pkg.lower() for pkg in load_profile_packages("RESEARCH_DATASET_ALPHA")}
    if not dataset_pkgs:
        print(status_messages.status("Research Dataset Alpha profile has no apps.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    batch_groups = _resolve_batch_groups(groups, dataset_pkgs)
    if not batch_groups:
        attempted = _auto_harvest_dataset_apks(dataset_pkgs=dataset_pkgs, base_dir=base_dir)
        if attempted:
            # Re-scan the local library for newly harvested artifacts.
            try:
                from scytaledroid.StaticAnalysis.core.repository import group_artifacts

                refreshed_groups = tuple(group_artifacts(base_dir))
                batch_groups = _resolve_batch_groups(refreshed_groups, dataset_pkgs)
            except Exception:
                batch_groups = []

        if not batch_groups:
            # Helpful diagnostics for operators after a reset.
            try:
                local_groups = list(groups)
                local_pkgs = sorted(
                    {str(getattr(g, "package_name", "")).lower() for g in local_groups if getattr(g, "package_name", None)}
                )
            except Exception:
                local_pkgs = []
            if local_pkgs:
                print(
                    status_messages.status(
                        f"Local library packages (sample): {', '.join(local_pkgs[:8])}"
                        + (" …" if len(local_pkgs) > 8 else ""),
                        level="info",
                    )
                )

            # Check whether dataset packages exist in the most recent device inventory snapshot (if any).
            try:
                from scytaledroid.DeviceAnalysis import inventory

                serial = _select_active_device_serial()
                if serial:
                    snapshot = inventory.load_latest_inventory(serial)
                    pkgs = snapshot.get("packages", []) if isinstance(snapshot, dict) else []
                    inv = {str(p.get("package_name") or "").lower() for p in pkgs if isinstance(p, dict)}
                    missing = sorted(pkg for pkg in dataset_pkgs if pkg not in inv)
                    present = sorted(pkg for pkg in dataset_pkgs if pkg in inv)
                    if present:
                        print(
                            status_messages.status(
                                f"Dataset packages present on device: {len(present)}/{len(dataset_pkgs)}",
                                level="info",
                            )
                        )
                    if missing:
                        print(
                            status_messages.status(
                                f"Dataset packages missing from device inventory: {', '.join(missing)}",
                                level="warn",
                            )
                        )
            except Exception:
                pass

            print(
                status_messages.status(
                    "No APK artifacts found for Research Dataset Alpha in the local library.",
                    level="warn",
                )
            )
            print(
                status_messages.status(
                    f"Library root: {base_dir}. Fix: Device Analysis → pull APK artifacts for these apps, then retry batch.",
                    level="info",
                )
            )
            prompt_utils.press_enter_to_continue()
            return

    quiet = True
    batch_id = datetime.now(UTC).strftime("static-batch-%Y%m%dT%H%M%SZ")
    batch_out_dir = Path("output") / "batches" / "static"
    batch_out_dir.mkdir(parents=True, exist_ok=True)
    batch_summary_path = batch_out_dir / f"{batch_id}.json"
    batch_rows: list[dict[str, object]] = []

    failures: list[str] = []
    total = len(batch_groups)
    completed = 0
    batch_start = time.monotonic()
    correlation_first_run_note_printed = False

    print()
    menu_utils.print_section("Running Research Dataset (batch static)")
    for group in batch_groups:
        app_started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
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

        params = RunParameters(
            profile=command.profile,
            scope=selection.scope,
            scope_label=selection.label,
            selected_tests=tuple(),
            session_stamp=session_stamp,
            session_label=session_stamp,
            canonical_action="first_run",
            show_split_summaries=False,
            scan_splits=False,
        )
        effective_params = apply_command_overrides(params, command)

        try:
            hb_stop = threading.Event()
            hb_started = time.monotonic()

            def _heartbeat(*, _stop=hb_stop, _started=hb_started, _label=selection_label) -> None:
                while not _stop.wait(30.0):
                    elapsed_s = time.monotonic() - _started
                    stage = None
                    done = None
                    total_done = None
                    stage_index = None
                    stage_total = None
                    try:
                        from scytaledroid.StaticAnalysis.cli.execution.heartbeat_state import (
                            snapshot,
                        )

                        hb = snapshot()
                        stage = hb.get("stage")
                        done = hb.get("done")
                        total_done = hb.get("total")
                        stage_index = hb.get("stage_index")
                        stage_total = hb.get("stage_total")
                    except Exception:
                        stage = None
                        done = None
                        total_done = None
                        stage_index = None
                        stage_total = None

                    parts = [f"Heartbeat: {_label}", f"elapsed={elapsed_s:.0f}s"]
                    if stage:
                        parts.append(f"stage={stage}")
                    if (
                        isinstance(stage_index, int)
                        and isinstance(stage_total, int)
                        and stage_total > 0
                    ):
                        parts.append(f"stage_progress={stage_index}/{stage_total}")
                    if isinstance(done, int) and isinstance(total_done, int) and total_done > 0:
                        parts.append(f"artifacts_done={done}/{total_done}")
                    msg = status_messages.status(" | ".join(parts), level="info")
                    try:
                        sys.__stdout__.write(msg + "\n")
                        sys.__stdout__.flush()
                    except Exception:
                        pass

            hb_thread = threading.Thread(
                target=_heartbeat,
                name="static-batch-heartbeat",
                daemon=True,
            )
            hb_thread.start()

            outcome = _execute_batch_run(
                group=group,
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
                hb_thread.join(timeout=1.0)
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
                    "ended_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
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
        identity_valid = None
        try:
            if outcome and getattr(outcome, "results", None):
                first = outcome.results[0]
                static_run_id = getattr(first, "static_run_id", None)
                plan_path = getattr(first, "dynamic_plan_path", None)
                identity_valid = getattr(first, "identity_valid", None)
        except Exception:
            static_run_id = None
            plan_path = None
            identity_valid = None

        # Batch static must produce a dynamic plan for gating dynamic runs.
        # Treat "no plan path" or "plan path missing on disk" as a batch failure even if the
        # scan otherwise completed, since this breaks Paper #2 static->dynamic contract.
        plan_exists = False
        plan_path_display = None
        try:
            if isinstance(plan_path, (str, Path)) and str(plan_path):
                plan_p = Path(str(plan_path))
                plan_exists = plan_p.exists()
                # Keep console output readable while still being precise.
                try:
                    plan_path_display = str(plan_p.relative_to(Path.cwd()))
                except Exception:
                    plan_path_display = str(plan_p)
        except Exception:
            plan_exists = False
            plan_path_display = None

        if status_label == "ok":
            if static_run_id is None:
                status_label = "failed"
                failure_note = "static_run_id_missing"
                failures.append(f"{selection.label}: {failure_note}")
            elif isinstance(identity_valid, bool) and identity_valid is False:
                status_label = "failed"
                failure_note = "identity_invalid"
                failures.append(f"{selection.label}: {failure_note}")
            elif not plan_exists:
                status_label = "failed"
                failure_note = "plan_missing"
                failures.append(f"{selection.label}: {failure_note}")

        audit = _derive_persistence_audit(outcome, static_run_id)
        paper_grade_status = audit["paper_grade"]
        if status_label != "ok" and paper_grade_status == "ok":
            paper_grade_status = "warn"

        audit_notes = audit.get("audit_notes") if isinstance(audit, dict) else None
        audit_notes_list = audit_notes if isinstance(audit_notes, list) else []
        errors_sample = audit.get("errors_sample") if isinstance(audit, dict) else None
        errors_list = errors_sample if isinstance(errors_sample, list) else []

        # Compact blocker summary (useful for debugging persistence_failed/canonical_failed).
        blockers_text = _format_audit_notes(audit_notes_list, limit=2)

        # High-signal stage summary (collapsed across split APK artifacts).
        # In dataset batch mode, RISK/FINDING are not "run failures"; keep them visible but non-alarming.
        try:
            if outcome and getattr(outcome, "results", None):
                app_result = outcome.results[0]
                from scytaledroid.StaticAnalysis.cli.batch.log_semantics import (
                    BatchStageLevel,
                    BatchWarnKind,
                    summarize_stage_levels,
                )

                stage_lines = summarize_stage_levels(
                    app_result,
                    artifact_set_resolver=_artifact_set_for_batch_log,
                )
                counts = {"RISK": 0, "FINDING": 0, "EVIDENCE_WARN": 0, "NOTE": 0, "POLICY_FAIL": 0, "ERROR": 0}
                for item in stage_lines:
                    text = item.format()

                    # Correlation "no baseline" is expected on the first dataset batch run.
                    # Print a single batch-level note instead of repeating it per app.
                    if (
                        item.level == BatchStageLevel.WARN
                        and item.warn_kind == BatchWarnKind.EVIDENCE
                        and item.section == "correlation_findings"
                        and (item.note or "") == "not_applicable:baseline_missing"
                    ):
                        # Treat as a NOTE, not an evidence warning, so per-app summaries don't
                        # imply a deficiency "by construction" when an app/version has no prior baseline.
                        counts["NOTE"] += 1
                        if not correlation_first_run_note_printed:
                            correlation_first_run_note_printed = True
                            print(
                                status_messages.status(
                                    "Correlation findings baseline not available for this app/version (expected after reset "
                                    "or first observation). Baseline comparisons require at least two static reports for "
                                    "the same app/version.",
                                    level="info",
                                )
                            )
                        continue

                    if item.level == BatchStageLevel.ERROR:
                        counts["ERROR"] += 1
                        print(status_messages.status(text, level="error"))
                        continue
                    if item.level == BatchStageLevel.POLICY_FAIL:
                        counts["POLICY_FAIL"] += 1
                        print(status_messages.status(text, level="warn"))
                        continue
                    if item.level == BatchStageLevel.FINDING:
                        counts["FINDING"] += 1
                        print(status_messages.status(text, level="info"))
                        continue
                    if item.level == BatchStageLevel.WARN:
                        if item.warn_kind == BatchWarnKind.RISK:
                            counts["RISK"] += 1
                            print(status_messages.status(text, level="info"))
                        else:
                            counts["EVIDENCE_WARN"] += 1
                            print(status_messages.status(text, level="info"))
                        continue

                # Per-app findings summary line (operator-friendly, deterministic).
                print(
                    status_messages.status(
                        "Findings summary: "
                        f"risk={counts['RISK']} finding={counts['FINDING']} "
                        f"evidence_warn={counts['EVIDENCE_WARN']} note={counts['NOTE']} "
                        f"policy_fail={counts['POLICY_FAIL']} error={counts['ERROR']}",
                        level="info",
                    )
                )
        except Exception:
            pass

        # Multiline completion block improves operator confidence and reduces "stuck" confusion.
        print(
            status_messages.status(
                f"Completed: {selection_label}",
                level="success" if status_label == "ok" else "warn",
            )
        )
        print(
            status_messages.status(
                f"status={status_label} | duration={duration_label}",
                level="info",
            )
        )
        print(
            status_messages.status(
                (f"static_run_id={static_run_id}" if static_run_id is not None else "static_run_id=—")
                + f" | paper_grade={paper_grade_status}",
                level="info",
            )
        )
        if isinstance(identity_valid, bool):
            print(status_messages.status(f"identity_valid={identity_valid}", level="info"))
        if plan_path_display:
            print(status_messages.status(f"plan={plan_path_display}", level="info"))
        if failure_note and status_label != "ok":
            print(status_messages.status(f"note={failure_note}", level="warn"))
        if blockers_text and status_label != "ok":
            print(status_messages.status(f"blockers={blockers_text}", level="warn"))

        if status_label != "ok" and outcome is not None:
            try:
                failures_list = list(getattr(outcome, "failures", []) or [])
            except Exception:
                failures_list = []
            if failures_list:
                print(
                    status_messages.status(
                        f"Failure codes: {', '.join(str(f) for f in failures_list[:3])}",
                        level="warn",
                    )
                )
            if errors_list:
                print(status_messages.status(f"Last error: {errors_list[-1]}", level="warn"))

        if paper_grade_status != "ok" and static_run_id is not None:
            blockers = audit_notes_list[:3]
            blocker_note = f" Paper-grade blockers: {', '.join(str(b) for b in blockers)}" if blockers else ""
            print(
                status_messages.status(
                    (
                        "Artifacts exist, but this run is not paper-grade. "
                        f"See {audit['evidence_path']}.{blocker_note}"
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
                "plan_exists": bool(plan_exists),
                "failures_count": len(getattr(outcome, "failures", []) or []) if outcome else 0,
                "failures_sample": (getattr(outcome, "failures", []) or [])[:3] if outcome else [],
                "aborted": bool(getattr(outcome, "aborted", False)) if outcome else False,
                "abort_reason": getattr(outcome, "abort_reason", None) if outcome else None,
                "started_at": app_started_at,
                "ended_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        )

        completed += 1
        elapsed = time.monotonic() - batch_start
        avg = elapsed / completed if completed else 0.0
        remaining = total - completed
        eta = avg * remaining if avg > 0 else 0.0
        print(
            status_messages.status(
                f"Progress: {completed}/{total} | fail={len(failures)} | ETA {_format_eta(eta)}",
                level="info",
            )
        )
        print()

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

    print()
    menu_utils.print_section("Batch summary")
    if failures:
        for failure in failures:
            print(status_messages.status(f"Failed: {failure}", level="warn"))
    else:
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
            ended_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
    except Exception as exc:
        print(status_messages.status(f"Failed to write batch summary: {exc}", level="warn"))
    print(status_messages.status(f"Completed {completed}/{total} apps in {elapsed:.1f}s.", level="info"))
    print(status_messages.status(f"Batch summary → {batch_summary_path}", level="info"))


__all__ = ["run_dataset_static_batch"]
