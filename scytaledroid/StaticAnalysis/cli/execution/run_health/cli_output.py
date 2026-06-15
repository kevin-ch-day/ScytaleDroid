"""Filesystem + CLI stdout helpers for run_health emission."""

from __future__ import annotations

import json
from collections.abc import Mapping, MutableMapping
from pathlib import Path

from ..scan_formatters import _detector_posture_readable


def sanitize_session_stamp_for_filename(session_stamp: str | None) -> str:
    """Return a filesystem-friendly token for tagging ``run_health`` JSON files."""
    token = str(session_stamp or "unknown-session").strip()
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in token).strip("_")
    return cleaned[:120] if cleaned else "unknown-session"


def _workflow_completion_stdout_label(exec_workflow: str) -> str:
    """Human token for scan/persistence workflow (distinct from detector/session posture)."""

    w = str(exec_workflow or "").strip().lower()
    table = {
        "complete": "COMPLETE",
        "aborted": "ABORTED",
        "persistence_failed": "FAILED (DB persistence)",
        "apps_failed": "FAILED (one or more apps)",
        "skipped_no_persistence": "SKIPPED (persistence not attempted)",
        "unknown": "UNKNOWN",
    }
    return table.get(w, w.upper().replace("_", " ") if w else "—")


def write_run_health_json(path: Path, document: Mapping[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
    return path


def _safe_int_token(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _workflow_execution_label(doc: Mapping[str, object], sr: Mapping[str, object], roll: Mapping[str, object]) -> str:
    """High-level scan/persistence workflow (not detector severity)."""

    if bool(doc.get("aborted")):
        return "aborted"
    db = str(sr.get("db_persistence_status") or "")
    if db == "failed":
        return "persistence_failed"
    if _safe_int_token(roll.get("apps_failed_final")) > 0:
        return "apps_failed"
    if db in {"ok", "partial"}:
        return "complete"
    if db == "skipped":
        return "skipped_no_persistence"
    return "unknown"


def compact_run_health_stdout_line(doc: Mapping[str, object]) -> str:
    """One-line roll-up; prefer ``format_run_health_stdout_lines`` for operator-facing detail."""
    roll = doc.get("run_rollups") if isinstance(doc.get("run_rollups"), Mapping) else {}
    path = _run_health_display_path(doc)
    workflow = str(
        doc.get("workflow_completion_status")
        or doc.get("workflow_run_status")
        or doc.get("final_run_status")
        or "unknown"
    )
    posture = str(
        doc.get("detector_posture")
        or doc.get("detector_posture_status")
        or roll.get("detector_posture")
        or roll.get("detector_posture_status")
        or "unknown"
    )
    fidelity = str(
        doc.get("finding_fidelity_status")
        or roll.get("finding_fidelity_status")
        or "unknown"
    )

    return (
        f"Run health (compact): workflow_completion_status={workflow} "
        f"| detector_posture={posture} "
        f"| finding_fidelity_status={fidelity} "
        f"| apps_complete={roll.get('apps_complete_final')} "
        f"apps_with_caveats={roll.get('apps_with_caveats', roll.get('apps_partial_final'))} "
        f"apps_failed={roll.get('apps_failed_final')} "
        f"| run_health_json={path}"
    )


def _detector_result_operator_label(
    pipeline_token: str | None,
    *,
    execution_errors: int,
) -> str:
    """Human label for pipeline outcome; never implies *execution* errors when count is zero."""
    token = str(pipeline_token or "").strip()
    ex = max(0, int(execution_errors or 0))
    if ex > 0:
        if "execution_errors_with" in token:
            return "execution errors and pipeline warnings/failures"
        return "detector execution errors"
    if not token or token == "ok":
        return "ok (no WARN-stage issues and no policy/finding gate failures)"
    mapping = {
        "warnings": "warnings (detector warn-stage only)",
        "policy_failures": "policy and finding gate failures",
        "warnings_and_policy_failures": "warnings and policy/finding gate failures",
    }
    return mapping.get(
        token,
        token.replace("_", " "),
    )


def _truncate_stdout_token(text: object, *, max_len: int = 140) -> str:
    s = str(text if text is not None else "")
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def _run_health_display_path(doc: Mapping[str, object]) -> str:
    """Prefer a path token that points operators to the real file location."""

    outp = doc.get("outputs") if isinstance(doc.get("outputs"), Mapping) else {}
    if not isinstance(outp, Mapping):
        return ""
    preferred = str(outp.get("run_health_json_display") or "").strip()
    if preferred:
        return preferred
    rel = str(outp.get("run_health_json_relative") or "").strip()
    if rel and any(sep in rel for sep in ("/", "\\")):
        return rel
    return str(outp.get("run_health_json_abs") or rel or "").strip()


def format_run_health_stdout_lines(doc: Mapping[str, object]) -> list[str]:
    """Structured operator summary when ``status_reasons`` is populated."""

    sr = doc.get("status_reasons") if isinstance(doc.get("status_reasons"), Mapping) else {}
    roll = doc.get("run_rollups") if isinstance(doc.get("run_rollups"), Mapping) else {}
    path = _run_health_display_path(doc)

    lines: list[str] = [
        f"Run health{(' - ' + path) if path else ''}:",
    ]
    if not sr:
        lines.append(compact_run_health_stdout_line(doc))
        return lines

    exec_workflow = _workflow_execution_label(doc, sr, roll)
    workflow_run_status = str(
        doc.get("workflow_completion_status")
        or doc.get("workflow_run_status")
        or doc.get("final_run_status")
        or exec_workflow
        or ""
    ).strip()
    detector_posture_status = str(
        doc.get("detector_posture")
        or roll.get("detector_posture")
        or doc.get("detector_posture_status")
        or roll.get("detector_posture_status")
        or doc.get("final_run_status")
        or ""
    ).strip()
    finding_fidelity_status = str(
        doc.get("finding_fidelity_status")
        or roll.get("finding_fidelity_status")
        or "unknown"
    ).strip()
    gov_r = _truncate_stdout_token(sr.get("governance_reason"))
    pipe = sr.get("detector_pipeline_status") or sr.get("detector_status")
    det_exec = _safe_int_token(sr.get("detector_execution_errors") or sr.get("detector_errors"))
    det_warn = _safe_int_token(sr.get("detector_warnings"))
    det_fail = _safe_int_token(sr.get("detector_finding_failures") or sr.get("detector_failures"))
    findings_runtime = _safe_int_token(roll.get("findings_runtime_total"))
    findings_persisted = _safe_int_token(roll.get("findings_persisted_db_total"))
    findings_capped = _safe_int_token(roll.get("findings_capped_not_persisted_total"))
    p0_capped = _safe_int_token(roll.get("p0_capped_not_persisted_total"))
    scan_done = roll.get("scan_execution_complete")
    if isinstance(scan_done, bool):
        exec_label = "complete" if scan_done else "incomplete"
    else:
        artifacts_done = _safe_int_token(roll.get("artifacts_scan_completed_counter"))
        artifacts_tot = _safe_int_token(roll.get("artifact_total_discovered_estimate"))
        exec_label = "complete" if artifacts_tot > 0 and artifacts_done >= artifacts_tot else "incomplete"

    det_human = _detector_result_operator_label(str(pipe) if pipe is not None else None, execution_errors=det_exec)

    lines.extend(
        [
            f"Execution        : {exec_label} (workflow={exec_workflow})",
            (
                "Detector result  : "
                f"{det_human} | detector_warnings={det_warn} policy_failures={det_fail} "
                f"execution_errors={det_exec}"
                + (" (none - not analyzer crashes)" if det_exec == 0 else "")
            ),
            (
                "DB persistence   : "
                f"{sr.get('db_persistence_status')} | string_rollup={sr.get('string_status')}"
            ),
            (
                "Finding fidelity : "
                f"runtime={findings_runtime} persisted_db={findings_persisted} "
                f"capped_not_persisted={findings_capped}"
            ),
            (
                "Governance       : "
                f"{sr.get('governance_grade')} - {gov_r}"
            ),
            f"Run completion   : {_workflow_completion_stdout_label(exec_workflow)}",
            f"Workflow status  : {workflow_run_status.upper() if workflow_run_status else '—'}",
            (
                "Detector posture : "
                f"{_detector_posture_readable(detector_posture_status or str(pipe or ''))}"
            ),
            f"Finding fidelity : {finding_fidelity_status} | runtime={findings_runtime} persisted_db={findings_persisted} capped_not_persisted={findings_capped}",
            (
                "Counts           : "
                f"parse_fallbacks={sr.get('parse_fallbacks')} "
                f"(pipeline_token={pipe})"
            ),
        ]
    )

    if (
        detector_posture_status in {"partial", "warnings", "policy_or_finding_gates"}
        and det_exec == 0
        and exec_workflow == "complete"
        and str(sr.get("db_persistence_status") or "") in {"ok", "partial"}
    ):
        lines.append(
            "Operator note    : Workflow completion and DB persistence finished successfully. "
            "The internal session/app rollup may still use 'partial' for compatibility when detector "
            "warnings and/or policy-finding gates fired; execution_errors=0 means no analyzer/pipeline crashes."
        )
    if findings_capped > 0:
        lines.append(
            "Fidelity warning : "
            f"PARTIAL - {findings_capped} runtime findings were capped before canonical DB persistence."
        )
        lines.append(
            "Persistence note : Some detector findings were intentionally omitted from canonical DB inserts "
            "because per-detector caps fired. Use run_health.json or DB capped counters when comparing "
            "runtime detector output to persisted findings."
        )
    if p0_capped > 0:
        lines.append(
            "High-priority fidelity warning: "
            f"{p0_capped} P0 findings were capped before canonical DB persistence."
        )

    apps = doc.get("apps") if isinstance(doc.get("apps"), list) else []
    partial_hints: list[str] = []
    for row in apps:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("final_status") or "") != "partial":
            continue
        pkg = str(row.get("package_name") or "?")
        sig = row.get("execution_signals") if isinstance(row.get("execution_signals"), Mapping) else {}
        drivers = sig.get("drivers") if isinstance(sig.get("drivers"), list) else []
        if drivers:
            partial_hints.append(f"{pkg}: " + "; ".join(str(d) for d in drivers[:6]))
        elif len(partial_hints) < 4:
            partial_hints.append(f"{pkg}: (see execution_signals in run_health.json)")
    if partial_hints:
        lines.append(
            "Apps with detector/persistence caveats: " + " | ".join(partial_hints[:4])
        )

    return lines


def attach_run_health_outputs_on_document(doc: MutableMapping[str, object], *, path: Path, base_dir: Path) -> None:
    outp = dict(doc.get("outputs") if isinstance(doc.get("outputs"), Mapping) else {})
    outp["run_health_json_abs"] = str(path)
    outp["run_health_base_dir_abs"] = str(base_dir)
    rel = path.name
    try:
        if base_dir.is_absolute():
            rel = str(path.resolve().relative_to(base_dir.resolve()))
        else:
            rel = str(path.relative_to(base_dir))
    except (OSError, ValueError):
        rel = path.name
    outp["run_health_json_relative"] = rel
    outp["run_health_json_display"] = rel if any(sep in rel for sep in ("/", "\\")) else str(path)
    doc["outputs"] = outp
