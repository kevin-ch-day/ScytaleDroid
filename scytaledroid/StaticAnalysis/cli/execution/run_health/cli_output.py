"""Filesystem + CLI stdout helpers for run_health emission."""

from __future__ import annotations

import json
from collections.abc import Mapping, MutableMapping
from pathlib import Path


def sanitize_session_stamp_for_filename(session_stamp: str | None) -> str:
    """Return a filesystem-friendly token for tagging ``run_health`` JSON files."""
    token = str(session_stamp or "unknown-session").strip()
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in token).strip("_")
    return cleaned[:120] if cleaned else "unknown-session"


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
    path = ""
    outp = doc.get("outputs") if isinstance(doc.get("outputs"), Mapping) else {}
    if isinstance(outp, Mapping):
        path = str(outp.get("run_health_json_relative") or outp.get("run_health_json_abs") or "")

    return (
        f"Run health: overall={doc.get('final_run_status')} "
        f'apps="complete {roll.get("apps_complete_final")} / partial {roll.get("apps_partial_final")} / '
        f'failed {roll.get("apps_failed_final")}" '
        f"path={path}"
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
        return "ok (no policy/finding failures, no warn-stage issues)"
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


def format_run_health_stdout_lines(doc: Mapping[str, object]) -> list[str]:
    """Structured operator summary when ``status_reasons`` is populated."""

    sr = doc.get("status_reasons") if isinstance(doc.get("status_reasons"), Mapping) else {}
    roll = doc.get("run_rollups") if isinstance(doc.get("run_rollups"), Mapping) else {}
    outp = doc.get("outputs") if isinstance(doc.get("outputs"), Mapping) else {}
    path = ""
    if isinstance(outp, Mapping):
        path = str(outp.get("run_health_json_relative") or outp.get("run_health_json_abs") or "")

    lines: list[str] = [
        f"Run health{(' — ' + path) if path else ''}:",
    ]
    if not sr:
        lines.append(compact_run_health_stdout_line(doc))
        return lines

    exec_workflow = _workflow_execution_label(doc, sr, roll)
    gov_r = _truncate_stdout_token(sr.get("governance_reason"))
    pipe = sr.get("detector_pipeline_status") or sr.get("detector_status")
    det_exec = _safe_int_token(sr.get("detector_execution_errors") or sr.get("detector_errors"))
    det_warn = _safe_int_token(sr.get("detector_warnings"))
    det_fail = _safe_int_token(sr.get("detector_finding_failures") or sr.get("detector_failures"))
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
                f"{det_human} | warnings={det_warn} finding_failures={det_fail} "
                f"execution_errors={det_exec}"
            ),
            (
                "DB persistence   : "
                f"{sr.get('db_persistence_status')} | string_rollup={sr.get('string_status')}"
            ),
            (
                "Governance       : "
                f"{sr.get('governance_grade')} — {gov_r}"
            ),
            f"Overall health   : {doc.get('final_run_status')}",
            (
                "Counts           : "
                f"parse_fallbacks={sr.get('parse_fallbacks')} "
                f"(pipeline_token={pipe})"
            ),
        ]
    )

    if (
        str(doc.get("final_run_status") or "") == "partial"
        and det_exec == 0
        and (det_fail > 0 or det_warn > 0)
    ):
        lines.append(
            "Note: partial means warn/policy-finding stages fired — not that scans or DB writes failed."
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
            "Apps not strictly complete (partial outcomes): " + " | ".join(partial_hints[:4])
        )

    return lines


def attach_run_health_outputs_on_document(doc: MutableMapping[str, object], *, path: Path, base_dir: Path) -> None:
    outp = dict(doc.get("outputs") if isinstance(doc.get("outputs"), Mapping) else {})
    outp["run_health_json_abs"] = str(path)
    rel = path.name
    try:
        if base_dir.is_absolute():
            rel = str(path.resolve().relative_to(base_dir.resolve()))
        else:
            rel = str(path.relative_to(base_dir))
    except (OSError, ValueError):
        rel = path.name
    outp["run_health_json_relative"] = rel
    doc["outputs"] = outp
