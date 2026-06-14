"""Compact post-run DB + archive grain summary for cohort static runs.

Uses the same read-only SQL as ``report_static_session_grain_integrity`` (via
:func:`collect_session_grain`) but prints a short operator summary instead of a
full report. Gated by :envvar:`SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY`.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.static_session_grain_integrity import (
    collect_session_grain,
    count_json_files_in_dir,
    format_grain_integrity_cli_command,
    reports_archive_dir,
)
from scytaledroid.Utils.DisplayUtils import status_messages

from ..core.run_context import StaticRunContext


def post_run_grain_summary_enabled(run_ctx: StaticRunContext | None) -> bool:
    """Return whether to emit the compact grain block after a successful static run."""

    raw = os.getenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", "").strip().lower()
    if raw in {"0", "no", "false", "off", "never"}:
        return False
    if raw in {"1", "yes", "true", "on", "always"}:
        return True
    # Default: cohort-style runs (non-interactive / batch) — avoid extra noise in fully interactive sessions.
    if run_ctx is None:
        return False
    return bool(run_ctx.batch or run_ctx.noninteractive)


def maybe_emit_post_run_grain_summary(
    session_stamp: str | None,
    *,
    scope_label: str | None,
    run_ctx: StaticRunContext | None,
    run_aggregate_status: str | None = None,
    session_metrics: dict[str, object] | None = None,
) -> None:
    """If enabled, print a few lines of session grain + archive JSON count + full-report command.

    When *session_metrics* is provided, stores a ``post_run_grain`` dict for logs / run_health consumers.
    """

    stamp = str(session_stamp or "").strip()
    emit_summary = post_run_grain_summary_enabled(run_ctx)
    collect_for_run_health = session_metrics is not None
    if not stamp or (not emit_summary and not collect_for_run_health):
        return
    try:
        data = collect_session_grain(
            core_q.run_sql,
            session_stamp=stamp,
            scope_label=scope_label,
            top_packages=1,
        )
    except Exception as exc:
        if emit_summary or collect_for_run_health:
            print(
                status_messages.status(
                    f"Post-run cohort quick check skipped (DB): {exc.__class__.__name__}: {exc}",
                    level="warn",
                )
            )
        return
    n_runs = int(data.get("static_run_rows") or 0)
    if n_runs <= 0:
        if emit_summary:
            print(
                status_messages.status(
                    "Post-run cohort quick check: no static_analysis_runs rows for this session_stamp yet.",
                    level="warn",
                )
            )
        return

    br = data.get("status_breakdown") or []
    completed = 0
    failed = 0
    other = 0
    if isinstance(br, list):
        for item in br:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                st, cnt = str(item[0] or ""), int(item[1] or 0)
            elif isinstance(item, dict):
                vals = list(item.values())
                if len(vals) < 2:
                    continue
                st, cnt = str(vals[0] or ""), int(vals[1] or 0)
            else:
                continue
            u = st.upper()
            if u == "COMPLETED":
                completed += cnt
            elif u == "FAILED":
                failed += cnt
            else:
                other += cnt

    arch_n = count_json_files_in_dir(reports_archive_dir(session_stamp=stamp))
    findings = int(data.get("canonical_findings_rows") or 0)
    matrix = int(data.get("permission_matrix_rows") or 0)
    pf = int(data.get("persistence_failure_rows") or 0)

    if session_metrics is not None:
        session_metrics["post_run_grain"] = {
            "session_stamp": stamp,
            "scope_label": str(scope_label).strip() if scope_label else None,
            "static_run_rows": n_runs,
            "sar_status_completed": completed,
            "sar_status_failed": failed,
            "sar_status_other": other,
            "canonical_findings_rows": findings,
            "permission_matrix_rows": matrix,
            "archive_json_files": arch_n,
            "persistence_failure_rows": pf,
            "run_aggregate_status": str(run_aggregate_status).strip() if run_aggregate_status else None,
        }

    if not emit_summary:
        return

    scope_note = f" scope_label={scope_label!r}" if scope_label and str(scope_label).strip() else ""
    print()
    print(
        status_messages.status(
            (
                f"Post-run cohort quick check | session={stamp}{scope_note} | "
                f"static_runs={n_runs} (COMPLETED={completed} FAILED={failed} other={other}) | "
                f"canonical_findings_rows={findings} permission_matrix_rows={matrix} | "
                f"archive_json_files={arch_n}"
            ),
            level="info",
        )
    )
    agg = str(run_aggregate_status or "").strip().lower()
    if agg == "partial":
        print(
            status_messages.status(
                "Post-run cohort quick check: package rollup is partial (detector warnings/gates); "
                "workflow and DB persistence still finished — counts above are the persisted cohort.",
                level="info",
            )
        )
    if pf > 0:
        print(
            status_messages.status(
                f"Post-run cohort quick check: static_persistence_failures rows={pf} (see DB / logs).",
                level="warn",
            )
        )
    cmd = format_grain_integrity_cli_command(
        stamp,
        scope_label=str(scope_label).strip() if scope_label else None,
        count_archive=True,
        aggregate_json=False,
    )
    print(status_messages.status(f"Full grain / integrity report: {cmd}", level="info"))


def _atomic_write_run_health_json(path: Path, doc: dict[str, object]) -> None:
    """Write JSON via temp file + os.replace (same directory = atomic on POSIX)."""

    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def merge_post_run_grain_into_run_health_json(outcome: object) -> None:
    """Merge ``post_run_grain`` from ``session_metrics`` into on-disk run_health.json.

    Run health is written during summary render before the post-run grain query; this second
    phase updates ``post_run_grain*`` provenance fields and the grain payload. Uses an atomic
    replace; failures emit a warning (no silent swallow).
    """

    metrics = getattr(outcome, "session_metrics", None)
    if not isinstance(metrics, dict):
        return
    grain = metrics.get("post_run_grain")
    if not isinstance(grain, dict):
        return
    path_s = getattr(outcome, "run_health_json_path", None)
    if not path_s or not str(path_s).strip():
        return
    path = Path(str(path_s))
    if not path.is_file():
        print(
            status_messages.status(
                f"post_run_grain merge skipped: run health JSON not found ({path})",
                level="warn",
            )
        )
        return
    try:
        raw = path.read_text(encoding="utf-8")
        doc = json.loads(raw)
        if not isinstance(doc, dict):
            print(
                status_messages.status(
                    f"post_run_grain merge failed: run health JSON is not an object ({path})",
                    level="warn",
                )
            )
            return
        doc["post_run_grain"] = grain
        doc["post_run_grain_present"] = bool(grain)
        doc["post_run_grain_merged_at_utc"] = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        prev_rev = int(doc.get("run_health_revision") or 1)
        doc["run_health_revision"] = prev_rev + 1
        doc["post_run_merge_status"] = "merged"
        doc.pop("post_run_merge_error", None)
        _atomic_write_run_health_json(path, doc)
    except Exception as exc:
        print(
            status_messages.status(
                f"post_run_grain merge failed ({path}): {exc.__class__.__name__}: {exc}",
                level="warn",
            )
        )
        try:
            raw2 = path.read_text(encoding="utf-8")
            doc2 = json.loads(raw2)
            if isinstance(doc2, dict):
                doc2["post_run_merge_status"] = "failed"
                doc2["post_run_merge_error"] = f"{exc.__class__.__name__}: {exc}"
                prev_rev = int(doc2.get("run_health_revision") or 1)
                doc2["run_health_revision"] = prev_rev + 1
                _atomic_write_run_health_json(path, doc2)
        except Exception:
            pass
