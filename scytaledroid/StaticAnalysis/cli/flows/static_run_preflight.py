"""Static analysis operator preflight (DB, schema gate, Permission Intel, paths).

Extracted from ``run_dispatch`` so orchestration stays thin and this surface is
easier to test and evolve independently.

Preflight body lines are mostly plain text (no ``[INFO]`` ribbons) so the block reads as
a compact checklist; **blocking** conditions use ``status_messages`` **error** rows
(primary DB connect failure, schema gate failure, output paths not writable).
**Degraded** but usually non-blocking Intel / persistence lines use **warn** rows when
plain text would be too quiet (Intel import/query failures, governance check errors,
DB persistence skipped). Explicit degraded wording (e.g. ``not configured``,
``EXPERIMENTAL``, ``snapshots not loaded``) stays plain.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import print_section


def _preflight_plain(msg: str) -> None:
    print(msg)


def _preflight_warn_row(msg: str) -> None:
    print(status_messages.status(msg, level="warn"))


def _preflight_error_row(msg: str) -> None:
    print(status_messages.status(msg, level="error"))


def check_static_persistence_readiness(params: RunParameters) -> tuple[bool, str, str]:
    """Return ``(gate_ok, summary_message, detail_tail)`` for schema gate + static DDL checks."""

    if params.dry_run:
        return True, "dry-run: persistence gate skipped", ""
    ok_base, msg_base, detail_base = schema_gate.check_base_schema()
    if not ok_base:
        return False, msg_base, detail_base or ""
    ok_static, msg_static, detail_static = schema_gate.static_schema_gate()
    if not ok_static:
        return False, msg_static, detail_static or ""
    return True, "OK", ""


def _emit_primary_db_and_schema(params: RunParameters) -> None:
    from scytaledroid.Database.db_core import db_config as _dbc

    if not _dbc.db_enabled():
        _preflight_plain(
            "Primary DB: not configured (filesystem-only; set SCYTALEDROID_DB_* for MariaDB)"
        )
        _preflight_plain("Static schema gate: skipped (no MariaDB backend)")
        return

    primary_ok = False
    try:
        from scytaledroid.Database.db_core.db_engine import DatabaseEngine

        eng = DatabaseEngine()
        eng.fetch_one("SELECT 1")
        eng.close()
        primary_ok = True
    except Exception:
        primary_ok = False
    if primary_ok:
        _preflight_plain("Primary DB: OK")
    else:
        _preflight_error_row(
            "Primary DB: ERROR — cannot connect (check SCYTALEDROID_DB_URL or "
            "*_NAME/USER/PASSWD/HOST/PORT)"
        )

    gate_ok, gate_msg, gate_detail = check_static_persistence_readiness(params)
    if gate_ok:
        _preflight_plain("Static schema gate: OK")
    else:
        tail = f" — {gate_detail.strip()}" if (gate_detail or "").strip() else ""
        _preflight_error_row(f"Static schema gate: ERROR — {gate_msg}{tail}")


def _emit_intel_and_run_grade_lines(params: RunParameters) -> None:
    """Permission Intel + paper-grade messaging (does not gate core scan execution)."""

    from scytaledroid.StaticAnalysis.cli.intel_gate import evaluate_intel_for_preflight

    paper = bool(getattr(params, "paper_grade_requested", True))
    ev = evaluate_intel_for_preflight()
    intel_label = ev.label

    if ev.governance_query_exc is not None:
        _preflight_warn_row(
            f"Permission Intel: WARN — query failed — {ev.governance_query_exc}"
        )
    elif intel_label == "missing":
        _preflight_plain("Permission Intel: not configured")
    elif intel_label == "ok":
        _preflight_plain("Permission Intel: OK (governance snapshot rows present)")
    elif intel_label == "governance_missing":
        _preflight_plain("Permission Intel: configured — governance snapshots not loaded")
    else:
        _preflight_warn_row(
            f"Permission Intel: WARN — governance check not satisfied ({ev.governance_detail})."
        )

    impact = (
        "Impact: Core scan and DB persistence continue. "
        "Paper-grade / governance-complete evidence requires Permission Intel readiness."
    )
    short_impact = (
        "Core scan + DB persist proceed; paper-grade needs Permission Intel + governance snapshots."
    )
    verbose = bool(getattr(params, "verbose_output", False))

    if not paper:
        _preflight_plain(
            "Run grade: EXPERIMENTAL (paper-grade not requested — SCYTALEDROID_CANONICAL_GRADE=0). "
            + (impact if verbose else short_impact)
        )
        _preflight_plain(
            "Next: SCYTALEDROID_CANONICAL_GRADE=1 and Permission Intel when you want paper-grade output."
        )
        return

    if intel_label == "ok":
        _preflight_plain(
            "Run grade: PAPER-GRADE READY — Permission Intel + governance snapshots OK; "
            "Intel does not gate detectors or persistence."
        )
        return

    # Paper requested; Intel path not paper-ready (Intel line was printed above).
    tail_by_intel = {
        "missing": (
            "Paper-grade: configure SCYTALEDROID_PERMISSION_INTEL_DB_* and load governance snapshots."
        ),
        "governance_missing": (
            "Paper-grade: load Permission Intel governance snapshots (Intel is already reachable)."
        ),
        "query_failed": (
            "Paper-grade: fix Permission Intel connectivity or governance queries, then re-check readiness."
        ),
    }
    tail = tail_by_intel.get(
        intel_label,
        "Paper-grade: resolve Permission Intel / governance readiness before claiming paper output.",
    )
    _preflight_plain(
        "Run grade: EXPERIMENTAL (research readiness — governance signals incomplete for paper-grade). "
        + (impact if verbose else short_impact)
    )
    _preflight_plain(tail)


def _emit_db_persistence_preflight(params: RunParameters) -> None:
    if getattr(params, "persistence_ready", True):
        _preflight_plain("DB persistence: ON (session writes to MariaDB when configured)")
    else:
        _preflight_warn_row(
            "DB persistence: WARN — skipped (SCYTALEDROID_PERSISTENCE_READY=0 — "
            "filesystem/report outputs only; session static rows will not be written)"
        )

    _preflight_plain("Legacy mirrors: OFF (canonical static writes only)")


def _emit_output_paths_and_split(params: RunParameters, base_dir: Path) -> None:
    roots = [Path(app_config.DATA_DIR), base_dir]
    write_ok = True
    first_err: str | None = None
    for root in roots:
        try:
            root.mkdir(parents=True, exist_ok=True)
            probe = root / ".scytaledroid_write_probe_delete_me"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError as exc:
            write_ok = False
            first_err = str(exc)
            break
    if write_ok:
        _preflight_plain("Output paths: OK (writable)")
    else:
        _preflight_error_row(
            f"Output paths: ERROR — not writable ({first_err or 'unknown error'})"
        )

    split_on = bool(getattr(params, "scan_splits", True))
    _preflight_plain(f"Split scan: {'ON' if split_on else 'OFF'}")


def _emit_run_context_preflight(params: RunParameters, selection: Any | None) -> None:
    """Session / scope / preset snapshot (mirrors progress Run context; counts optional)."""

    session = (getattr(params, "session_stamp", None) or "")
    session = str(session).strip() or "(unspecified)"
    _preflight_plain(f"Session: {session}")
    scope = getattr(params, "scope_label", None) or getattr(params, "scope", None) or ""
    scope = str(scope).strip() or "—"
    _preflight_plain(f"Scope: {scope}")
    preset = str(getattr(params, "profile_label", None) or getattr(params, "profile", "") or "—").strip()
    _preflight_plain(f"Preset: {preset}")
    workers = str(getattr(params, "workers", None) or "auto").strip()
    _preflight_plain(f"Workers: {workers}")
    groups = tuple(getattr(selection, "groups", ()) or ()) if selection is not None else ()
    if groups:
        n_pkg = len(groups)
        n_apk = sum(len(getattr(g, "artifacts", ()) or ()) for g in groups)
        _preflight_plain(f"Packages in this run: {n_pkg}")
        _preflight_plain(f"APK files in this run: {n_apk}")


def emit_static_run_preflight_summary(
    params: RunParameters,
    *,
    frozen_ctx: StaticRunContext,
    base_dir: Path,
    selection: Any | None = None,
) -> None:
    """One consolidated operator-facing block before ``execute_scan`` (real runs only)."""

    if params.dry_run:
        return
    if frozen_ctx.quiet and frozen_ctx.batch:
        return

    print()
    print("Static Analysis ▶ Static run preflight")
    print()

    print_section("Core readiness")
    _emit_primary_db_and_schema(params)
    _emit_db_persistence_preflight(params)
    _emit_output_paths_and_split(params, base_dir)
    _emit_intel_and_run_grade_lines(params)
    print()

    print_section("Run context")
    _emit_run_context_preflight(params, selection)
    print()

    print_section("Catalog & labels")
    _emit_catalog_display_labels(selection)
    print()

    print_section("After this run")
    _preflight_plain(
        "Read-only DB checks: Post-run diagnostics → 11 (DB-backed session checks); "
        "Database Tools → 12 (session health, grain, artifact registry, static_session_id rollout verify)."
    )
    print()


def _emit_catalog_display_labels(selection: Any | None) -> None:
    """``apps.display_name`` coverage for this run's packages (read-only; no CSV apply)."""

    if selection is None:
        _preflight_plain("Display labels: skipped (no selection)")
        return
    groups = tuple(getattr(selection, "groups", ()) or ())
    if not groups:
        _preflight_plain("Display labels: skipped (empty selection)")
        return
    try:
        from scytaledroid.Database.db_utils.catalog.app_display_label_preflight import (
            format_apps_display_name_hygiene_line,
        )

        line = format_apps_display_name_hygiene_line(groups)
    except Exception as exc:
        _preflight_warn_row(f"Display labels: WARN — {exc}")
        return
    if line:
        _preflight_plain(line)


__all__ = [
    "check_static_persistence_readiness",
    "emit_static_run_preflight_summary",
]
