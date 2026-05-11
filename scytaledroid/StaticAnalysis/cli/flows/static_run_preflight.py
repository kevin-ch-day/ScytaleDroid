"""Static analysis operator preflight (DB, schema gate, Permission Intel, paths).

Extracted from ``run_dispatch`` so orchestration stays thin and this surface is
easier to test and evolve independently.
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
        print(
            status_messages.status(
                "Primary DB: not configured (filesystem-only; set SCYTALEDROID_DB_* for MariaDB)",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "Static schema gate: skipped (no MariaDB backend)",
                level="info",
            )
        )
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
        print(status_messages.status("Primary DB: OK", level="info"))
    else:
        print(
            status_messages.status(
                "Primary DB: failed (cannot connect — check SCYTALEDROID_DB_URL or *_NAME/USER/PASSWD/HOST/PORT)",
                level="warn",
            )
        )

    gate_ok, gate_msg, gate_detail = check_static_persistence_readiness(params)
    if gate_ok:
        print(status_messages.status("Static schema gate: OK", level="info"))
    else:
        tail = f" — {gate_detail.strip()}" if (gate_detail or "").strip() else ""
        print(
            status_messages.status(
                f"Static schema gate: failed — {gate_msg}{tail}",
                level="warn",
            )
        )


def _emit_research_readiness_block(params: RunParameters) -> None:
    """Governance / paper-grade lines (does not gate core scan execution)."""

    print_section("Research readiness")
    paper = bool(getattr(params, "paper_grade_requested", True))
    intel_label = "unknown"
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db
        from scytaledroid.StaticAnalysis.cli.execution.pipeline import governance_ready
    except Exception as exc:  # pragma: no cover - import guard
        intel_label = "query_failed"
        print(
            status_messages.status(
                f"Permission Intel: import failed ({exc}).",
                level="warn",
            )
        )
    else:
        if not intel_db.is_permission_intel_configured():
            intel_label = "missing"
            print(status_messages.status("Permission Intel: not configured", level="info"))
        else:
            try:
                gov_ok, gov_detail = governance_ready()
            except Exception as exc:
                intel_label = "query_failed"
                print(
                    status_messages.status(
                        f"Permission Intel: query failed — {exc}",
                        level="warn",
                    )
                )
            else:
                if gov_ok:
                    intel_label = "ok"
                    print(
                        status_messages.status(
                            "Permission Intel: OK (governance snapshot rows present)",
                            level="info",
                        )
                    )
                elif gov_detail == "governance_missing":
                    intel_label = "governance_missing"
                    print(
                        status_messages.status(
                            "Permission Intel: configured — governance snapshots not loaded",
                            level="info",
                        )
                    )
                else:
                    intel_label = "query_failed"
                    print(
                        status_messages.status(
                            f"Permission Intel: governance check not satisfied ({gov_detail}).",
                            level="warn",
                        )
                    )

    impact = (
        "Impact: Core scan and DB persistence continue. "
        "Paper-grade / governance-complete evidence requires Permission Intel readiness."
    )
    if not paper:
        print(
            status_messages.status(
                "Run grade: EXPERIMENTAL (paper-grade not requested — SCYTALEDROID_CANONICAL_GRADE=0)",
                level="info",
            )
        )
        print(status_messages.status(impact, level="info"))
        print(
            status_messages.status(
                "Action: Enable canonical grade and configure Permission Intel for paper-grade output.",
                level="info",
            )
        )
        return

    if intel_label == "ok":
        print(status_messages.status("Run grade: PAPER-GRADE READY", level="info"))
        print(
            status_messages.status(
                "Core scan: allowed — Permission Intel does not gate detectors or persistence.",
                level="info",
            )
        )
        return

    print(
        status_messages.status(
            "Run grade: EXPERIMENTAL (research readiness — governance signals incomplete)",
            level="info",
        )
    )
    print(status_messages.status(impact, level="info"))
    if intel_label == "missing":
        print(
            status_messages.status(
                "Action: Configure SCYTALEDROID_PERMISSION_INTEL_DB_* (and governance snapshots) "
                "for paper-grade runs.",
                level="info",
            )
        )
    elif intel_label == "governance_missing":
        print(
            status_messages.status(
                "Action: Load Permission Intel governance snapshots before paper-grade runs.",
                level="info",
            )
        )
    elif intel_label == "query_failed":
        print(
            status_messages.status(
                "Action: Fix Permission Intel connectivity/queries, then re-check governance readiness.",
                level="info",
            )
        )
    else:
        print(
            status_messages.status(
                "Action: Resolve Permission Intel / governance readiness before paper-grade runs.",
                level="info",
            )
        )


def _emit_db_persistence_preflight(params: RunParameters) -> None:
    if getattr(params, "persistence_ready", True):
        print(
            status_messages.status(
                "DB persistence: ON (session writes to MariaDB when configured)",
                level="info",
            )
        )
    else:
        print(
            status_messages.status(
                "DB persistence: skipped (SCYTALEDROID_PERSISTENCE_READY=0 — filesystem/report outputs only)",
                level="warn",
            )
        )

    print(status_messages.status("Legacy mirrors: OFF (canonical static writes only)", level="info"))


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
        print(status_messages.status("Output paths: OK (writable)", level="info"))
    else:
        print(
            status_messages.status(
                f"Output paths: failed ({first_err or 'unknown error'})",
                level="warn",
            )
        )

    split_on = bool(getattr(params, "scan_splits", True))
    print(
        status_messages.status(
            f"Split scan: {'ON' if split_on else 'OFF'}",
            level="info",
        )
    )


def _emit_run_context_preflight(params: RunParameters, selection: Any | None) -> None:
    """Session / scope / preset snapshot (mirrors progress Run context; counts optional)."""

    print_section("Run context")
    session = (getattr(params, "session_stamp", None) or "")
    session = str(session).strip() or "(unspecified)"
    print(status_messages.status(f"Session: {session}", level="info"))
    scope = getattr(params, "scope_label", None) or getattr(params, "scope", None) or ""
    scope = str(scope).strip() or "—"
    print(status_messages.status(f"Scope: {scope}", level="info"))
    preset = str(getattr(params, "profile_label", None) or getattr(params, "profile", "") or "—").strip()
    print(status_messages.status(f"Preset: {preset}", level="info"))
    workers = str(getattr(params, "workers", None) or "auto").strip()
    print(status_messages.status(f"Workers: {workers}", level="info"))
    groups = tuple(getattr(selection, "groups", ()) or ()) if selection is not None else ()
    if groups:
        n_pkg = len(groups)
        n_apk = sum(len(getattr(g, "artifacts", ()) or ()) for g in groups)
        print(status_messages.status(f"Packages in this run: {n_pkg}", level="info"))
        print(status_messages.status(f"APK files in this run: {n_apk}", level="info"))


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
    print(status_messages.step("Static run preflight", label="Static Analysis"))

    print_section("Core readiness")
    _emit_primary_db_and_schema(params)
    _emit_db_persistence_preflight(params)
    _emit_output_paths_and_split(params, base_dir)
    _emit_research_readiness_block(params)
    _emit_run_context_preflight(params, selection)
    print()


__all__ = [
    "check_static_persistence_readiness",
    "emit_static_run_preflight_summary",
]
