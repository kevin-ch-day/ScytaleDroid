"""Static analysis operator preflight (DB, schema gate, Permission Intel, paths).

Extracted from ``run_dispatch`` so orchestration stays thin and this surface is
easier to test and evolve independently.
"""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.Utils.DisplayUtils import status_messages


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


def _emit_permission_intel_and_grade(params: RunParameters) -> None:
    """Print Intel / paper-grade lines."""

    paper = bool(getattr(params, "paper_grade_requested", True))
    intel_label = "unknown"
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db
        from scytaledroid.StaticAnalysis.cli.execution.pipeline import governance_ready
    except Exception as exc:  # pragma: no cover - import guard
        print(
            status_messages.status(
                f"Permission Intel: import failed ({exc}).",
                level="warn",
            )
        )
        intel_label = "query_failed"
    else:
        if not intel_db.is_permission_intel_configured():
            intel_label = "missing"
            print(
                status_messages.status(
                    "Permission Intel: missing — run will be EXPERIMENTAL unless SCYTALEDROID_CANONICAL_GRADE=0.",
                    level="warn",
                )
            )
        else:
            try:
                gov_ok, gov_detail = governance_ready()
            except Exception as exc:
                intel_label = "query_failed"
                print(
                    status_messages.status(
                        f"Permission Intel: query_failed — {exc}",
                        level="warn",
                    )
                )
            else:
                if gov_ok:
                    intel_label = "ok"
                    print(
                        status_messages.status(
                            "Permission Intel: OK — governance snapshot rows present; paper-grade ready.",
                            level="info",
                        )
                    )
                elif gov_detail == "governance_missing":
                    intel_label = "governance_missing"
                    print(
                        status_messages.status(
                            "Permission Intel: configured but governance_missing — load governance snapshots "
                            "before paper-grade runs.",
                            level="warn",
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

    if paper:
        if intel_label == "ok":
            print(status_messages.status("Paper-grade: ready", level="info"))
        else:
            print(
                status_messages.status(
                    "Paper-grade: experimental (intel/governance not satisfied for canonical grade)",
                    level="warn",
                )
            )
    else:
        print(
            status_messages.status(
                "Paper-grade: experimental (SCYTALEDROID_CANONICAL_GRADE=0)",
                level="info",
            )
        )


def _emit_db_persistence_preflight(params: RunParameters) -> None:
    if getattr(params, "persistence_ready", True):
        print(
            status_messages.status(
                "DB persistence: enabled (session writes to MariaDB when configured)",
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

    print(
        status_messages.status(
            "Canonical static writes only (legacy runs/metrics/buckets mirror removed).",
            level="info",
        )
    )


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
        print(status_messages.status("Output paths: writable", level="info"))
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
            f"Split scan: {'on' if split_on else 'off'}",
            level="info",
        )
    )


def emit_static_run_preflight_summary(
    params: RunParameters,
    *,
    frozen_ctx: StaticRunContext,
    base_dir: Path,
) -> None:
    """One consolidated operator-facing block before ``execute_scan`` (real runs only)."""

    if params.dry_run:
        return
    if frozen_ctx.quiet and frozen_ctx.batch:
        return

    print()
    print(status_messages.step("Static run preflight", label="Static Analysis"))

    _emit_primary_db_and_schema(params)
    _emit_permission_intel_and_grade(params)
    _emit_db_persistence_preflight(params)
    _emit_output_paths_and_split(params, base_dir)
    print()


__all__ = [
    "check_static_persistence_readiness",
    "emit_static_run_preflight_summary",
]
