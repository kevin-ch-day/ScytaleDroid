"""Scan static-analysis logs and persistence audit artifacts after a run.

Operator-focused helpers: filesystem paths resolve from ``app_config``; DB counts
stay in ``Database.db_scripts.static_run_audit`` for MariaDB-backed runs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
import re
from collections.abc import Sequence
from pathlib import Path

from scytaledroid.Config import app_config

DEFAULT_MARKERS: tuple[str, ...] = (
    "error",
    "exception",
    "traceback",
    "persistence_failed",
    "PERSISTENCE",
    "db_write_failed:",
    "governance",
    "MISSING_GOVERNANCE",
    "Detector error",
    "persist_error",
    "canonical_failed",
)

_SESSION_RE = re.compile(r"^[0-9]{8}-[0-9a-zA-Z_-]+$")


def _looks_like_session_stamp(text: str) -> bool:
    token = text.strip()
    return bool(token) and len(token) <= 160 and bool(_SESSION_RE.match(token))


def tail_text_lines(path: Path, *, max_lines: int) -> list[str]:
    """Return up to ``max_lines`` complete lines from the end of a text file."""

    if not path.is_file() or max_lines <= 0:
        return []
    size = path.stat().st_size
    if size == 0:
        return []

    chunk_size = min(65536, max(size, 1))
    with path.open("rb") as handle:
        data = b""
        pos = size
        newlines = 0
        while pos > 0 and newlines < max_lines + 1:
            step = min(chunk_size, pos)
            pos -= step
            handle.seek(pos)
            data = handle.read(step) + data
            newlines = data.count(b"\n")
            if pos == 0:
                break

    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return lines[-max_lines:] if len(lines) > max_lines else lines


def _line_matches(
    line: str,
    *,
    session: str | None,
    markers_lower: Sequence[str],
    extra_lower: Sequence[str],
) -> bool:
    lowered = line.lower()
    tok = session.strip().lower() if session else ""
    if tok and tok in lowered:
        return True
    for m in markers_lower:
        if m in lowered:
            return True
    for e in extra_lower:
        if e in lowered:
            return True
    return False


def persistence_audit_candidates(
    session_stamp: str,
    *,
    output_root: Path | None = None,
) -> tuple[Path, Path]:
    base = (output_root or Path(app_config.OUTPUT_DIR)).expanduser().resolve() / "audit" / "persistence"
    stamp = session_stamp.strip()
    return (
        base / f"{stamp}_persistence_audit.json",
        base / f"{stamp}_missing_run_ids.json",
    )


def summarize_persistence_audit(path: Path) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"  (cannot read audit JSON: {exc})")
        return

    summary = payload.get("summary")
    meta_schema = payload.get("schema_version")
    total_apps = payload.get("total_apps")
    print(f"  schema_version : {meta_schema or 'unknown'}")
    print(f"  total_apps     : {total_apps if total_apps is not None else 'unknown'}")
    if not isinstance(summary, dict):
        return
    outcome = summary.get("outcome")
    if isinstance(outcome, dict):
        print(
            "  outcome        : "
            f"canonical_failed={bool(outcome.get('canonical_failed', False))} "
            f"persistence_failed={bool(outcome.get('persistence_failed', False))} "
            f"compat_export_failed={bool(outcome.get('compat_export_failed', False))}"
        )


def scan_log_tail(
    path: Path,
    *,
    session: str | None,
    tail_lines: int,
    markers: Sequence[str] | None,
    extras: Sequence[str],
    max_report: int,
) -> list[str]:
    lines = tail_text_lines(path, max_lines=tail_lines)
    markers_l = tuple(m.lower() for m in (markers or DEFAULT_MARKERS))
    extras_l = tuple(e.lower() for e in extras if e.strip())
    picked: list[str] = []
    for line in lines:
        if _line_matches(line, session=session, markers_lower=markers_l, extra_lower=extras_l):
            picked.append(line)
            if len(picked) >= max_report:
                break
    return picked


def emit_static_audit_report(
    *,
    session: str | None,
    tail_lines: int = 8000,
    max_hits_per_file: int = 120,
    extra_keywords: Sequence[str] = (),
    logs_root: Path | None = None,
    output_root: Path | None = None,
) -> None:
    """Print resolved paths plus optional persistence summary and log hits."""

    root = (logs_root or Path(app_config.LOGS_DIR)).expanduser().resolve()
    out_root = (output_root or Path(app_config.OUTPUT_DIR)).expanduser().resolve()
    static_log = root / "static_analysis.log"
    error_log = root / "error.log"
    tp_dir = root / "third_party"
    extras = tuple(extra_keywords)

    print("Static analysis — post-run filesystem audit")
    print("--------------------------------------------")
    print(f"Logs root     : {root}")
    print(f"Static log    : {static_log} ({'present' if static_log.is_file() else 'missing'})")
    print(f"Error log     : {error_log} ({'present' if error_log.is_file() else 'missing'})")
    print(f"Third-party   : {tp_dir} ({'present' if tp_dir.is_dir() else 'missing'})")
    print(f"Reports dir   : {(Path(app_config.DATA_DIR).expanduser().resolve() / 'static_analysis' / 'reports')}")
    print(f"Tail lines    : {tail_lines} (per file)")
    print(f"Markers       : {', '.join(DEFAULT_MARKERS[:6])}, … (+ extras)")

    if session:
        st = session.strip()
        print()
        print(f"Session stamp : {st}")
        if not _looks_like_session_stamp(st):
            print("  Note: stamp does not match typical YYYYMMDD-<slug> pattern; scan still proceeds.")
        pa, mi = persistence_audit_candidates(st, output_root=out_root)
        print("Persistence audits:")
        for label, cand in ("persistence_audit", pa), ("missing_run_ids", mi):
            if cand.is_file():
                print(f"  [{label}] {cand}")
                if label == "persistence_audit":
                    summarize_persistence_audit(cand)
            else:
                print(f"  [{label}] (not found) {cand}")

    markers = DEFAULT_MARKERS
    print()
    for label, path in ("static_analysis.log", static_log), ("error.log", error_log):
        print(f"[{label}] matching lines (most recent tail, capped):")
        if not path.is_file():
            print("  (file missing)")
            print()
            continue
        hits = scan_log_tail(
            path,
            session=session.strip() if session else None,
            tail_lines=tail_lines,
            markers=markers,
            extras=extras,
            max_report=max_hits_per_file,
        )
        if not hits:
            print("  (no hits for session substring + default markers in tail window)")
        else:
            for line in hits:
                print(f"  {line}")
        print()

    if tp_dir.is_dir():
        recent = sorted(tp_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
        if recent:
            print("[third_party] recent *.log (newest first):")
            for p in recent:
                mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                print(f"  {p.name}  mtime={mtime}")

    print()
    print(
        "DB reconciliation (MariaDB): "
        "python -m scytaledroid.Database.db_scripts.static_run_audit --session <stamp>"
    )
    print("Operator log listing: Menus expose this via system utilities → show log paths (show_log_locations).")


__all__ = [
    "DEFAULT_MARKERS",
    "emit_static_audit_report",
    "persistence_audit_candidates",
    "scan_log_tail",
    "summarize_persistence_audit",
    "tail_text_lines",
]
