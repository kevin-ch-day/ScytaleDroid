"""Lightweight user script registry and runner for DB utilities.

Looks for scripts under ``scripts/db`` (relative to repo root):

- ``.sql`` files: executed statement-by-statement (naïve splitter on ';').
- ``.py``  files: must expose a ``run(core_q)`` function and may print output.

This is intentionally minimal so you can add, tune, and delete scripts easily
without touching the main CLI code. The menu will discover files at runtime.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


SCRIPTS_DIR = Path("scripts/db")


@dataclass(frozen=True)
class UserScript:
    name: str
    path: Path
    kind: str  # "sql" or "py"
    desc: str
    mtime: float


def ensure_dir() -> Path:
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    return SCRIPTS_DIR


def discover_scripts() -> List[UserScript]:
    base = ensure_dir()
    entries: List[UserScript] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in {".sql", ".py"}:
            continue
        kind = "sql" if suffix == ".sql" else "py"
        # First line comment (if any) becomes desc
        desc = ""
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                first = fh.readline().strip()
                if first.startswith("-- "):
                    desc = first[3:].strip()
                elif first.startswith("# "):
                    desc = first[2:].strip()
        except Exception:
            pass
        entries.append(
            UserScript(name=path.name, path=path, kind=kind, desc=desc, mtime=path.stat().st_mtime)
        )
    return entries


def _split_sql(statements: str) -> List[str]:
    """Very simple SQL splitter on ';' outside of single quotes.

    Not perfect, but good enough for short admin scripts.
    """
    out: List[str] = []
    buf: List[str] = []
    in_single = False
    escape = False
    for ch in statements:
        buf.append(ch)
        if ch == "\\" and not escape:
            escape = True
            continue
        if ch == "'" and not escape:
            in_single = not in_single
        escape = False
        if ch == ";" and not in_single:
            segment = "".join(buf).strip()
            if segment:
                out.append(segment[:-1].strip())
            buf = []
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return [stmt for stmt in out if stmt]


def run_sql_script(path: Path, *, print_fn, table_fn) -> None:
    from scytaledroid.Database.db_core import db_queries as core_q
    text = path.read_text(encoding="utf-8")
    stmts = _split_sql(text)
    if not stmts:
        print_fn("(empty or unparsable SQL)")
        return
    for index, stmt in enumerate(stmts, start=1):
        stmt_stripped = stmt.strip()
        try:
            if stmt_stripped.upper().startswith("SELECT") or stmt_stripped.upper().startswith("WITH"):
                rows = core_q.run_sql(stmt_stripped, fetch="all")
                table_fn([f"col{i+1}" for i in range(len(rows[0]) if rows else 0)], rows or [])
            else:
                core_q.run_sql(stmt_stripped)
            print_fn(f"[{index}/{len(stmts)}] OK")
        except Exception as exc:
            print_fn(f"[{index}/{len(stmts)}] ERROR: {exc}")


def run_python_script(path: Path, *, print_fn) -> None:
    # Load module from file and call run(core_q)
    try:
        spec = importlib.util.spec_from_file_location(f"user_script_{path.stem}", str(path))
        if spec is None or spec.loader is None:
            print_fn("Unable to load script.")
            return
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module  # type: ignore[attr-defined]
        spec.loader.exec_module(module)  # type: ignore[attr-defined]
    except Exception as exc:
        print_fn(f"Import failed: {exc}")
        return

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        if hasattr(module, "run"):
            module.run(core_q)  # type: ignore[arg-type]
        else:
            print_fn("Script missing run(core_q) entrypoint.")
    except Exception as exc:
        print_fn(f"Execution failed: {exc}")


def delete_script(path: Path) -> bool:
    try:
        path.unlink(missing_ok=False)
        return True
    except Exception:
        return False


def create_sql_script(name: str, content: str) -> Path | None:
    base = ensure_dir()
    safe = "".join(ch for ch in name if ch.isalnum() or ch in ("-", "_", ".")).strip()
    if not safe.endswith(".sql"):
        safe += ".sql"
    target = base / safe
    if target.exists():
        return None
    target.write_text(content, encoding="utf-8")
    return target

