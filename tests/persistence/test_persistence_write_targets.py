from __future__ import annotations

import ast
import inspect
import re

from scytaledroid.StaticAnalysis.cli.persistence import run_summary as rs
from scytaledroid.StaticAnalysis.cli.persistence import run_writers as rw
from scytaledroid.StaticAnalysis.cli.persistence.contracts import (
    LEDGER_TABLES,
    SCIENTIFIC_UOW_TABLES,
)

_WRITE_RE = re.compile(r"\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+([a-zA-Z0-9_]+)", re.IGNORECASE)


def _string_literals(source: str) -> list[str]:
    tree = ast.parse(source)
    values: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.append(node.value)
    return values


def _write_targets(source: str) -> set[str]:
    targets: set[str] = set()
    for text in _string_literals(source):
        probe = text.lstrip().upper()
        if not probe.startswith(("INSERT", "UPDATE", "DELETE")):
            continue
        for match in _WRITE_RE.finditer(text):
            targets.add(match.group(1).lower())
    return targets


def test_persistence_direct_write_targets_are_declared():
    # Restrict this check to the run persistence call path helpers that are used by
    # persist_run_summary. This keeps the assertion tied to the atomic UoW surface.
    sources = [
        inspect.getsource(rs.persist_run_summary),
        inspect.getsource(rs._persist_static_analysis_findings),
        inspect.getsource(rs._persist_correlation_results),
        inspect.getsource(rw._ensure_app_version),
        inspect.getsource(rw._create_static_run),
        inspect.getsource(rw._update_static_run_metadata),
        inspect.getsource(rw.update_static_run_status),
    ]

    touched = set()
    for src in sources:
        touched.update(_write_targets(src))

    assert touched, "write-target extraction unexpectedly found no tables"
    allowed = SCIENTIFIC_UOW_TABLES | LEDGER_TABLES
    undeclared = sorted(touched - allowed)
    assert not undeclared, f"Undeclared write targets in persistence path: {undeclared}"
