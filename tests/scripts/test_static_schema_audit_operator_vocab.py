"""Operator vocabulary mapping for ``static_schema_audit`` (no DB)."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_audit_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "db" / "static_schema_audit.py"
    spec = importlib.util.spec_from_file_location("static_schema_audit", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_legacy_table_names_matches_legacy_five_plus_correlations() -> None:
    m = _load_audit_module()
    assert m.LEGACY_TABLE_NAMES == frozenset(
        {"runs", "findings", "metrics", "buckets", "contributors", "correlations"}
    )


def test_operator_vocab_mapping() -> None:
    m = _load_audit_module()
    f = m._operator_vocab_for_classification
    assert f("canonical_keep") == "CANONICAL"
    assert f("derived_keep") == "DERIVED"
    assert f("bridge_compat") == "OPTIONAL (bridge compat)"
    assert f("legacy_freeze") == "LEGACY MIRROR"
    assert f("") == "—"
