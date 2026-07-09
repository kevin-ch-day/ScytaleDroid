"""CLI contract for normalize_evidence_hash_collation.py."""

from __future__ import annotations

from scripts.db import normalize_evidence_hash_collation as migration


def test_target_ok_requires_ascii_bin_and_expected_nullability() -> None:
    row = {
        "column_type": "char(64)",
        "character_set_name": "ascii",
        "collation_name": "ascii_bin",
        "is_nullable": "YES",
    }
    assert migration._target_ok(row, nullable="YES")
    assert not migration._target_ok(row, nullable="NO")


def test_target_ok_rejects_legacy_collation() -> None:
    row = {
        "column_type": "char(64)",
        "character_set_name": "latin1",
        "collation_name": "latin1_swedish_ci",
        "is_nullable": "NO",
    }
    assert not migration._target_ok(row, nullable="NO")
