"""CLI contract for check_evidence_storage_posture.py."""

from __future__ import annotations

from scripts.db import check_evidence_storage_posture as posture


def test_hash_collation_ok_requires_ascii_bin_targets() -> None:
    assert posture._hash_collation_ok(
        [
            {
                "table_name": "static_analysis_findings",
                "column_name": "evidence_hash",
                "column_type": "char(64)",
                "character_set_name": "ascii",
                "collation_name": "ascii_bin",
            },
            {
                "table_name": "static_finding_evidence_payloads",
                "column_name": "evidence_hash",
                "column_type": "char(64)",
                "character_set_name": "ascii",
                "collation_name": "ascii_bin",
            },
        ]
    )


def test_hash_collation_rejects_mixed_live_legacy_collations() -> None:
    assert not posture._hash_collation_ok(
        [
            {
                "table_name": "static_analysis_findings",
                "column_name": "evidence_hash",
                "column_type": "char(64)",
                "character_set_name": "utf8mb4",
                "collation_name": "utf8mb4_general_ci",
            },
            {
                "table_name": "static_finding_evidence_payloads",
                "column_name": "evidence_hash",
                "column_type": "char(64)",
                "character_set_name": "latin1",
                "collation_name": "latin1_swedish_ci",
            },
        ]
    )
