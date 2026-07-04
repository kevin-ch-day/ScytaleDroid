"""CLI contract for report_dynamic_static_alignment.py."""

from __future__ import annotations

from scripts.db import report_dynamic_static_alignment as report


class _FakeCoreQ:
    def run_sql(self, sql, params=(), **kwargs):  # noqa: ANN001, ANN201
        table = params[0]
        if table == "dynamic_sessions":
            return [
                {
                    "index_name": "ix_dynamic_sessions_base_apk_sha256",
                    "column_name": "base_apk_sha256",
                }
            ]
        if table == "static_analysis_runs":
            return [
                {
                    "index_name": "ix_static_runs_base_hash_contract",
                    "column_name": "base_apk_sha256",
                },
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "status"},
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "run_class"},
                {
                    "index_name": "ix_static_runs_base_hash_contract",
                    "column_name": "identity_valid",
                },
            ]
        return []


def test_index_posture_accepts_static_composite_as_base_hash_coverage() -> None:
    posture = report._index_posture(_FakeCoreQ())
    assert posture["dynamic_sessions_base_apk_sha256_index_present"] == 1
    assert posture["static_runs_base_hash_contract_index_present"] == 1
    assert posture["static_runs_base_apk_sha256_index_covered"] == 1
