"""Matrix persistence dedupes permissions that collide after lowercase canonicalization.

``static_permission_matrix.permission_name`` keeps **first-seen detector casing**
after ``strip()``; dedupe is by lowercase key only (see ``permission_matrix`` module
docstring). ``static_permission_risk_vnext`` stores lowercase — pairing is via
``LOWER(spm.permission_name)`` in SQL backfill/joins.
"""

from __future__ import annotations

import pytest
from scytaledroid.StaticAnalysis.cli.persistence.permission_matrix import persist_permission_matrix


def test_permission_matrix_logs_when_table_missing_but_profiles_present(
    monkeypatch, caplog
) -> None:
    import logging

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.ensure_table",
        lambda: False,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.require_canonical_schema",
        lambda: None,
    )
    replaced: dict[str, object] = {}
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.replace_for_run",
        lambda *a, **k: replaced.setdefault("called", True),
    )

    with caplog.at_level(logging.WARNING):
        persist_permission_matrix(
            static_run_id=42,
            package_name="com.example.app",
            apk_id=None,
            permission_profiles={"android.permission.CAMERA": {"is_runtime_dangerous": True}},
        )
    assert "matrix rows not persisted" in caplog.text
    assert "called" not in replaced


def test_permission_matrix_skips_case_colliding_keys(monkeypatch) -> None:
    captured: list[dict[str, object]] = []

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.ensure_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.require_canonical_schema",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.replace_for_run",
        lambda _rid, rows: captured.extend(list(rows)),
    )

    persist_permission_matrix(
        static_run_id=1,
        package_name="com.example.app",
        apk_id=None,
        permission_profiles={
            "Android.Permission.CAMERA": {"is_runtime_dangerous": True},
            "android.permission.camera": {"is_runtime_dangerous": False},
        },
    )
    assert len(captured) == 1
    assert captured[0]["permission_name"] == "Android.Permission.CAMERA"


def test_permission_matrix_strips_leading_trailing_whitespace_on_keys(monkeypatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.ensure_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.require_canonical_schema",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.replace_for_run",
        lambda _rid, rows: captured.extend(list(rows)),
    )
    persist_permission_matrix(
        static_run_id=21,
        package_name="com.example.ws",
        apk_id=None,
        permission_profiles={
            "  android.permission.INTERNET  ": {"is_runtime_dangerous": False},
        },
    )
    assert len(captured) == 1
    assert captured[0]["permission_name"] == "android.permission.INTERNET"


def test_permission_matrix_fills_catalog_fields_when_profile_omits_them(monkeypatch) -> None:
    import json

    captured: list[dict[str, object]] = []

    class _Desc:
        source = "permission_intel_v1"
        protection = ("dangerous", "instant")
        permission_group = "CAMERA"
        background_permission = "android.permission.CAMERA"
        authority_class = "AOSP_PUBLIC"
        feature_dependency = "android.hardware.camera"

        def guard_strength(self) -> str:
            return "dangerous"

    class _Catalog:
        def describe(self, name: str):
            if name == "android.permission.CAMERA":
                return _Desc()
            return None

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.load_permission_catalog",
        lambda: _Catalog(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.ensure_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.require_canonical_schema",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.replace_for_run",
        lambda _rid, rows: captured.extend(list(rows)),
    )
    persist_permission_matrix(
        static_run_id=11,
        package_name="com.example.app",
        apk_id=None,
        permission_profiles={"android.permission.CAMERA": {"is_runtime_dangerous": True}},
    )
    assert len(captured) == 1
    row = captured[0]
    assert row["guard_strength"] == "dangerous"
    assert row["protection"] == "dangerous|instant"
    flags = json.loads(str(row["flags"]))
    assert flags["catalog_source"] == "permission_intel_v1"
    assert flags["protection_levels"] == ["dangerous", "instant"]
    assert flags["permission_group"] == "CAMERA"
    assert flags["background_permission"] == "android.permission.CAMERA"
    assert flags["authority_class"] == "AOSP_PUBLIC"
    assert flags["feature_dependency"] == "android.hardware.camera"


def test_permission_matrix_skips_empty_keys(monkeypatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.ensure_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.require_canonical_schema",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.replace_for_run",
        lambda _rid, rows: captured.extend(list(rows)),
    )
    persist_permission_matrix(
        static_run_id=2,
        package_name="com.example.app",
        apk_id=None,
        permission_profiles={
            "": {"is_runtime_dangerous": False},
            "android.permission.INTERNET": {"is_runtime_dangerous": False},
        },
    )
    assert len(captured) == 1
    assert captured[0]["permission_name"] == "android.permission.INTERNET"


def test_permission_matrix_split_like_merged_profiles_same_perm_different_casing(
    monkeypatch,
) -> None:
    """Merged base+split profile maps often repeat the same perm with different casing."""
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.ensure_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.require_canonical_schema",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.replace_for_run",
        lambda _rid, rows: captured.extend(list(rows)),
    )
    persist_permission_matrix(
        static_run_id=3,
        package_name="com.example.splits",
        apk_id=None,
        permission_profiles={
            "android.permission.USE_BIOMETRIC": {"is_runtime_dangerous": True},
            "android.permission.use_biometric": {"is_runtime_dangerous": False},
        },
    )
    assert len(captured) == 1
    assert captured[0]["permission_name"] == "android.permission.USE_BIOMETRIC"


def test_permission_matrix_replace_failure_propagates(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.ensure_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.require_canonical_schema",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_matrix.matrix_db.replace_for_run",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("matrix insert failed")),
    )
    with pytest.raises(RuntimeError, match="matrix insert failed"):
        persist_permission_matrix(
            static_run_id=9,
            package_name="com.example.app",
            apk_id=None,
            permission_profiles={"android.permission.INTERNET": {"is_runtime_dangerous": False}},
        )


def test_replace_for_run_batches_inserts(monkeypatch) -> None:
    from scytaledroid.Database.db_func.static_analysis import (
        static_permission_matrix as matrix_db,
    )
    from scytaledroid.Database.db_queries.static_analysis import (
        static_permission_matrix as queries,
    )

    captured: dict[str, object] = {}

    def _one(sql, params=None, **_kwargs):
        captured["delete"] = (sql, params)

    def _many(sql, rows, **_kwargs):
        captured["sql"] = sql
        captured["rows"] = list(rows)

    monkeypatch.setattr(matrix_db, "run_sql", _one)
    monkeypatch.setattr(matrix_db, "run_sql_many", _many)

    rows = [
        {key: None for key in queries.INSERT_ROW_KEYS}
        | {"run_id": 9, "permission_name": "android.permission.INTERNET"},
        {key: None for key in queries.INSERT_ROW_KEYS}
        | {"run_id": 9, "permission_name": "android.permission.CAMERA"},
    ]
    assert matrix_db.replace_for_run(9, rows) == 2
    assert captured["delete"][1] == (9,)
    assert captured["sql"] == queries.INSERT_ROWS_MANY
    assert len(captured["rows"]) == 2
    assert captured["rows"][0][queries.INSERT_ROW_KEYS.index("permission_name")] == (
        "android.permission.INTERNET"
    )
