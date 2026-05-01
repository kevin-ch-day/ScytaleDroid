from __future__ import annotations

from scytaledroid.StaticAnalysis.persistence import ingest


def _columns_sql(table: str) -> str:
    return f"SHOW COLUMNS FROM {table}"


def _insert_columns(sql: str) -> list[str]:
    prefix = sql.split("(", 1)[1]
    return [token.strip() for token in prefix.split(")", 1)[0].split(",")]


def test_create_provider_row_includes_package_fields_when_available(monkeypatch):
    ingest._TABLE_COLUMNS_CACHE.clear()
    calls: list[tuple[str, tuple[object, ...] | None]] = []

    def fake_run_sql(sql, params=None, **kwargs):
        calls.append((sql, params))
        if sql == _columns_sql("static_fileproviders"):
            return [
                ("run_id",),
                ("package_name",),
                ("session_stamp",),
                ("scope_label",),
                ("component_name",),
                ("provider_name",),
                ("authority",),
                ("authorities",),
                ("exported",),
                ("base_permission",),
                ("read_permission",),
                ("write_permission",),
                ("base_guard",),
                ("read_guard",),
                ("write_guard",),
                ("effective_guard",),
                ("grant_uri_permissions",),
                ("metrics",),
            ]
        if sql.startswith("INSERT INTO static_fileproviders"):
            return 77
        return None

    monkeypatch.setattr(ingest.core_q, "run_sql", fake_run_sql)

    provider_id = ingest._create_provider_row(
        7,
        {
            "name": "com.example.Provider",
            "authorities": ["com.example.provider"],
            "exported": True,
        },
        package_name="com.example.app",
        session_stamp="20260217",
        scope_label="All apps",
    )

    assert provider_id == 77
    insert_sql, insert_params = next(
        (sql, params) for sql, params in calls if sql.startswith("INSERT INTO static_fileproviders")
    )
    columns = _insert_columns(insert_sql)
    row = dict(zip(columns, insert_params or (), strict=False))
    assert row["package_name"] == "com.example.app"
    assert row["session_stamp"] == "20260217"
    assert row["scope_label"] == "All apps"


def test_create_provider_row_skips_insert_when_legacy_package_required_but_missing(monkeypatch):
    ingest._TABLE_COLUMNS_CACHE.clear()
    calls: list[str] = []

    def fake_run_sql(sql, params=None, **kwargs):
        calls.append(sql)
        if sql == _columns_sql("static_fileproviders"):
            return [("run_id",), ("component_name",), ("package_name",)]
        return None

    monkeypatch.setattr(ingest.core_q, "run_sql", fake_run_sql)

    provider_id = ingest._create_provider_row(
        9,
        {"name": "com.example.Provider", "authorities": ["com.example.provider"]},
        package_name=None,
        session_stamp="20260217",
        scope_label="All apps",
    )

    assert provider_id is None
    assert not any(sql.startswith("INSERT INTO static_fileproviders") for sql in calls)


def test_create_provider_acl_row_propagates_parent_package_fields(monkeypatch):
    ingest._TABLE_COLUMNS_CACHE.clear()
    ingest._PROVIDER_PARENT_CACHE.clear()
    ingest._PROVIDER_PARENT_CACHE[42] = {
        "authority": "com.example.provider",
        "provider_name": "com.example.Provider",
        "package_name": "com.example.app",
        "session_stamp": "20260217",
        "scope_label": "All apps",
        "exported": 1,
    }
    captured: dict[str, object] = {}

    def fake_run_sql(sql, params=None, **kwargs):
        if sql == _columns_sql("static_provider_acl"):
            return [
                ("provider_id",),
                ("package_name",),
                ("session_stamp",),
                ("scope_label",),
                ("authority",),
                ("provider_name",),
                ("path",),
                ("path_type",),
                ("read_perm",),
                ("write_perm",),
                ("base_perm",),
                ("exported",),
            ]
        if sql.startswith("INSERT INTO static_provider_acl"):
            captured["sql"] = sql
            captured["params"] = params
        return None

    monkeypatch.setattr(ingest.core_q, "run_sql", fake_run_sql)

    ingest._create_provider_acl_row(
        42,
        {"path": "/foo", "pathType": "prefix", "read_permission": "READ", "write_permission": "WRITE"},
    )

    columns = _insert_columns(captured["sql"])  # type: ignore[index]
    row = dict(zip(columns, captured["params"], strict=False))  # type: ignore[index]
    assert row["package_name"] == "com.example.app"
    assert row["authority"] == "com.example.provider"
    assert row["provider_name"] == "com.example.Provider"
