from __future__ import annotations

from scytaledroid.Database.db_func.harvest import install_sets
from scytaledroid.Utils.install_set_identity import V1, V2, compute_artifact_set_hash


def _members() -> tuple[install_sets.InstallSetMember, ...]:
    return (
        install_sets.InstallSetMember(
            apk_id=2,
            role="split",
            split_name="split_config.xhdpi",
            sha256="c" * 64,
        ),
        install_sets.InstallSetMember(
            apk_id=1,
            role="base",
            split_name="base",
            sha256="b" * 64,
        ),
        install_sets.InstallSetMember(
            apk_id=3,
            role="split",
            split_name="split_config.arm64_v8a",
            sha256="a" * 64,
        ),
    )


def _record(members=None) -> install_sets.InstallSetRecord:
    return install_sets.InstallSetRecord(
        session_label="session-a",
        package_name="com.example",
        device_serial="SERIAL",
        snapshot_id=None,
        app_id=None,
        version_code="1",
        version_name="1.0",
        status="clean",
        generated_at_utc=None,
        receipt_root=None,
        members=members or _members(),
    )


def test_artifact_set_hash_v1_orders_base_then_splits_by_name() -> None:
    members = (
        install_sets.InstallSetMember(
            apk_id=2,
            role="split",
            split_name="split_config.xhdpi",
            sha256="c" * 64,
        ),
        install_sets.InstallSetMember(
            apk_id=1,
            role="base",
            split_name="base",
            sha256="b" * 64,
        ),
        install_sets.InstallSetMember(
            apk_id=3,
            role="split",
            split_name="split_config.arm64_v8a",
            sha256="a" * 64,
        ),
    )

    assert install_sets.artifact_set_hash_v1(members) == (
        "d1b2463f7903c7f311649dddf5e1a584423523334d2db6b409654494c9f9a549"
    )


def test_upsert_install_set_ignores_records_without_exactly_one_base(monkeypatch) -> None:
    def fail_ensure_tables() -> None:  # pragma: no cover - should not be called
        raise AssertionError("ensure_tables should not be called")

    monkeypatch.setattr(install_sets, "ensure_tables", fail_ensure_tables)
    record = _record(
        members=(
            install_sets.InstallSetMember(
                apk_id=2,
                role="split",
                split_name="split_config.xhdpi",
                sha256="c" * 64,
            ),
        )
    )

    assert install_sets.upsert_install_set(record) is None


def test_upsert_new_install_set_defaults_to_v2(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _run_sql(_sql, params=(), **kwargs):
        query_name = str(kwargs.get("query_name") or "")
        if "lookup_existing_identity" in query_name:
            return None
        if "lookup_app_version" in query_name:
            return {}
        if "upsert_session" in query_name:
            return 1
        if "upsert_set" in query_name:
            captured["set_params"] = params
            return 9
        return None

    monkeypatch.setattr(install_sets, "ensure_tables", lambda: None)
    monkeypatch.setattr(install_sets, "run_sql", _run_sql)

    apk_set_id = install_sets.upsert_install_set(_record())
    expected = compute_artifact_set_hash(_members(), version=V2)

    assert apk_set_id == 9
    assert captured["set_params"][7] == expected
    assert captured["set_params"][8] == V2


def test_upsert_install_set_reuses_stored_v1_identity(monkeypatch) -> None:
    captured: dict[str, object] = {}
    stored_v1 = compute_artifact_set_hash(_members(), version=V1)

    def _run_sql(_sql, params=(), **kwargs):
        query_name = str(kwargs.get("query_name") or "")
        if "lookup_existing_identity" in query_name:
            return {
                "apk_set_id": 843,
                "artifact_set_hash": stored_v1,
                "artifact_set_hash_version": V1,
            }
        if "lookup_app_version" in query_name:
            return {}
        if "upsert_session" in query_name:
            return 1
        if "upsert_set" in query_name:
            captured["set_params"] = params
            return 843
        return None

    monkeypatch.setattr(install_sets, "ensure_tables", lambda: None)
    monkeypatch.setattr(install_sets, "run_sql", _run_sql)

    apk_set_id = install_sets.upsert_install_set(_record())

    assert apk_set_id == 843
    assert captured["set_params"][7] == stored_v1
    assert captured["set_params"][8] == V1
    assert stored_v1 != compute_artifact_set_hash(_members(), version=V2)


def test_upsert_install_set_reuses_stored_v2_identity(monkeypatch) -> None:
    captured: dict[str, object] = {}
    stored_v2 = compute_artifact_set_hash(_members(), version=V2)

    def _run_sql(_sql, params=(), **kwargs):
        query_name = str(kwargs.get("query_name") or "")
        if "lookup_existing_identity" in query_name:
            return {
                "apk_set_id": 9001,
                "artifact_set_hash": stored_v2,
                "artifact_set_hash_version": V2,
            }
        if "lookup_app_version" in query_name:
            return {}
        if "upsert_session" in query_name:
            return 1
        if "upsert_set" in query_name:
            captured["set_params"] = params
            return 9001
        return None

    monkeypatch.setattr(install_sets, "ensure_tables", lambda: None)
    monkeypatch.setattr(install_sets, "run_sql", _run_sql)

    apk_set_id = install_sets.upsert_install_set(_record())

    assert apk_set_id == 9001
    assert captured["set_params"][7] == stored_v2
    assert captured["set_params"][8] == V2


def test_upsert_install_set_fills_missing_apk_id_from_sha256(monkeypatch) -> None:
    captured: dict[str, object] = {}
    lookups: list[tuple[str, tuple]] = []

    def _run_sql(_sql, params=(), **kwargs):
        query_name = str(kwargs.get("query_name") or "")
        if "lookup_apk_id_by_package" in query_name:
            lookups.append((query_name, tuple(params)))
            return (31400,)
        if "lookup_existing_identity" in query_name:
            return None
        if "lookup_app_version" in query_name:
            return {}
        if "upsert_session" in query_name:
            return 1
        if "upsert_set" in query_name:
            captured["set_params"] = params
            return 11
        if "upsert_member" in query_name:
            captured.setdefault("member_params", []).append(params)
            return None
        return None

    monkeypatch.setattr(install_sets, "ensure_tables", lambda: None)
    monkeypatch.setattr(install_sets, "run_sql", _run_sql)

    record = _record(
        members=(
            install_sets.InstallSetMember(
                apk_id=None,
                role="base",
                split_name="base",
                sha256="b" * 64,
            ),
        )
    )
    apk_set_id = install_sets.upsert_install_set(record)

    assert apk_set_id == 11
    assert lookups == [("harvest.install_sets.lookup_apk_id_by_package", ("b" * 64, "com.example"))]
    assert captured["set_params"][5] == 31400
    assert captured["member_params"][0][1] == 31400


def test_existing_apk_set_identity_sql_uses_ascii_hash_equality() -> None:
    from scytaledroid.Database.db_queries.harvest import install_sets as install_set_sql

    sql = install_set_sql.SELECT_EXISTING_APK_SET_IDENTITY
    assert "artifact_set_hash IN (%s, %s)" in sql
    assert "LOWER(TRIM(artifact_set_hash))" not in sql
