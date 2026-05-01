from __future__ import annotations


def test_run_writers_ensure_app_version_heals_missing_sdk(monkeypatch):
    from scytaledroid.StaticAnalysis.cli.persistence import run_writers

    calls: list[tuple[str, tuple[object, ...] | None]] = []

    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.package_utils.normalize_package_name",
        lambda value, **_kwargs: value.lower(),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.reference_seed.ensure_default_reference_rows",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.publisher_rules.apply_publisher_mapping",
        lambda *_args, **_kwargs: None,
    )

    def fake_run_sql(sql, params=None, fetch=None, **kwargs):
        text = " ".join(str(sql).split()).lower()
        calls.append((text, params))
        if "select id, display_name from apps" in text:
            return (10, "Example")
        if "select id, min_sdk, target_sdk from app_versions" in text:
            return (99, None, None)
        if text.startswith("update app_versions"):
            return None
        raise AssertionError(f"unexpected SQL: {sql}")

    monkeypatch.setattr(run_writers.core_q, "run_sql", fake_run_sql)

    version_id = run_writers._ensure_app_version(
        package_for_run="Com.Example.App",
        display_name="Example",
        version_name="1.0",
        version_code=1,
        min_sdk=24,
        target_sdk=35,
    )

    assert version_id == 99
    update_calls = [params for sql, params in calls if sql.startswith("update app_versions")]
    assert update_calls == [(24, 35, 99)]


def test_ingest_get_or_create_version_heals_missing_sdk(monkeypatch):
    from scytaledroid.StaticAnalysis.persistence import ingest

    calls: list[tuple[str, tuple[object, ...] | None]] = []

    def fake_run_sql(sql, params=None, fetch=None, **kwargs):
        text = " ".join(str(sql).split()).lower()
        calls.append((text, params))
        if "select id, min_sdk, target_sdk from app_versions" in text:
            return (77, None, 35)
        if text.startswith("update app_versions"):
            return None
        raise AssertionError(f"unexpected SQL: {sql}")

    monkeypatch.setattr(ingest.core_q, "run_sql", fake_run_sql)

    version_id = ingest._get_or_create_version(
        10,
        version_name="1.0",
        version_code=1,
        min_sdk=24,
        target_sdk=35,
    )

    assert version_id == 77
    update_calls = [params for sql, params in calls if sql.startswith("update app_versions")]
    assert update_calls == [(24, 35, 77)]


def test_run_writers_ensure_app_version_reuses_existing_version_code_row(monkeypatch):
    from scytaledroid.StaticAnalysis.cli.persistence import run_writers

    calls: list[tuple[str, tuple[object, ...] | None]] = []

    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.package_utils.normalize_package_name",
        lambda value, **_kwargs: value.lower(),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.reference_seed.ensure_default_reference_rows",
        lambda: None,
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.publisher_rules.apply_publisher_mapping",
        lambda *_args, **_kwargs: None,
    )

    def fake_run_sql(sql, params=None, fetch=None, **kwargs):
        text = " ".join(str(sql).split()).lower()
        calls.append((text, params))
        if "select id, display_name from apps" in text:
            return (10, "Example")
        if "select id, min_sdk, target_sdk from app_versions" in text:
            return None
        if "select id, version_name, min_sdk, target_sdk from app_versions" in text:
            return (88, "314.11 - Stable", 24, 35)
        if text.startswith("update app_versions"):
            raise AssertionError("should not update richer existing row")
        if text.startswith("insert into app_versions"):
            raise AssertionError("should reuse existing version_code row")
        raise AssertionError(f"unexpected SQL: {sql}")

    monkeypatch.setattr(run_writers.core_q, "run_sql", fake_run_sql)

    version_id = run_writers._ensure_app_version(
        package_for_run="com.discord",
        display_name="Discord",
        version_name="314.11",
        version_code=314011,
        min_sdk=None,
        target_sdk=None,
    )

    assert version_id == 88


def test_ingest_get_or_create_version_reuses_existing_version_code_row(monkeypatch):
    from scytaledroid.StaticAnalysis.persistence import ingest

    calls: list[tuple[str, tuple[object, ...] | None]] = []

    def fake_run_sql(sql, params=None, fetch=None, **kwargs):
        text = " ".join(str(sql).split()).lower()
        calls.append((text, params))
        if "select id, min_sdk, target_sdk from app_versions" in text:
            return None
        if "select id, version_name, min_sdk, target_sdk from app_versions" in text:
            return (55, "Stable", 24, 35)
        if text.startswith("update app_versions"):
            raise AssertionError("should not update richer existing row")
        if text.startswith("insert into app_versions"):
            raise AssertionError("should reuse existing version_code row")
        raise AssertionError(f"unexpected SQL: {sql}")

    monkeypatch.setattr(ingest.core_q, "run_sql", fake_run_sql)

    version_id = ingest._get_or_create_version(
        10,
        version_name="Stable old label",
        version_code=314011,
        min_sdk=None,
        target_sdk=None,
    )

    assert version_id == 55
