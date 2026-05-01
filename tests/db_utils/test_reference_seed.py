def test_reference_seed_executes_inserts(monkeypatch):
    from scytaledroid.Database.db_utils import reference_seed

    calls = []

    def fake_run_sql(sql, params=None, **kwargs):
        calls.append((sql, params, kwargs.get("query_name")))
        return None

    monkeypatch.setattr(reference_seed, "run_sql", fake_run_sql)

    reference_seed.ensure_default_reference_rows()

    # We expect at least the publishers + profiles inserts to run.
    assert any("android_app_publishers" in sql for sql, _p, _q in calls)
    assert any("android_app_profiles" in sql for sql, _p, _q in calls)
    assert any("SET display_name" in sql for sql, _p, _q in calls)
