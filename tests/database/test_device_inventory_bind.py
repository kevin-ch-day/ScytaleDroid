from __future__ import annotations

from scytaledroid.Database.db_func.harvest import device_inventory as di


def test_bind_package_resolves_category_id_from_name(monkeypatch) -> None:
    di._CATEGORY_ID_CACHE.clear()
    calls: list[tuple[object, object]] = []

    def fake_run_sql(sql, params=None, fetch=None):
        del sql, fetch
        calls.append(params)
        return (7,)

    monkeypatch.setattr(di, "run_sql", fake_run_sql)
    bound = di._bind_package(
        12,
        "ZY22JK89DR",
        {
            "package_name": "com.example.app",
            "category_name": "User",
            "apk_paths": ["/data/app/x/base.apk", "/data/app/x/split.apk"],
        },
    )

    assert bound is not None
    assert bound[7] == "User"
    assert bound[8] == 7
    assert bound[15] == 2
    assert bound[16] == 1
    assert calls == [("User",)]

    again = di._bind_package(
        12,
        "ZY22JK89DR",
        {
            "package_name": "com.example.other",
            "category_name": "User",
            "apk_paths": ["/data/app/y/base.apk"],
        },
    )
    assert again is not None
    assert again[8] == 7
    assert calls == [("User",)]


def test_bind_package_retries_category_lookup_after_miss(monkeypatch) -> None:
    di._CATEGORY_ID_CACHE.clear()
    responses = [None, (4,)]

    def fake_run_sql(sql, params=None, fetch=None):
        del sql, params, fetch
        return responses.pop(0)

    monkeypatch.setattr(di, "run_sql", fake_run_sql)
    missing = di._bind_package(
        1,
        "SER",
        {"package_name": "com.example.app", "category_name": "User", "apk_paths": ["/data/app/x/base.apk"]},
    )
    found = di._bind_package(
        1,
        "SER",
        {"package_name": "com.example.other", "category_name": "User", "apk_paths": ["/data/app/y/base.apk"]},
    )

    assert missing is not None
    assert missing[8] is None
    assert found is not None
    assert found[8] == 4



def test_bind_package_keeps_supplied_category_id(monkeypatch) -> None:
    di._CATEGORY_ID_CACHE.clear()

    def fail_run_sql(*args, **kwargs):
        raise AssertionError("category lookup should not run when category_id is present")

    monkeypatch.setattr(di, "run_sql", fail_run_sql)
    bound = di._bind_package(
        1,
        "SER",
        {
            "package_name": "com.example.app",
            "category_name": "User",
            "category_id": 3,
            "split_count": 1,
            "apk_paths": ["/data/app/x/base.apk"],
        },
    )

    assert bound is not None
    assert bound[8] == 3
    assert bound[15] == 1
    assert bound[16] == 0
