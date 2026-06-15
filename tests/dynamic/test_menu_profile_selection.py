from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis import menu


def test_select_profile_package_uses_operational_profiles_only(monkeypatch) -> None:
    captured_rows: dict[str, object] = {}

    monkeypatch.setattr(menu, "list_categories", lambda _groups: [])
    monkeypatch.setattr(
        menu,
        "load_operational_profiles",
        lambda: [
            {
                "profile_key": "NEWS",
                "display_name": "News",
                "app_count": 5,
            },
            {
                "profile_key": "BROWSER",
                "display_name": "Browser",
                "app_count": 2,
            },
        ],
    )
    monkeypatch.setattr(
        menu,
        "load_profile_packages",
        lambda profile_key: {
            "NEWS": {"com.example.news"},
            "BROWSER": {"com.example.browser"},
        }.get(profile_key, set()),
    )
    monkeypatch.setattr(
        menu.table_utils,
        "render_table",
        lambda _headers, rows, **_kwargs: captured_rows.setdefault("rows", rows),
    )
    monkeypatch.setattr(menu, "_choose_index", lambda _prompt, _count: None)

    result = menu._select_profile_package(
        (
            SimpleNamespace(package_name="com.example.news"),
            SimpleNamespace(package_name="com.example.browser"),
        )
    )

    assert result is None
    assert captured_rows["rows"] == [
        ["1", "Browser", "2", "0"],
        ["2", "News", "5", "0"],
    ]


def test_select_profile_package_selects_from_operational_profile(monkeypatch) -> None:
    groups = (
        SimpleNamespace(package_name="com.example.news"),
        SimpleNamespace(package_name="com.example.browser"),
    )

    monkeypatch.setattr(menu, "list_categories", lambda _groups: [])
    monkeypatch.setattr(
        menu,
        "load_operational_profiles",
        lambda: [
            {
                "profile_key": "NEWS",
                "display_name": "News",
                "app_count": 1,
            }
        ],
    )
    monkeypatch.setattr(
        menu,
        "load_profile_packages",
        lambda profile_key: {"com.example.news"} if profile_key == "NEWS" else set(),
    )
    monkeypatch.setattr(menu.table_utils, "render_table", lambda *_a, **_k: None)
    monkeypatch.setattr(menu, "_choose_index", lambda _prompt, _count: 0)
    monkeypatch.setattr(
        menu,
        "_select_package_from_groups",
        lambda scoped_groups, *, title: (
            "com.example.news"
            if title == "News apps" and [group.package_name for group in scoped_groups] == ["com.example.news"]
            else None
        ),
    )

    result = menu._select_profile_package(groups)

    assert result == ("com.example.news", "NEWS")
