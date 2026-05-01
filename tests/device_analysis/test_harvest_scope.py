from __future__ import annotations

from scytaledroid.DeviceAnalysis.harvest import scope
from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow, ScopeSelection


def _row(package_name: str, label: str = "Example App") -> InventoryRow:
    return InventoryRow(
        raw={"package_name": package_name},
        package_name=package_name,
        app_label=label,
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/example/base.apk",
        profile_key=None,
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/example/base.apk"],
        split_count=1,
    )


def test_scope_profiles_auto_selects_single_active_profile(monkeypatch, capsys) -> None:
    from scytaledroid.DynamicAnalysis import profile_loader

    monkeypatch.setattr(
        profile_loader,
        "load_db_profiles",
        lambda: [
            {
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "display_name": "Research Dataset Alpha",
                "app_count": 1,
            }
        ],
    )
    monkeypatch.setattr(
        profile_loader,
        "load_profile_packages",
        lambda profile_key: {"com.example.alpha"} if profile_key == "RESEARCH_DATASET_ALPHA" else set(),
    )

    selection = scope._scope_profiles(
        [_row("com.example.alpha", "Alpha")],
        set(),
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    assert selection.label == "Research Dataset Alpha"
    assert selection.kind == "profile_scope"
    assert selection.metadata["scope_id"] == "profile::research_dataset_alpha"
    out = capsys.readouterr().out
    assert "Only one active profile is available" in out


def test_select_package_scope_menu_drops_paper_dataset_labels(monkeypatch) -> None:
    captured_rows: dict[str, list[list[object]]] = {}

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_render_scope_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scope,
        "_load_active_profile_scopes",
        lambda rows, device_serial: [
            {
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "display_name": "Research Dataset Alpha",
                "scope_id": "profile::research_dataset_alpha",
                "expected_packages": {"com.example.alpha"},
                "rows": list(rows),
            }
        ],
    )
    monkeypatch.setattr(
        scope,
        "_scope_profiles",
        lambda rows, allow, *, device_serial, is_rooted: ScopeSelection(
            label="Research Dataset Alpha",
            packages=list(rows),
            kind="profile_scope",
            metadata={"profile_scope": True},
        ),
    )
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda headers, rows, **kwargs: captured_rows.setdefault("rows", rows),
    )
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "1")
    monkeypatch.setattr(scope.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)

    selection = scope.select_package_scope(
        [_row("com.example.alpha", "Alpha")],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    labels = [str(row[1]) for row in captured_rows["rows"]]
    assert "App profile" in labels
    assert "Paper #2 Dataset" not in labels
    assert "Paper #3 Dataset" not in labels


def test_select_package_scope_menu_dedupes_profile_package_count(monkeypatch) -> None:
    captured_rows: dict[str, list[list[object]]] = {}
    alpha = _row("com.example.alpha", "Alpha")
    beta = _row("com.example.beta", "Beta")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_render_scope_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scope,
        "_load_active_profile_scopes",
        lambda rows, device_serial: [
            {
                "profile_key": "PROFILE_A",
                "display_name": "Profile A",
                "scope_id": "profile::a",
                "expected_packages": {"com.example.alpha", "com.example.beta"},
                "rows": [alpha, beta],
            },
            {
                "profile_key": "PROFILE_B",
                "display_name": "Profile B",
                "scope_id": "profile::b",
                "expected_packages": {"com.example.alpha"},
                "rows": [alpha],
            },
        ],
    )
    monkeypatch.setattr(
        scope,
        "_scope_profiles",
        lambda rows, allow, *, device_serial, is_rooted: ScopeSelection(
            label="Profile A",
            packages=list(rows),
            kind="profile_scope",
            metadata={"profile_scope": True},
        ),
    )
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda headers, rows, **kwargs: captured_rows.setdefault("rows", rows),
    )
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "1")
    monkeypatch.setattr(scope.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)

    selection = scope.select_package_scope(
        [alpha, beta],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    app_profile_row = next(row for row in captured_rows["rows"] if str(row[1]) == "App profile")
    assert app_profile_row[2] == 2
