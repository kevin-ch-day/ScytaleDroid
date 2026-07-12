from __future__ import annotations

from scytaledroid.DeviceAnalysis.harvest import scope
from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow, ScopeSelection


def _row(package_name: str, label: str = "Example App", *, primary_path: str = "/data/app/example/base.apk") -> InventoryRow:
    return InventoryRow(
        raw={"package_name": package_name},
        package_name=package_name,
        app_label=label,
        installer="com.android.vending",
        category=None,
        primary_path=primary_path,
        profile_key=None,
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=[primary_path],
        split_count=1,
    )


def test_scope_profiles_auto_selects_single_active_profile(monkeypatch, capsys) -> None:
    from scytaledroid.DynamicAnalysis import profile_loader

    monkeypatch.setattr(
        profile_loader,
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
        profile_loader,
        "load_profile_packages",
        lambda profile_key: {"com.example.alpha"} if profile_key == "NEWS" else set(),
    )

    selection = scope._scope_profiles(
        [_row("com.example.alpha", "Alpha")],
        set(),
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    assert selection.label == "News"
    assert selection.kind == "profile_scope"
    assert selection.metadata["scope_id"] == "profile::news"
    out = capsys.readouterr().out
    assert "Only one active profile is available" in out


def test_select_package_scope_menu_drops_paper_dataset_labels(monkeypatch) -> None:
    captured_rows: dict[str, list[list[object]]] = {}

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
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
    assert app_profile_row[2] == "2"  # Inventory = device inventory rows
    assert app_profile_row[3] == scope._DASH  # Pullable unknown until a profile is chosen
    assert app_profile_row[4] == scope._DASH


def test_select_package_scope_menu_uses_compact_headers(monkeypatch) -> None:
    captured: dict[str, object] = {}
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.terminal, "get_terminal_width", lambda **kwargs: 120)

    def _capture(headers, rows, **kwargs):
        captured["headers"] = headers
        captured["rows"] = rows

    monkeypatch.setattr(scope.table_utils, "render_table", _capture)
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "2")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    assert captured["headers"] == ["#", "Scope", "Inventory", "Pullable", "APKs", "Notes"]


def test_select_package_scope_menu_shortens_full_inventory_label(monkeypatch) -> None:
    captured_rows: dict[str, list[list[object]]] = {}
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda headers, rows, **kwargs: captured_rows.setdefault("rows", rows),
    )
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "4")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    labels = [str(row[1]) for row in captured_rows["rows"]]
    assert "Full inventory pullable" in labels
    assert "All pullable packages (full inventory)" not in labels
    assert selection.label == "All pullable packages (full inventory)"


def test_select_package_scope_full_inventory_handler_binds_metadata(monkeypatch) -> None:
    alpha = _row("com.example.alpha", "Alpha")
    beta = _row("com.example.beta", "Beta", primary_path="/system/app/Beta/base.apk")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "4")

    selection = scope.select_package_scope(
        [alpha, beta],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    assert selection.kind == "everything"
    assert selection.metadata["candidate_count"] == 2
    assert selection.metadata["selected_count"] == 2
    assert selection.metadata["pullable_count"] == 1
    assert selection.metadata["policy_blocked_inventory"] == 1
    assert selection.metadata["estimated_files"] == 1


def test_select_package_scope_menu_marks_default_scope_recommended(monkeypatch) -> None:
    captured_rows: dict[str, list[list[object]]] = {}
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda headers, rows, **kwargs: captured_rows.setdefault("rows", rows),
    )
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "2")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    default_row = next(row for row in captured_rows["rows"] if str(row[1]) == "Play & user apps")
    assert default_row[5] == "recommended"


def test_select_package_scope_layout_renders_summary_and_last_scope_block(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(
        scope,
        "_LAST_SCOPE",
        ScopeSelection(
            label="All pullable packages (full inventory)",
            packages=[alpha],
            kind="everything",
            metadata={"candidate_count": 578, "pullable_count": 152},
        ),
    )
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.terminal, "get_terminal_width", lambda **kwargs: 120)
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda headers, rows, **kwargs: captured.update({"headers": headers, "rows": rows}),
    )
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "R")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    out = capsys.readouterr().out
    assert selection is not None
    assert "Inventory snapshot" in out
    assert "Snapshot packages : 1" in out
    assert "Pullable packages : 1" in out
    assert "Policy-blocked    : 0" in out
    assert "Estimated APKs    : ~1" in out
    assert "Last scope" in out
    assert "R) Re-run last scope" in out
    assert "All pullable packages · full inventory · 578 inventory / 152 pullable" in out
    labels = [str(row[1]) for row in captured["rows"]]
    assert all(not label.startswith("Re-run last scope") for label in labels)


def test_select_package_scope_narrow_layout_uses_short_headers(monkeypatch) -> None:
    captured: dict[str, object] = {}
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.terminal, "get_terminal_width", lambda **kwargs: 80)
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda headers, rows, **kwargs: captured.update({"headers": headers, "rows": rows}),
    )
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "2")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    assert captured["headers"] == ["#", "Scope", "Inv", "Pull", "APKs", "Note"]
