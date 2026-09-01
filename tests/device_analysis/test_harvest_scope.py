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


def test_select_package_scope_menu_uses_profile_without_paper_dataset_labels(monkeypatch, capsys) -> None:

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
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "2")
    monkeypatch.setattr(scope.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)

    selection = scope.select_package_scope(
        [_row("com.example.alpha", "Alpha")],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    out = capsys.readouterr().out
    assert "App profile — 1 profile" in out
    assert "Paper #2 Dataset" not in out
    assert "Paper #3 Dataset" not in out


def test_select_package_scope_menu_reports_profile_count(monkeypatch, capsys) -> None:
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
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "2")
    monkeypatch.setattr(scope.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)

    selection = scope.select_package_scope(
        [alpha, beta],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    assert "App profile — 2 profiles" in capsys.readouterr().out


def test_select_package_scope_menu_makes_full_pull_the_default(monkeypatch, capsys) -> None:
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "1")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    out = capsys.readouterr().out
    assert "Most common action" in out
    assert "1) Pull all available APKs [recommended]" in out
    assert "Pull a smaller collection" in out


def test_select_package_scope_menu_labels_full_pull_clearly(monkeypatch, capsys) -> None:
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "1")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    out = capsys.readouterr().out
    assert "Pull all available APKs" in out
    assert "All pullable packages (full inventory)" not in out
    assert selection.label == "All pullable packages (full inventory)"


def test_select_package_scope_full_inventory_handler_binds_metadata(monkeypatch) -> None:
    alpha = _row("com.example.alpha", "Alpha")
    beta = _row("com.example.beta", "Beta", primary_path="/system/app/Beta/base.apk")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "1")

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


def test_select_package_scope_menu_describes_smaller_default_scope(monkeypatch, capsys) -> None:
    alpha = _row("com.example.alpha", "Alpha")

    monkeypatch.setattr(scope, "_LAST_SCOPE", None)
    monkeypatch.setattr(scope, "_load_active_profile_scopes", lambda rows, device_serial: [])
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "3")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    assert selection is not None
    assert "Play & user apps — 1 packages · ~1 APK files · smaller default scope" in capsys.readouterr().out


def test_select_package_scope_layout_renders_summary_and_last_scope_block(monkeypatch, capsys) -> None:
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
    monkeypatch.setattr(scope.prompt_utils, "get_choice", lambda *args, **kwargs: "R")

    selection = scope.select_package_scope(
        [alpha],
        device_serial="SERIAL123",
        is_rooted=False,
    )

    out = capsys.readouterr().out
    assert selection is not None
    assert "Available on this device" in out
    assert "1 package(s) · ~1 APK file(s), including splits" in out
    assert "Last scope" in out
    assert "R) Re-run last scope" in out
    assert "All pullable packages · full inventory · 578 inventory / 152 pullable" in out
