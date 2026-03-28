from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import main as app_main
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import headless_run
from scytaledroid.StaticAnalysis.cli.flows import session_uniqueness
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


def _dummy_group():
    artifact = RepositoryArtifact(
        path=Path("/tmp/example.apk"),
        display_path="example.apk",
        metadata={
            "package_name": "com.example.app",
            "version_code": "42",
            "version_name": "1.0.0",
        },
    )
    return ArtifactGroup(
        group_key="com.example.app:1.0.0",
        package_name="com.example.app",
        version_display="1.0.0",
        session_stamp=None,
        capture_id="legacy-test",
        artifacts=(artifact,),
    )


def test_main_menu_renders_when_base_schema_unavailable(monkeypatch):
    rendered = []

    monkeypatch.setattr(app_main, "ensure_db_ready", lambda: None)
    monkeypatch.setattr(
        schema_gate,
        "check_base_schema",
        lambda: (False, "Database disabled.", "DB is optional."),
    )
    monkeypatch.setattr(app_main, "_print_tier1_status_banner", lambda: {})
    monkeypatch.setattr(app_main.menu_utils, "print_header", lambda *_a, **_k: None)
    monkeypatch.setattr(app_main.menu_utils, "render_menu", lambda spec: rendered.append(spec))
    monkeypatch.setattr(app_main.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    monkeypatch.setattr(app_main.status_messages, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(app_main.status_messages, "print_strip", lambda *_a, **_k: None)

    app_main.main_menu()

    assert rendered, "main menu should still render even when the base schema gate fails"


def test_static_menu_allows_dry_run_when_schema_gate_fails(monkeypatch):
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")
    dummy_group = _dummy_group()
    captured: dict[str, object] = {}
    choices = iter(["D", "0"])

    monkeypatch.setattr(schema_gate, "check_base_schema", lambda: (False, "Database disabled.", "DB is optional."))
    monkeypatch.setattr(
        schema_gate,
        "static_schema_gate",
        lambda: (False, "Static Analysis schema unavailable.", "offline"),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.repository.group_artifacts",
        lambda _base_dir: (dummy_group,),
    )
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 0)
    monkeypatch.setattr(
        menu_module.prompt_utils,
        "get_choice",
        lambda valid, default=None, prompt=None: next(choices),
    )
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        menu_module,
        "choose_scope",
        lambda groups: ScopeSelection(scope="app", label="Example", groups=(dummy_group,)),
    )
    monkeypatch.setattr(menu_module, "collect_view_options", lambda command: (False, False, False, False))
    monkeypatch.setattr(menu_module, "ask_run_controls", lambda: "run")
    monkeypatch.setattr(menu_module.menu_utils, "print_header", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.status_messages, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.core.run_specs.build_static_run_spec",
        lambda **kwargs: captured.setdefault("spec", kwargs),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_dispatch.execute_run_spec",
        lambda spec: captured.setdefault("executed", spec),
    )

    menu_module.static_analysis_menu()

    spec = captured.get("spec")
    assert spec is not None, "dry-run command should remain reachable even when persistence gates fail"
    assert spec["params"].dry_run is True


def test_headless_dry_run_skips_schema_gate_and_uniqueness(monkeypatch, tmp_path):
    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"apk")
    dummy_group = _dummy_group()
    captured: dict[str, object] = {}

    class _CoreQueries:
        @staticmethod
        def run_sql(*_args, **_kwargs):
            raise AssertionError("dry-run should not query session uniqueness")

    monkeypatch.setattr(
        headless_run.schema_gate,
        "static_schema_gate",
        lambda: (False, "Static Analysis schema unavailable.", "offline"),
    )
    monkeypatch.setattr(session_uniqueness, "core_q", _CoreQueries())
    monkeypatch.setattr(headless_run, "_artifact_group_from_path", lambda _path: dummy_group)
    monkeypatch.setattr(headless_run, "build_static_run_spec", lambda **kwargs: captured.setdefault("spec", kwargs))
    monkeypatch.setattr(headless_run, "execute_run_spec", lambda spec: captured.setdefault("executed", spec))

    result = headless_run.main(["--apk", str(apk_path), "--profile", "full", "--dry-run"])

    assert result == 0
    assert captured["spec"]["params"].dry_run is True
    assert captured["spec"]["params"].paper_grade_requested is False


def test_artifact_group_from_path_extracts_identity_without_sidecar(monkeypatch, tmp_path):
    apk_path = tmp_path / "upload.apk"
    apk_path.write_bytes(b"apk")

    class _DummyApk:
        @staticmethod
        def get_package():
            return "com.example.upload"

        @staticmethod
        def get_androidversion_code():
            return "88"

        @staticmethod
        def get_androidversion_name():
            return "8.8.0"

        @staticmethod
        def get_app_name():
            return "Example Upload"

    monkeypatch.setattr(headless_run, "_load_metadata", lambda _path: {})
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.resource_fallback.open_apk_with_fallback",
        lambda _path: SimpleNamespace(apk=_DummyApk(), fallback_meta=None),
    )

    group = headless_run._artifact_group_from_path(apk_path)

    assert group.package_name == "com.example.upload"
    assert group.version_display == "8.8.0"
