"""Regression for the physical TikTok pre-capture manifest failure."""

import json
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.orchestrator import DynamicRunOrchestrator
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.core.runner import run_dynamic_session
from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    artifact_relative_path,
    resolve_contained_path,
)


def test_relative_writer_absolute_json_path(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    writer = EvidencePackWriter(Path("data/evidence/dynamic/run"))
    writer.ensure_layout()
    artifact = writer.write_json(
        "inputs/static_dynamic_plan.json", {"package_name": "com.zhiliaoapp.musically"}
    )
    assert artifact.is_absolute()
    # The exact expression that crashed on the physical device run.
    assert str(artifact.relative_to(writer.run_dir)) == "inputs/static_dynamic_plan.json"


def test_manifest_build_with_relative_root(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    writer = EvidencePackWriter(Path("data/evidence/dynamic/run"))
    writer.ensure_layout()
    engine = DynamicRunOrchestrator(
        DynamicSessionConfig("com.zhiliaoapp.musically", 240), observers=[]
    )
    ctx = RunContext(
        dynamic_run_id="run",
        package_name="com.zhiliaoapp.musically",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=writer.run_dir,
        artifacts_dir=writer.artifacts_dir,
        analysis_dir=writer.analysis_dir,
        notes_dir=writer.notes_dir,
        interactive=True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.collect_host_tools", lambda: {}
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.db_diagnostics.get_schema_version",
        lambda: "test",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.get_git_commit", lambda: "test"
    )
    manifest = engine._build_manifest(ctx, {"package_name": ctx.package_name}, writer)
    assert manifest.target["static_plan_path"] == "inputs/static_dynamic_plan.json"
    assert manifest.artifacts[0].relative_path == "inputs/static_dynamic_plan.json"


@pytest.mark.parametrize(
    "absolute_root,absolute_artifact", [(True, True), (False, True), (False, False), (True, False)]
)
def test_artifact_representations(monkeypatch, tmp_path, absolute_root, absolute_artifact):
    monkeypatch.chdir(tmp_path)
    root = Path("data/evidence/dynamic/run")
    artifact = root / "inputs/static_dynamic_plan.json"
    assert (
        artifact_relative_path(
            root.resolve() if absolute_root else root,
            artifact.resolve() if absolute_artifact else artifact,
        )
        == "inputs/static_dynamic_plan.json"
    )


@pytest.mark.parametrize(
    "path",
    [
        "outside.json",
        "run/../outside.json",
        "run/inputs/../../outside.json",
        "run/inputs/../inside.json",
    ],
)
def test_outside_and_any_parent_traversal_rejected(monkeypatch, tmp_path, path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        artifact_relative_path(Path("run"), Path(path))
    assert resolve_contained_path(Path("run"), "../outside.json") is None


def test_writer_rejects_traversal_and_symlink_escape(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    writer = EvidencePackWriter(Path("run"))
    writer.ensure_layout()
    outside = tmp_path / "outside"
    outside.mkdir()
    (writer.run_dir / "inputs").symlink_to(outside, target_is_directory=True)
    for path in ("inputs/static_dynamic_plan.json", "../outside/x.json", "notes/../x.json"):
        with pytest.raises(ValueError):
            writer.write_json(path, {})
    with pytest.raises(ValueError):
        artifact_relative_path(writer.run_dir, writer.run_dir / "inputs/static_dynamic_plan.json")
    assert not list(outside.iterdir())


def test_dep_snapshot_conversion_and_destination_containment(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    from scytaledroid.DynamicAnalysis.core.manifest import RunManifest

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.core_q.run_sql", lambda *a, **k: None
    )
    dep = Path("evidence/static_runs/7730/dep.json")
    dep.parent.mkdir(parents=True)
    dep.write_text("{}")
    writer = EvidencePackWriter(Path("data/evidence/dynamic/run"))
    writer.ensure_layout()
    config = DynamicSessionConfig("com.zhiliaoapp.musically", 240, static_run_id=7730)
    orch = DynamicRunOrchestrator(config, observers=[])
    from types import SimpleNamespace

    ctx = SimpleNamespace(static_run_id=7730, package_name=config.package_name)
    manifest = RunManifest(1, "run", "time")
    artifact = orch._attach_dep_snapshot(ctx, writer, manifest)
    assert artifact.relative_path == "artifacts/dep/dep.json"
    (writer.artifacts_dir / "dep/dep.json").unlink()
    (writer.artifacts_dir / "dep").rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (writer.artifacts_dir / "dep").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        orch._attach_dep_snapshot(ctx, writer, manifest)
    assert not (outside / "dep.json").exists()


@pytest.fixture
def startup_environment(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.ensure_legacy_dynamic_symlink",
        lambda *a: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.peek_next_run_protocol", lambda *a, **k: {}
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.build_operator_guidance", lambda *a, **k: []
    )

    def forbidden(*a, **k):
        raise AssertionError("Must not run during failed startup")

    for path in (
        "scytaledroid.DynamicAnalysis.core.orchestrator.EnvironmentManager.prepare",
        "scytaledroid.DynamicAnalysis.core.orchestrator.TargetManager.prepare",
        "scytaledroid.DynamicAnalysis.core.orchestrator.update_dataset_tracker",
        "scytaledroid.DynamicAnalysis.core.orchestrator.DynamicRunOrchestrator._start_observers",
        "scytaledroid.DynamicAnalysis.core.orchestrator.adb_shell.run_shell",
    ):
        monkeypatch.setattr(path, forbidden)
    return DynamicSessionConfig(
        "com.zhiliaoapp.musically",
        240,
        tier="dataset",
        counts_toward_completion=True,
        output_root="data/evidence/dynamic",
        run_profile="baseline_idle",
        observer_ids=("pcapdroid_capture", "system_log_capture"),
    )


@pytest.mark.parametrize("stage", ["layout", "manifest", "event_logger"])
def test_startup_failure_seals_controlled_result_without_capture_or_credit(
    monkeypatch, startup_environment, stage
):
    targets = {
        "layout": "scytaledroid.DynamicAnalysis.core.orchestrator.EvidencePackWriter.ensure_layout",
        "manifest": "scytaledroid.DynamicAnalysis.core.orchestrator.DynamicRunOrchestrator._build_manifest",
        "event_logger": "scytaledroid.DynamicAnalysis.core.orchestrator.RunEventLogger",
    }

    def fail(*a, **k):
        raise ValueError("injected initialization failure")

    if stage == "event_logger":
        from scytaledroid.DynamicAnalysis.core.manifest import RunManifest

        monkeypatch.setattr(
            DynamicRunOrchestrator,
            "_build_manifest",
            lambda self, ctx, *a: RunManifest(1, ctx.dynamic_run_id, "time"),
        )
    monkeypatch.setattr(targets[stage], fail)
    result = run_dynamic_session(
        startup_environment, plan_payload={"package_name": startup_environment.package_name}
    )
    assert result.status == "failed" and result.errors
    assert result.startup_failure["capture_started"] is False
    assert result.startup_failure["database_attempted"] is False
    run_dir = Path(result.evidence_path)
    payload = json.loads((run_dir / "run_manifest.json").read_text())
    assert payload["sealed_at"] and payload["status"] == "failed"
    assert payload["dataset"]["countable"] is False
    assert payload["dataset"]["valid_dataset_run"] is False
    assert payload["operator"]["counts_toward_completion"] is False
    assert payload["qa"]["startup_failure"]["capture_started"] is False
    assert payload["observers"] == []
    assert not (run_dir / "notes/.scytaledroid_in_progress").exists()
    from scytaledroid.DynamicAnalysis.menus.capture_summary import exact_build_history

    counts = exact_build_history(
        startup_environment.package_name,
        {"artifact_set_hash_version": "v1", "artifact_set_hash": "a" * 64},
        runs=[(run_dir, payload)],
    )
    assert counts["current"] == 0


def test_failed_seal_preserves_detectable_marker_even_with_live_pid(
    monkeypatch, startup_environment
):
    from scytaledroid.DynamicAnalysis.utils import run_cleanup

    def fail(*a, **k):
        raise OSError("seal unavailable")

    monkeypatch.setattr(DynamicRunOrchestrator, "_build_manifest", fail)
    monkeypatch.setattr(EvidencePackWriter, "write_manifest", fail)
    result = run_dynamic_session(
        startup_environment, plan_payload={"package_name": startup_environment.package_name}
    )
    run_dir = Path(result.evidence_path)
    marker = run_dir / "notes/.scytaledroid_in_progress"
    assert marker.exists() and json.loads(marker.read_text())["state"] == "startup_failed"
    assert not run_cleanup._active_in_progress_marker(marker)
    monkeypatch.setattr(run_cleanup, "iter_dynamic_run_dirs", lambda: (run_dir,))
    assert run_cleanup.find_incomplete_dynamic_run_dirs() == [run_dir]
    assert not (run_dir / "run_manifest.json").exists()
    assert result.startup_failure["recovery"].startswith("Available")


def test_unwritable_workspace_returns_failure(monkeypatch, startup_environment, tmp_path):
    from dataclasses import replace

    path = tmp_path / "file"
    path.write_text("not a directory")
    result = run_dynamic_session(
        replace(startup_environment, output_root=str(path)),
        plan_payload={"package_name": startup_environment.package_name},
    )
    assert result.status == "failed"
    assert result.startup_failure["recovery"].startswith("Failed")
    assert path.read_text() == "not a directory"


def test_engine_skips_database_and_probes_and_prints_startup_failure(
    monkeypatch, startup_environment, capsys
):
    from scytaledroid.DynamicAnalysis.engine import DynamicAnalysisEngine
    from scytaledroid.DynamicAnalysis.menus.capture_summary import print_capture_summary

    monkeypatch.setattr(
        DynamicAnalysisEngine,
        "_resolve_plan_payload",
        lambda self: ({"package_name": self.config.package_name}, None),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.engine.missing_required_tools", lambda **k: []
    )

    def fail(*a, **k):
        raise ValueError("manifest conversion failed")

    def forbidden(*a, **k):
        pytest.fail("Startup failure must skip probes and production persistence")

    monkeypatch.setattr(DynamicRunOrchestrator, "_build_manifest", fail)
    monkeypatch.setattr(DynamicAnalysisEngine, "_persist_summary", forbidden)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.engine.run_probe_set", forbidden)
    result = DynamicAnalysisEngine(startup_environment).run().session
    print_capture_summary(result, "TikTok", "idle", {})
    out = capsys.readouterr().out
    for text in (
        "Dynamic run could not start.",
        "Capture started: No",
        "Database persisted: No",
        "Not eligible; startup failed",
        "Not required; failed startup sealed",
    ):
        assert text in out
    assert "Traceback" not in out


def test_capture_first_menu_returns_safely_after_real_startup_failure(
    monkeypatch, startup_environment, capsys
):
    """Exercise the normal Idle controller through the actual failed engine result."""
    from scytaledroid.DynamicAnalysis.controllers import capture_run as flow
    from scytaledroid.DynamicAnalysis.engine import DynamicAnalysisEngine
    from scytaledroid.DynamicAnalysis.services.application_resolution import Application
    from scytaledroid.DynamicAnalysis.services.capture_target import InstalledBuild

    package = startup_environment.package_name
    build = InstalledBuild(package, "2024609030", "46.9.3", (("/data/app/base.apk", "a" * 64),))
    selection = {
        "package_name": package,
        "version_code": build.version_code,
        "version_name": build.version_name,
        "base_apk_sha256": build.base_sha256,
        "artifact_set_hash_version": "v1",
        "artifact_set_hash": "b" * 64,
        "static_run_id": 7730,
        "plan_path": "plan.json",
    }
    monkeypatch.setattr(flow, "select_device", lambda: ("test-serial", "Test Android"))
    monkeypatch.setattr(flow, "load_applications", lambda *a: ([], []))
    monkeypatch.setattr(
        flow, "choose_application", lambda *a: Application(package, "TikTok", True, True)
    )
    monkeypatch.setattr(flow, "read_installed_build", lambda *a: build)
    monkeypatch.setattr(flow, "select_exact_plan", lambda *a: selection)
    monkeypatch.setattr(flow.prompt_utils, "prompt_yes_no", lambda *a, **k: True)
    monkeypatch.setattr(flow.prompt_utils, "prompt_text", lambda *a, **k: "240")
    choices = iter(["2", "0"])
    monkeypatch.setattr(flow.prompt_utils, "get_choice", lambda *a, **k: next(choices))
    monkeypatch.setattr(
        DynamicAnalysisEngine,
        "_resolve_plan_payload",
        lambda self: ({"package_name": package}, None),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.engine.missing_required_tools", lambda **k: []
    )

    def fail(*a, **k):
        raise ValueError("faithful startup path failure")

    def forbidden(*a, **k):
        pytest.fail("Startup must not persist, probe, or enter research")

    monkeypatch.setattr(DynamicRunOrchestrator, "_build_manifest", fail)
    monkeypatch.setattr(DynamicAnalysisEngine, "_persist_summary", forbidden)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.engine.run_probe_set", forbidden)
    flow.run_capture_app(
        select_observers=lambda *a, **k: ["pcapdroid_capture", "system_log_capture"],
        guided_collection=forbidden,
        advanced_capture=forbidden,
        research_qualification=forbidden,
    )
    output = capsys.readouterr().out
    assert "Dynamic run could not start." in output
    assert "Run again" in output and "Another app" in output
    assert "Capture started: No" in output and "Traceback" not in output
