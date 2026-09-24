from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from scytaledroid.DynamicAnalysis.controllers import capture_run as flow
from scytaledroid.DynamicAnalysis.core.session import DynamicSessionResult
from scytaledroid.DynamicAnalysis.menus import capture_summary as summary
from scytaledroid.DynamicAnalysis.services import capture_target as target
from scytaledroid.DynamicAnalysis.services.application_resolution import (
    Application,
    find_applications,
    merge_applications,
)
from scytaledroid.Utils.install_set_identity import compute_artifact_set_hash

PKG = "com.zhiliaoapp.musically"
BASE, SPLIT = "a" * 64, "b" * 64


@pytest.fixture
def build():
    return target.InstalledBuild(
        PKG, "123", "1.2", (("/data/app/x/base.apk", BASE), ("/data/app/x/split_a.apk", SPLIT))
    )


@pytest.fixture
def members():
    return [
        {"role": "base", "split_name": "base", "sha256": BASE},
        {"role": "split", "split_name": "a", "sha256": SPLIT},
    ]


@pytest.fixture
def selection(members):
    return {
        "package_name": PKG,
        "version_code": "123",
        "version_name": "1.2",
        "base_apk_sha256": BASE,
        "artifact_set_hash_version": "v2",
        "artifact_set_hash": compute_artifact_set_hash(members, version="v2"),
        "static_run_id": 42,
        "plan_path": "/fake/plan.json",
    }


@pytest.mark.parametrize("query", ["TikTok", "tiktok", PKG])
def test_exact_resolution(query):
    apps = merge_applications({PKG}, {PKG: "TikTok"}, {PKG: "TikTok"})
    matches = find_applications(query, apps)
    assert len(matches.applications) == 1 and not matches.fuzzy
    assert matches.applications[0].installed and matches.applications[0].harvested


def test_fuzzy_and_unmatched_resolution():
    apps = merge_applications({PKG}, {PKG: "TikTok"}, {})
    assert find_applications("Tictok", apps).fuzzy
    assert find_applications("not.a.real.package", apps).applications == ()
    assert not find_applications("zz", apps).applications


def test_installed_harvest_alias_and_ambiguous_labels():
    apps = merge_applications(
        {PKG, "org.installed.only"},
        {"org.one.app": "Shared", "org.two.app": "Shared"},
        {"org.harvest.only": "Harvested"},
    )
    assert len(find_applications("Shared", apps).applications) == 2
    assert find_applications("Harvested", apps).applications[0].harvested
    assert find_applications("org.installed.only", apps).applications[0].installed
    assert find_applications("TikTok", apps).applications[0].package == PKG


def test_fuzzy_must_be_confirmed(monkeypatch):
    inputs = iter(["Tictok", ""])
    monkeypatch.setattr(flow.prompt_utils, "prompt_text", lambda *a, **k: next(inputs))
    confirmations = []
    monkeypatch.setattr(
        flow.prompt_utils, "prompt_yes_no", lambda *a, **k: confirmations.append(a[0]) or False
    )
    assert flow.choose_application([Application(PKG, "TikTok")]) is None
    assert confirmations == ["Use this app?"]


def test_ambiguous_selection_is_explicit(monkeypatch):
    inputs = iter(["Shared", "2"])
    monkeypatch.setattr(flow.prompt_utils, "prompt_text", lambda *a, **k: next(inputs))
    apps = [Application("org.one.app", "Shared"), Application("org.two.app", "Shared")]
    assert flow.choose_application(apps) == apps[1]


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_member_identity_requires_full_install_set(build, members, selection, version):
    selection = dict(
        selection,
        artifact_set_hash_version=version,
        artifact_set_hash=compute_artifact_set_hash(members, version=version),
    )
    assert target.members_match(build, selection, members)
    assert not target.members_match(replace(build, members=(build.members[0],)), selection, members)
    assert not target.members_match(
        replace(build, members=(build.members[0], ("/split.apk", "c" * 64))), selection, members
    )
    assert not target.members_match(build, dict(selection, artifact_set_hash_version=None), members)
    assert not target.members_match(build, dict(selection, artifact_set_hash="c" * 64), members)
    assert not target.members_match(build, dict(selection, version_code="124"), members)
    assert not target.members_match(build, dict(selection, package_name="org.other.app"), members)


def test_installed_build_hashes_every_member_and_scopes_version(monkeypatch, build):
    from scytaledroid.DeviceAnalysis.adb import package_manager as pm
    from scytaledroid.DeviceAnalysis.adb import shell

    calls = []
    monkeypatch.setattr(pm, "configured_user_id", lambda: "0")
    monkeypatch.setattr(
        pm,
        "read_supported_metadata_dump",
        lambda *a, **k: (
            SimpleNamespace(
                stdout=f"Package [{PKG}] (abc):\n versionCode=123 minSdk=24\n versionName=1.2\nPackage [org.other.app] (x):\n versionCode=999\n"
            ),
            [],
        ),
    )

    def run(serial, command, **kw):
        calls.append(command)
        if command[:2] == ["pm", "path"]:
            return "\n".join("package:" + p for p, h in build.members)
        return next(h for p, h in build.members if command[-1] == p) + "  " + command[-1]

    monkeypatch.setattr(shell, "run_shell", run)
    assert target.read_installed_build("test-device", PKG) == build
    assert len([c for c in calls if c[0] == "sha256sum"]) == 2
    assert ["pm", "path", "--user", "0", PKG] in calls


def test_installed_hash_failure_and_unrecognized_label_stop(monkeypatch):
    from scytaledroid.DeviceAnalysis.adb import package_manager as pm
    from scytaledroid.DeviceAnalysis.adb import shell

    monkeypatch.setattr(pm, "configured_user_id", lambda: "0")
    monkeypatch.setattr(
        pm,
        "read_supported_metadata_dump",
        lambda *a, **k: (
            SimpleNamespace(stdout=f"Package [{PKG}] (x):\n versionCode=123\n versionName=1.2\n"),
            [],
        ),
    )
    monkeypatch.setattr(
        shell,
        "run_shell",
        lambda s, c, **k: "package:/data/app/base.apk" if c[0] == "pm" else "unreadable",
    )
    with pytest.raises(target.TargetUnavailable, match="hash"):
        target.read_installed_build("test", PKG)
    with pytest.raises(target.TargetUnavailable, match="recognized"):
        target.read_installed_build("test", "Tictok")


def test_plan_selection_preserves_engine_validation(
    monkeypatch, tmp_path, build, members, selection
):
    from scytaledroid.Database.db_core import db_queries
    from scytaledroid.DynamicAnalysis import plan_selection
    from scytaledroid.DynamicAnalysis.plans import validation

    path = tmp_path / "plan.json"
    path.write_text("{}")
    selection = dict(selection, plan_path=str(path))
    monkeypatch.setattr(
        plan_selection, "load_plan_candidates", lambda p: ([{"generated_at": "2026"}], None)
    )
    monkeypatch.setattr(plan_selection, "_build_selection", lambda c: selection)
    queries = []
    monkeypatch.setattr(
        db_queries, "run_sql", lambda sql, params, **kw: queries.append((sql, params)) or members
    )
    monkeypatch.setattr(
        validation, "validate_dynamic_plan", lambda *a, **k: SimpleNamespace(status="PASS")
    )
    assert target.select_exact_plan(build) == selection
    assert "artifact_set_hash_version=%s" in queries[0][0]
    monkeypatch.setattr(
        validation, "validate_dynamic_plan", lambda *a, **k: SimpleNamespace(status="FAIL")
    )
    with pytest.raises(target.TargetUnavailable):
        target.select_exact_plan(build)


def _mock_flow(monkeypatch, build, selection, choices):
    calls = []
    monkeypatch.setattr(flow, "select_device", lambda: ("test", "Test Android"))
    monkeypatch.setattr(flow, "load_applications", lambda s: ([], []))
    monkeypatch.setattr(
        flow, "choose_application", lambda apps: Application(PKG, "TikTok", True, True)
    )
    monkeypatch.setattr(flow, "read_installed_build", lambda *a: build)
    monkeypatch.setattr(flow, "select_exact_plan", lambda b: selection)
    monkeypatch.setattr(flow, "exact_build_history", lambda *a: {"total": 0, "current": 0})
    monkeypatch.setattr(flow, "print_capture_summary", lambda *a: calls.append("summary"))
    monkeypatch.setattr(flow.prompt_utils, "prompt_yes_no", lambda *a, **k: True)
    monkeypatch.setattr(flow.prompt_utils, "prompt_text", lambda *a, **k: "")
    values = iter(choices)
    monkeypatch.setattr(flow.prompt_utils, "get_choice", lambda *a, **k: next(values))
    from scytaledroid.DynamicAnalysis import run_dynamic_analysis as runner

    def capture(package, **kw):
        calls.append(kw)
        proof = kw["final_operator_metadata_collector"](None)
        assert proof["capture_build_verification"]["end_matches_start"] is True
        return SimpleNamespace()

    monkeypatch.setattr(runner, "run_dynamic_analysis", capture)
    return calls


@pytest.mark.parametrize(
    "mode,profile", [("1", "interaction_manual"), ("2", "baseline_idle"), ("3", "baseline_idle")]
)
def test_default_capture_has_no_research_admission(monkeypatch, build, selection, mode, profile):
    calls = _mock_flow(monkeypatch, build, selection, [mode, "0"])
    flow.run_capture_app(
        select_observers=lambda *a, **k: ["system_log_capture"],
        guided_collection=lambda: pytest.fail("implicit research"),
        advanced_capture=lambda: pytest.fail("implicit advanced"),
        research_qualification=lambda: pytest.fail("implicit qualification"),
    )
    config = calls[0]
    assert config["tier"] == "exploration"
    assert config["run_profile"] == profile
    assert config["static_run_id"] == 42 and config["plan_path"] == selection["plan_path"]
    assert config["counts_toward_completion"] is False
    assert config["clear_logcat"] is False
    assert calls[1] == "summary"


def test_explicit_guided_collection_path(monkeypatch, build, selection):
    calls = _mock_flow(monkeypatch, build, selection, ["4"])
    flow.run_capture_app(
        select_observers=lambda *a, **k: pytest.fail("capture"),
        guided_collection=lambda: calls.append("guided"),
        advanced_capture=lambda: None,
        research_qualification=lambda: None,
    )
    assert calls == ["guided"]


def test_summary_does_not_treat_paper_rejection_as_capture_failure(
    monkeypatch, tmp_path, selection, capsys
):
    (tmp_path / "analysis/index/v1").mkdir(parents=True)
    manifest = {
        "sealed_at": "now",
        "dataset": {"valid_dataset_run": False, "invalid_reason_code": "QUOTA_NOT_SATISFIED"},
        "operator": {"capture_build_verification": {"end_matches_start": True}},
    }
    (tmp_path / "run_manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "analysis/pcap_report.json").write_text(
        json.dumps({"report_status": "ok", "capinfos": {"parsed": {"packet_count": 0}}})
    )
    (tmp_path / "analysis/index/v1/db_persistence_status.json").write_text(
        '{"attempted":true,"ok":true}'
    )
    monkeypatch.setattr(summary, "local_runs", lambda: [])
    monkeypatch.setattr(summary, "resolve_evidence_path", lambda path: tmp_path)
    result = DynamicSessionResult(
        PKG,
        240,
        datetime.now(UTC),
        status="success",
        dynamic_run_id="test",
        evidence_path=str(tmp_path),
    )
    summary.print_capture_summary(result, "TikTok", "interactive", selection)
    output = capsys.readouterr().out
    assert "DYNAMIC CAPTURE: SUCCESS" in output and "checks passed" in output
    assert "Packets: 0" in output and "Persistence: OK" in output
    assert "Research eligibility: not evaluated" in output and "QUOTA_NOT_SATISFIED" not in output
    assert json.loads((tmp_path / "run_manifest.json").read_text()) == manifest


def test_history_never_infers_unknown_versions(selection):
    identity = {
        k: selection[k]
        for k in (
            "version_code",
            "base_apk_sha256",
            "artifact_set_hash_version",
            "artifact_set_hash",
        )
    }
    good = {
        "target": {"package_name": PKG, "identity_start": identity},
        "operator": {"capture_behavior_intent": "interactive"},
    }
    legacy = {
        "target": {
            "package_name": PKG,
            "identity_start": dict(identity, artifact_set_hash_version=None),
        }
    }
    counts = summary.exact_build_history(PKG, selection, [(None, good), (None, legacy)])
    assert counts["total"] == 2 and counts["current"] == 1 and counts["interactive"] == 1


def test_landing_overview_does_not_query_research(monkeypatch, capsys):
    from scytaledroid.DynamicAnalysis.menus import menu_overview

    monkeypatch.setattr(
        menu_overview.device_manager, "describe_active_device", lambda: "Test Android"
    )
    monkeypatch.setattr(
        menu_overview, "_cached_overview_state", lambda *a: pytest.fail("research query")
    )
    menu_overview.render_dynamic_menu_overview()
    output = capsys.readouterr().out
    assert "Test Android" in output and "READY" not in output and "quota" not in output


def test_compact_queue_recommendation_is_optional(monkeypatch, capsys):
    from scytaledroid.DynamicAnalysis.menus import queue_selection as queue

    row = SimpleNamespace(
        package_name=PKG,
        display_name="TikTok",
        next_label="Idle",
        need_baseline=1,
        need_interactive=4,
    )
    prepared = SimpleNamespace(
        evidence_summary={},
        row_models=[row],
        dataset_apps_total=1,
        dataset_pkgs={PKG},
        cfg=SimpleNamespace(),
        expected_runs=7,
        current_build_ready_count=0,
    )
    monkeypatch.setattr(queue, "_next_recommended_row", lambda rows: row)
    monkeypatch.setattr(
        queue, "_render_compact_queue_table", lambda *a, **k: pytest.fail("automatic table")
    )
    monkeypatch.setattr(queue.prompt_utils, "prompt_text", lambda *a, **k: "r")
    assert (
        queue.run_package_selection_menu(prepared, summarize_evidence_quota_fn=lambda *a: {}) == PKG
    )
    assert "Missing: 1 baseline, 4 interactive" in capsys.readouterr().out
    monkeypatch.setattr(queue.prompt_utils, "prompt_text", lambda *a, **k: "b")
    assert (
        queue.run_package_selection_menu(prepared, summarize_evidence_quota_fn=lambda *a: {})
        is None
    )


@pytest.mark.parametrize("available", [False, True])
def test_engine_persistence_receipt_is_truthful_and_manifest_immutable(
    monkeypatch, tmp_path, available
):
    from contextlib import nullcontext

    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis import engine
    from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
    from scytaledroid.DynamicAnalysis.storage import persistence

    root = tmp_path / "evidence"
    run = root / "unit-run"
    run.mkdir(parents=True)
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", str(root))
    original = '{"dynamic_run_id":"unit-run","sealed_at":"now","target":{"package_name":"com.zhiliaoapp.musically"}}'
    (run / "run_manifest.json").write_text(original)
    result = DynamicSessionResult(
        PKG,
        240,
        datetime.now(UTC),
        status="success",
        dynamic_run_id="unit-run",
        evidence_path=str(run),
    )
    config = DynamicSessionConfig(
        PKG,
        240,
        tier="exploration",
        static_run_id=42,
        require_dynamic_schema=False,
        counts_toward_completion=False,
    )
    monkeypatch.setattr(persistence.dynamic_schema, "ensure_all", lambda: available)
    writes = []
    monkeypatch.setattr(
        persistence,
        "database_session",
        lambda: nullcontext(SimpleNamespace(transaction=lambda: nullcontext())),
    )
    monkeypatch.setattr(persistence, "_insert_dynamic_session", lambda row: writes.append(row))
    monkeypatch.setattr(persistence, "_register_manifest_artifacts", lambda *a: None)
    monkeypatch.setattr(persistence, "_insert_dynamic_issues", lambda *a: None)
    monkeypatch.setattr(persistence, "_persist_telemetry", lambda *a, **k: None)
    monkeypatch.setattr(persistence, "_index_derived_dynamic_artifacts", lambda **k: None)
    monkeypatch.setattr(persistence, "_tracker_truth_for_run", lambda *a: None)
    monkeypatch.setattr(persistence, "_load_artifact_registry", lambda *a: [])
    monkeypatch.setattr(persistence.db_diagnostics, "get_schema_version", lambda: "test")
    identity = {
        "artifact_set_hash_version": "v2",
        "artifact_set_hash": SPLIT,
        "base_apk_sha256": BASE,
    }
    payload = {"plan": {"package_name": PKG, "static_run_id": 42, "run_identity": identity}}
    engine.DynamicAnalysisEngine(config)._persist_summary(result, payload)
    receipt = json.loads((run / "analysis/index/v1/db_persistence_status.json").read_text())
    assert receipt["attempted"] is True and receipt["ok"] is available
    assert (run / "run_manifest.json").read_text() == original
    if available:
        assert len(writes) == 1 and writes[0]["tier"] == "exploration"
        assert writes[0]["artifact_set_hash_version"] == "v2"
        assert writes[0]["artifact_set_hash"] == SPLIT
        assert writes[0]["static_run_id"] == 42
    else:
        assert not writes and receipt["error_code"] == "DB_PERSISTENCE_DISABLED"


def test_capture_rechecks_build_after_confirmation(monkeypatch, build, selection, capsys):
    calls = _mock_flow(monkeypatch, build, selection, ["1"])
    reads = iter([build, replace(build, version_code="999")])
    monkeypatch.setattr(flow, "read_installed_build", lambda *a: next(reads))
    apps = iter([Application(PKG, "TikTok"), None])
    monkeypatch.setattr(flow, "choose_application", lambda apps_: next(apps))
    flow.run_capture_app(
        select_observers=lambda *a, **k: ["system_log_capture"],
        guided_collection=lambda: None,
        advanced_capture=lambda: None,
        research_qualification=lambda: None,
    )
    assert calls == []
    assert "changed after confirmation" in capsys.readouterr().out


def test_end_build_mismatch_never_claims_original_set_identity(monkeypatch, build, selection):
    proof = target.verification_record(build, selection)
    monkeypatch.setattr(flow, "read_installed_build", lambda *a: replace(build, version_code="999"))
    record = flow._final_metadata("test", build, selection, "interactive", proof, None)[
        "capture_build_verification"
    ]
    assert record["verified_at"] == proof["verified_at"]
    assert record["end_matches_start"] is False
    assert record["end"]["artifact_set_hash"] is None
    assert record["end"]["artifact_set_hash_version"] is None


def test_new_capture_does_not_update_research_tracker(monkeypatch, tmp_path):
    from scytaledroid.DynamicAnalysis.pcap import dataset_tracker

    # Non-research tier returns before quota/config/evidence operations.
    monkeypatch.setattr(
        dataset_tracker, "load_dataset_tracker", lambda: pytest.fail("research tracker read")
    )
    manifest = SimpleNamespace(operator={"tier": "exploration"})
    assert (
        dataset_tracker.update_dataset_tracker(manifest, tmp_path, config=SimpleNamespace()) is None
    )
    assert list(tmp_path.iterdir()) == []


def test_catalog_loader_combines_sources_without_cohort_filter(monkeypatch):
    from scytaledroid.Database.db_core import db_queries
    from scytaledroid.DeviceAnalysis import package_inventory
    from scytaledroid.DynamicAnalysis.services import application_resolution as resolver
    from scytaledroid.StaticAnalysis.core import repository

    monkeypatch.setattr(
        package_inventory, "list_packages", lambda serial: [PKG, "org.installed.only"]
    )
    monkeypatch.setattr(
        db_queries, "run_sql", lambda *a, **k: [{"package_name": PKG, "display_name": "TikTok"}]
    )
    monkeypatch.setattr(repository, "group_artifacts", lambda: [])
    monkeypatch.setattr(
        repository, "list_packages", lambda groups: [("org.harvest.only", "1.0", 1, "Harvested")]
    )
    apps, notes = resolver.load_applications("test")
    assert not notes
    assert {a.package for a in apps} == {PKG, "org.installed.only", "org.harvest.only"}
    assert find_applications("Harvested", apps).applications[0].harvested


def test_recent_runs_reject_escaping_paths_and_conflicting_manifest_ids(monkeypatch, tmp_path):
    from scytaledroid.Config import app_config

    root = tmp_path / "evidence"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "run_manifest.json").write_text('{"dynamic_run_id":"escape"}')
    (root / "escape").symlink_to(outside, target_is_directory=True)
    good = root / "good"
    good.mkdir()
    (good / "run_manifest.json").write_text('{"dynamic_run_id":"good","created_at":"2026"}')
    mismatch = root / "mismatch"
    mismatch.mkdir()
    (mismatch / "run_manifest.json").write_text('{"dynamic_run_id":"other"}')
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", str(root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    assert [m["dynamic_run_id"] for p, m in summary.local_runs()] == ["good"]


def test_menu_facade_connects_new_capture_and_explicit_research(monkeypatch):
    from scytaledroid.DynamicAnalysis.menus import dynamic_menu

    calls = []
    monkeypatch.setattr(flow, "run_capture_app", lambda **kw: calls.append(kw))
    monkeypatch.setattr(dynamic_menu, "_resolve_active_cohort_for_run", lambda: {"cohort": "test"})
    monkeypatch.setattr(dynamic_menu, "_run_guided_dataset_run", lambda ui: calls.append("guided"))
    dynamic_menu._run_focused_app_run(SimpleNamespace())
    assert len(calls) == 1
    calls[0]["guided_collection"]()
    assert calls[1] == "guided"
