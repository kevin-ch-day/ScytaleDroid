from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.environment import EnvironmentSnapshot
from scytaledroid.DynamicAnalysis.core.runner import run_dynamic_session
from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
from scytaledroid.DynamicAnalysis.core.target_manager import TargetSnapshot
from scytaledroid.DynamicAnalysis.scenarios import ScenarioResult


def test_run_dynamic_session_seals_failed_manifest_when_post_run_step_raises(
    monkeypatch, tmp_path: Path
) -> None:
    config = DynamicSessionConfig(
        package_name="com.whatsapp",
        duration_seconds=60,
        scenario_id="basic_usage",
        interactive=True,
        observer_ids=(),
        output_root=str(tmp_path / "dynamic"),
        run_profile="baseline_connected",
        interaction_level="minimal",
        tier="baseline",
    )

    started_at = datetime.now(UTC)
    ended_at = started_at + timedelta(seconds=5)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.build_operator_guidance",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.peek_next_run_protocol",
        lambda *_args, **_kwargs: {"run_profile": "baseline_connected"},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.EnvironmentManager.prepare",
        lambda self, _run_ctx: EnvironmentSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.EnvironmentManager.finalize",
        lambda self, _run_ctx: EnvironmentSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.TargetManager.prepare",
        lambda self, _run_ctx: TargetSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.TargetManager.finalize",
        lambda self, _run_ctx: TargetSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.ManualScenarioRunner.run",
        lambda self, _run_ctx, **_kwargs: ScenarioResult(
            started_at=started_at,
            ended_at=ended_at,
            notes="ok",
            interaction_level="idle",
            protocol={"interaction_protocol_version": 1},
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.DynamicRunOrchestrator._emit_marker",
        lambda self, _run_ctx, _label: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.write_pcap_report",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("report boom")),
    )

    result = run_dynamic_session(config, plan_payload={"package_name": "com.whatsapp"})

    assert result.status == "failed"
    assert result.dynamic_run_id
    assert result.evidence_path

    run_dir = Path(str(result.evidence_path))
    manifest_path = run_dir / "run_manifest.json"
    assert manifest_path.exists()
    assert not (run_dir / "notes" / ".scytaledroid_in_progress").exists()
    assert (run_dir / "notes" / "finalization_error.txt").exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["ended_at"]
    assert any(
        isinstance(entry, dict) and entry.get("type") == "finalization_error"
        for entry in manifest.get("artifacts") or []
    )
    assert any("Finalization error:" in str(note) for note in manifest.get("notes") or [])


def test_run_dynamic_session_applies_script_manual_override_to_manifest(
    monkeypatch, tmp_path: Path
) -> None:
    config = DynamicSessionConfig(
        package_name="com.whatsapp",
        duration_seconds=60,
        scenario_id="basic_usage",
        interactive=True,
        observer_ids=(),
        output_root=str(tmp_path / "dynamic"),
        run_profile="interaction_scripted",
        interaction_level="scripted",
        tier="baseline",
    )

    started_at = datetime.now(UTC)
    ended_at = started_at + timedelta(seconds=20)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.build_operator_guidance",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.peek_next_run_protocol",
        lambda *_args, **_kwargs: {"run_profile": "interaction_scripted"},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.EnvironmentManager.prepare",
        lambda self, _run_ctx: EnvironmentSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.EnvironmentManager.finalize",
        lambda self, _run_ctx: EnvironmentSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.TargetManager.prepare",
        lambda self, _run_ctx: TargetSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.TargetManager.finalize",
        lambda self, _run_ctx: TargetSnapshot(metadata={}, artifacts=[]),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.DynamicRunOrchestrator._emit_marker",
        lambda self, _run_ctx, _label: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.index_pcap_by_app",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.write_pcap_report",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.write_pcap_features",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.write_static_dynamic_overlap",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.orchestrator.ManualScenarioRunner.run",
        lambda self, _run_ctx, **_kwargs: ScenarioResult(
            started_at=started_at,
            ended_at=ended_at,
            notes="manual after script diverged",
            interaction_level="scripted",
            protocol={
                "interaction_protocol_version": 2,
                "script_exit_code": 0,
                "profile_override": "interaction_manual",
                "interaction_level_override": "manual",
                "script_manual_override": True,
                "script_manual_override_reason": "operator_continued_manual_after_script_diverged",
            },
        ),
    )

    result = run_dynamic_session(config, plan_payload={"package_name": "com.whatsapp"})

    assert result.status in {"success", "degraded"}
    run_dir = Path(str(result.evidence_path))
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["operator"]["run_profile"] == "interaction_manual"
    assert manifest["operator"]["interaction_level"] == "manual"
    assert manifest["operator"]["script_manual_override"] is True
    assert (
        manifest["operator"]["script_manual_override_reason"]
        == "operator_continued_manual_after_script_diverged"
    )
    assert manifest["target"]["run_intent"] == "interaction_manual"
