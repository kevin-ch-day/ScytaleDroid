import json


class _DummyValidation:
    # Mirror the real PlanValidationOutcome interface used by build_plan_validation_event().
    status = "FAIL"
    reasons = ["dummy"]
    warnings: list[str] = []
    mismatches: list[dict[str, str]] = []
    plan: dict[str, object] = {}
    db: dict[str, object] = {}
    source = "test"

    @property
    def is_pass(self) -> bool:
        return False


def test_engine_blocked_plan_validation_writes_manifest_dataset_block(tmp_path, monkeypatch) -> None:
    # Avoid DB schema version lookup variability.
    from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
    from scytaledroid.DynamicAnalysis.engine import DynamicAnalysisEngine

    # Keep host tools deterministic (not required for this test).
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.engine.collect_host_tools",
        lambda: {"tshark": {"path": "/usr/bin/tshark", "version": "x"}, "capinfos": {"path": "/usr/bin/capinfos", "version": "y"}},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.engine.db_diagnostics.get_schema_version",
        lambda: "0.0.0-test",
    )

    cfg = DynamicSessionConfig(
        package_name="com.example.app",
        duration_seconds=180,
        device_serial="SERIAL",
        tier="dataset",
        interactive=False,
        output_root=str(tmp_path / "evidence"),
        static_run_id=1,
    )
    engine = DynamicAnalysisEngine(cfg)
    run_id, evidence_path = engine._write_blocked_event(_DummyValidation())  # noqa: SLF001
    assert run_id
    assert evidence_path
    mf = tmp_path / "evidence" / run_id / "run_manifest.json"
    payload = json.loads(mf.read_text(encoding="utf-8"))
    assert isinstance(payload.get("dataset"), dict)
    assert payload["dataset"].get("tier") == "dataset"
    assert payload["dataset"].get("countable") is True
    assert payload["dataset"].get("valid_dataset_run") is False
    assert payload["dataset"].get("invalid_reason_code") in {"PCAP_PARSE_ERROR"}


def test_engine_blocked_missing_tools_writes_manifest_dataset_block(tmp_path, monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
    from scytaledroid.DynamicAnalysis.engine import DynamicAnalysisEngine

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.engine.collect_host_tools",
        lambda: {},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.engine.db_diagnostics.get_schema_version",
        lambda: "0.0.0-test",
    )

    cfg = DynamicSessionConfig(
        package_name="com.example.app",
        duration_seconds=180,
        device_serial="SERIAL",
        tier="dataset",
        interactive=False,
        output_root=str(tmp_path / "evidence"),
        static_run_id=1,
    )
    engine = DynamicAnalysisEngine(cfg)
    run_id, evidence_path = engine._write_blocked_tools_missing(plan_payload=None, missing_tools=["tshark"])  # noqa: SLF001
    assert run_id
    assert evidence_path
    mf = tmp_path / "evidence" / run_id / "run_manifest.json"
    payload = json.loads(mf.read_text(encoding="utf-8"))
    assert isinstance(payload.get("dataset"), dict)
    assert payload["dataset"].get("tier") == "dataset"
    assert payload["dataset"].get("countable") is True
    assert payload["dataset"].get("valid_dataset_run") is False
    assert payload["dataset"].get("invalid_reason_code") in {"MISSING_TOOLS_TSHARK", "MISSING_TOOLS_CAPINFOS"}
