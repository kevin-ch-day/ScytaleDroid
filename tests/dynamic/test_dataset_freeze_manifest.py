from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.freeze_contract import (
    build_freeze_contract_snapshot,
    freeze_contract_hash,
)
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_manifest import (
    FreezeConfig,
    _resolve_sampling_duration_seconds,
    build_dataset_freeze_manifest,
)


def test_build_dataset_freeze_manifest_reports_all_insufficient_apps(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    plan.write_text(
        json.dumps(
            {
                "apps": {
                    "com.example.one": {"runs": []},
                    "com.example.two": {"runs": []},
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError) as excinfo:
        build_dataset_freeze_manifest(
            dataset_plan_path=plan,
            evidence_root=evidence_root,
            cfg=FreezeConfig(baseline_required=1, interactive_required=2),
        )

    message = str(excinfo.value)
    assert message.startswith("FREEZE_INSUFFICIENT_ELIGIBLE_RUNS:2 app(s):")
    assert "com.example.one:baseline=0/1:interactive=0/2" in message
    assert "com.example.two:baseline=0/1:interactive=0/2" in message


def test_resolve_sampling_duration_falls_back_to_scenario_timestamps() -> None:
    manifest = {
        "started_at": "2026-07-09T18:41:47.075288+00:00",
        "ended_at": "2026-07-09T18:49:21.027244+00:00",
        "scenario": {
            "started_at": "2026-07-09T18:41:55.568347+00:00",
            "ended_at": "2026-07-09T18:49:03.953894+00:00",
        },
    }

    assert _resolve_sampling_duration_seconds(manifest, {}) == pytest.approx(428.385547)


def test_resolve_sampling_duration_prefers_dataset_value() -> None:
    manifest = {
        "scenario": {
            "started_at": "2026-07-09T18:41:55.568347+00:00",
            "ended_at": "2026-07-09T18:49:03.953894+00:00",
        }
    }

    assert _resolve_sampling_duration_seconds(manifest, {"sampling_duration_seconds": 240}) == 240.0


def test_build_dataset_freeze_manifest_allows_category_specific_baseline_hashes(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    packages = ("com.example.news", "com.example.social")
    plan.write_text(json.dumps({"apps": {pkg: {} for pkg in packages}}), encoding="utf-8")

    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())
    for index, package in enumerate(packages):
        _write_freeze_run_fixture(
            evidence_root,
            run_id=f"{package}.baseline",
            package=package,
            run_profile="baseline_idle",
            baseline_hash=f"{index + 1:064x}",
            interaction_protocol_version=None,
            contract_hash=contract_hash,
        )
        for interactive_index in range(2):
            _write_freeze_run_fixture(
                evidence_root,
                run_id=f"{package}.interactive.{interactive_index}",
                package=package,
                run_profile="interaction_manual",
                baseline_hash=None,
                interaction_protocol_version=2,
                contract_hash=contract_hash,
            )

    payload = build_dataset_freeze_manifest(
        dataset_plan_path=plan,
        evidence_root=evidence_root,
        cfg=FreezeConfig(baseline_required=1, interactive_required=2),
    )

    contracts = payload["selected_run_contracts"]
    assert contracts["baseline_protocol_versions"] == [2]
    assert contracts["baseline_protocol_hash_policy"] == "category_specific_hashes_allowed"
    assert contracts["baseline_protocol_hashes"] == [f"{1:064x}", f"{2:064x}"]


def test_build_dataset_freeze_manifest_includes_all_eligible_runs_above_minimum(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    package = "com.example.app"
    plan.write_text(json.dumps({"apps": {package: {}}}), encoding="utf-8")
    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())

    for index in range(2):
        _write_freeze_run_fixture(
            evidence_root,
            run_id=f"baseline-{index}",
            package=package,
            run_profile="baseline_idle",
            baseline_hash=f"{index + 1:064x}",
            interaction_protocol_version=None,
            contract_hash=contract_hash,
        )
    for index in range(3):
        _write_freeze_run_fixture(
            evidence_root,
            run_id=f"interactive-{index}",
            package=package,
            run_profile="interaction_manual",
            baseline_hash=None,
            interaction_protocol_version=2,
            contract_hash=contract_hash,
        )

    payload = build_dataset_freeze_manifest(
        dataset_plan_path=plan,
        evidence_root=evidence_root,
        cfg=FreezeConfig(baseline_required=1, interactive_required=2),
    )

    app = payload["apps"][package]
    assert len(app["baseline_run_ids"]) == 2
    assert len(app["interactive_run_ids"]) == 3
    assert len(app["included_run_ids"]) == 5
    assert len(payload["included_run_ids"]) == 5
    assert payload["quota_policy"]["extras_policy"] == (
        "extra runs from other build groups are retained in evidence but excluded from this ML freeze"
    )


def test_build_dataset_freeze_manifest_rejects_stale_pcap_report_hash(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    package = "com.example.app"
    plan.write_text(json.dumps({"apps": {package: {}}}), encoding="utf-8")
    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())
    _write_freeze_run_fixture(evidence_root, run_id="baseline", package=package, run_profile="baseline_idle", baseline_hash="1" * 64, interaction_protocol_version=None, contract_hash=contract_hash)
    for index in range(2):
        _write_freeze_run_fixture(evidence_root, run_id=f"interactive-{index}", package=package, run_profile="interaction_manual", baseline_hash=None, interaction_protocol_version=2, contract_hash=contract_hash)
    report = evidence_root / "baseline" / "analysis" / "pcap_report.json"
    report.write_text(json.dumps({"pcap_size_bytes": 60000, "pcap_sha256": "0" * 64}), encoding="utf-8")

    with pytest.raises(RuntimeError, match="FREEZE_PCAP_REPORT_HASH_MISMATCH:baseline"):
        build_dataset_freeze_manifest(dataset_plan_path=plan, evidence_root=evidence_root, cfg=FreezeConfig(baseline_required=1, interactive_required=2))


def test_build_dataset_freeze_manifest_rejects_non_scalar_pcap_report_size(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    package = "com.example.app"
    plan.write_text(json.dumps({"apps": {package: {}}}), encoding="utf-8")
    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())
    _write_freeze_run_fixture(evidence_root, run_id="baseline", package=package, run_profile="baseline_idle", baseline_hash="1" * 64, interaction_protocol_version=None, contract_hash=contract_hash)
    for index in range(2):
        _write_freeze_run_fixture(evidence_root, run_id=f"interactive-{index}", package=package, run_profile="interaction_manual", baseline_hash=None, interaction_protocol_version=2, contract_hash=contract_hash)
    report = evidence_root / "baseline" / "analysis" / "pcap_report.json"
    report.write_text(json.dumps({"pcap_size_bytes": []}), encoding="utf-8")

    with pytest.raises(RuntimeError, match="FREEZE_PCAP_REPORT_SIZE_INVALID:baseline"):
        build_dataset_freeze_manifest(dataset_plan_path=plan, evidence_root=evidence_root, cfg=FreezeConfig(baseline_required=1, interactive_required=2))


@pytest.mark.parametrize("reported_size", [True, -1, 60000.5])
def test_build_dataset_freeze_manifest_rejects_invalid_scalar_pcap_report_size(
    tmp_path: Path,
    reported_size: object,
) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    package = "com.example.app"
    plan.write_text(json.dumps({"apps": {package: {}}}), encoding="utf-8")
    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())
    _write_freeze_run_fixture(
        evidence_root,
        run_id="baseline",
        package=package,
        run_profile="baseline_idle",
        baseline_hash="1" * 64,
        interaction_protocol_version=None,
        contract_hash=contract_hash,
    )
    for index in range(2):
        _write_freeze_run_fixture(
            evidence_root,
            run_id=f"interactive-{index}",
            package=package,
            run_profile="interaction_manual",
            baseline_hash=None,
            interaction_protocol_version=2,
            contract_hash=contract_hash,
        )
    report = evidence_root / "baseline" / "analysis" / "pcap_report.json"
    report.write_text(json.dumps({"pcap_size_bytes": reported_size}), encoding="utf-8")

    with pytest.raises(RuntimeError, match="FREEZE_PCAP_REPORT_SIZE_INVALID:baseline"):
        build_dataset_freeze_manifest(
            dataset_plan_path=plan,
            evidence_root=evidence_root,
            cfg=FreezeConfig(baseline_required=1, interactive_required=2),
        )


def test_build_dataset_freeze_manifest_rejects_pcap_path_outside_run(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    package = "com.example.app"
    plan.write_text(json.dumps({"apps": {package: {}}}), encoding="utf-8")
    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())
    _write_freeze_run_fixture(
        evidence_root,
        run_id="baseline",
        package=package,
        run_profile="baseline_idle",
        baseline_hash="1" * 64,
        interaction_protocol_version=None,
        contract_hash=contract_hash,
    )
    for index in range(2):
        _write_freeze_run_fixture(
            evidence_root,
            run_id=f"interactive-{index}",
            package=package,
            run_profile="interaction_manual",
            baseline_hash=None,
            interaction_protocol_version=2,
            contract_hash=contract_hash,
        )
    manifest_path = evidence_root / "baseline" / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["relative_path"] = "../../outside.pcap"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "outside.pcap").write_bytes(b"outside")

    with pytest.raises(RuntimeError, match="FREEZE_UNSAFE_ARTIFACT_PATH:baseline"):
        build_dataset_freeze_manifest(
            dataset_plan_path=plan,
            evidence_root=evidence_root,
            cfg=FreezeConfig(baseline_required=1, interactive_required=2),
        )


def test_build_dataset_freeze_manifest_respects_max_age_window(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    package = "com.example.app"
    plan.write_text(json.dumps({"apps": {package: {}}}), encoding="utf-8")
    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())
    recent = datetime.now(UTC).replace(microsecond=0).isoformat()
    old = (datetime.now(UTC) - timedelta(days=30)).replace(microsecond=0).isoformat()

    _write_freeze_run_fixture(
        evidence_root,
        run_id="old-baseline",
        package=package,
        run_profile="baseline_idle",
        baseline_hash=f"{1:064x}",
        interaction_protocol_version=None,
        contract_hash=contract_hash,
        started_at=old,
    )
    _write_freeze_run_fixture(
        evidence_root,
        run_id="new-baseline",
        package=package,
        run_profile="baseline_idle",
        baseline_hash=f"{2:064x}",
        interaction_protocol_version=None,
        contract_hash=contract_hash,
        started_at=recent,
    )
    for index in range(2):
        _write_freeze_run_fixture(
            evidence_root,
            run_id=f"interactive-{index}",
            package=package,
            run_profile="interaction_manual",
            baseline_hash=None,
            interaction_protocol_version=2,
            contract_hash=contract_hash,
            started_at=recent,
        )

    payload = build_dataset_freeze_manifest(
        dataset_plan_path=plan,
        evidence_root=evidence_root,
        cfg=FreezeConfig(baseline_required=1, interactive_required=2, max_age_days=14),
    )

    app = payload["apps"][package]
    assert app["baseline_run_ids"] == ["new-baseline"]
    assert "old-baseline" not in payload["included_run_ids"]
    assert payload["quota_policy"]["max_age_days"] == 14
    assert payload["excluded_reason_counts_by_app"][package]["EXCLUDED_OUTSIDE_MAX_AGE_WINDOW"] == 1


def test_build_dataset_freeze_manifest_selects_newest_complete_build_group(tmp_path: Path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    package = "com.example.app"
    plan.write_text(json.dumps({"apps": {package: {}}}), encoding="utf-8")
    contract_hash = freeze_contract_hash(build_freeze_contract_snapshot())

    _write_freeze_run_fixture(
        evidence_root,
        run_id="new-baseline-only",
        package=package,
        run_profile="baseline_idle",
        baseline_hash=f"{1:064x}",
        interaction_protocol_version=None,
        contract_hash=contract_hash,
        version_code="200",
        base_apk_sha256="2" * 64,
        started_at="2026-07-13T00:00:00+00:00",
    )
    _write_freeze_run_fixture(
        evidence_root,
        run_id="old-baseline",
        package=package,
        run_profile="baseline_idle",
        baseline_hash=f"{2:064x}",
        interaction_protocol_version=None,
        contract_hash=contract_hash,
        version_code="100",
        base_apk_sha256="1" * 64,
        started_at="2026-07-12T00:00:00+00:00",
    )
    for index in range(2):
        _write_freeze_run_fixture(
            evidence_root,
            run_id=f"old-interactive-{index}",
            package=package,
            run_profile="interaction_manual",
            baseline_hash=None,
            interaction_protocol_version=2,
            contract_hash=contract_hash,
            version_code="100",
            base_apk_sha256="1" * 64,
            started_at="2026-07-12T00:00:00+00:00",
        )

    payload = build_dataset_freeze_manifest(
        dataset_plan_path=plan,
        evidence_root=evidence_root,
        cfg=FreezeConfig(baseline_required=1, interactive_required=2),
    )

    app = payload["apps"][package]
    assert app["selected_version_code"] == "100"
    assert app["selected_base_apk_sha256"] == "1" * 64
    assert app["baseline_run_ids"] == ["old-baseline"]
    assert app["interactive_run_ids"] == ["old-interactive-0", "old-interactive-1"]
    assert "new-baseline-only" not in payload["included_run_ids"]


def _write_freeze_run_fixture(
    evidence_root: Path,
    *,
    run_id: str,
    package: str,
    run_profile: str,
    baseline_hash: str | None,
    interaction_protocol_version: int | None,
    contract_hash: str,
    started_at: str = "2026-07-13T00:00:00+00:00",
    version_code: str = "100",
    base_apk_sha256: str = "a" * 64,
) -> None:
    run_dir = evidence_root / run_id
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir()
    (run_dir / "artifacts/pcapdroid_capture").mkdir(parents=True)
    pcap_path = run_dir / "artifacts/pcapdroid_capture/capture.pcap"
    pcap_path.write_bytes(b"pcap-fixture" * 5000)
    identity = {
        "package_name_lc": package,
        "version_code": version_code,
        "base_apk_sha256": base_apk_sha256,
        "artifact_set_hash": "b" * 64,
        "signer_set_hash": "c" * 64,
        "static_handoff_hash": "d" * 64,
    }
    manifest = {
        "started_at": started_at,
        "ended_at": _fixture_end_time(started_at),
        "scenario": {
            "started_at": started_at,
            "ended_at": _fixture_end_time(started_at),
        },
        "target": {
            "package_name": package,
            "version_code": version_code,
            "run_identity": identity,
        },
        "dataset": {
            "valid_dataset_run": True,
            "run_profile": run_profile,
            "window_count": 60,
            "pcap_size_bytes": pcap_path.stat().st_size,
            "sampling_duration_seconds": 300,
        },
        "operator": {
            "capture_policy_version": 1,
            "run_profile": run_profile,
            "baseline_protocol_id": "baseline_idle_v1" if baseline_hash else None,
            "baseline_protocol_version": 2 if baseline_hash else None,
            "baseline_protocol_hash": baseline_hash,
            "interaction_protocol_version": interaction_protocol_version,
            "paper_contract_version": "v1",
            "paper_contract_hash": contract_hash,
        },
        "artifacts": [
            {
                "type": "pcapdroid_capture",
                "relative_path": "artifacts/pcapdroid_capture/capture.pcap",
                "size_bytes": pcap_path.stat().st_size,
            }
        ],
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "inputs/static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "plan_schema_version": "fixture-v1",
                "paper_contract_version": 1,
                "package_name": package,
                "version_code": version_code,
                "run_identity": identity,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis/summary.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis/pcap_report.json").write_text(
        json.dumps({"pcap_size_bytes": pcap_path.stat().st_size}),
        encoding="utf-8",
    )
    (run_dir / "analysis/pcap_features.json").write_text("{}", encoding="utf-8")


def _fixture_end_time(started_at: str) -> str:
    raw = started_at
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    return (parsed + timedelta(minutes=5)).isoformat()
