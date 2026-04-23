from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.storage import feature_backfill


def test_list_missing_feature_candidates_classifies_local_evidence(monkeypatch, tmp_path):
    run_dir = tmp_path / "run-1"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis" / "pcap_features.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        feature_backfill.core_q,
        "run_sql",
        lambda *_args, **_kwargs: [
            ("run-1", "com.example", str(run_dir), "dataset", "success", 1),
            ("run-2", "com.missing", str(tmp_path / "missing"), "dataset", "success", 1),
        ],
    )

    rows = feature_backfill.list_missing_feature_candidates()

    assert rows[0].dynamic_run_id == "run-1"
    assert rows[0].can_build is True
    assert rows[0].features_artifact_exists is True
    assert rows[1].dynamic_run_id == "run-2"
    assert rows[1].evidence_exists is False
    assert rows[1].can_build is False


def test_backfill_missing_dynamic_network_features_dry_run(monkeypatch, tmp_path):
    candidate = feature_backfill.FeatureBackfillCandidate(
        dynamic_run_id="run-1",
        package_name="com.example",
        evidence_path=Path(tmp_path),
        tier="dataset",
        status="success",
        countable=True,
        evidence_exists=True,
        manifest_exists=True,
        features_artifact_exists=True,
        report_artifact_exists=True,
    )
    monkeypatch.setattr(feature_backfill, "list_missing_feature_candidates", lambda limit=None: [candidate])
    monkeypatch.setattr(
        feature_backfill,
        "build_dynamic_network_features_row_from_evidence_pack",
        lambda _path: {"dynamic_run_id": "run-1", "low_signal": 1},
    )
    calls: list[dict] = []
    monkeypatch.setattr(feature_backfill, "upsert_dynamic_network_features_row", calls.append)

    result = feature_backfill.backfill_missing_dynamic_network_features(dry_run=True)

    assert result.scanned == 1
    assert result.buildable == 1
    assert result.upserted == 0
    assert result.low_signal_upserted == 1
    assert calls == []
