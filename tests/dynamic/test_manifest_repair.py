import json
from pathlib import Path


def test_backfill_dataset_block_from_legacy_operator(tmp_path: Path):
    from scytaledroid.DynamicAnalysis.tools.manifest_repair import backfill_dataset_block

    run_dir = tmp_path / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "dynamic_run_id": "run-1",
        "operator": {
            "tier": "dataset",
            "dataset_validity": {
                "valid_dataset_run": True,
                "invalid_reason_code": None,
                "min_pcap_bytes": 100000,
                "sampling_duration_seconds": 200,
                "short_run": 0,
                "no_traffic_observed": 0,
            },
        },
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = backfill_dataset_block(tmp_path, dry_run=False)
    assert result.scanned == 1
    assert result.repaired == 1

    repaired = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert "dataset" in repaired
    assert repaired["dataset"]["valid_dataset_run"] is True
    assert repaired["dataset"]["tier"] == "dataset"
    assert repaired["dataset"]["countable"] is True
    # Preserve legacy field.
    assert repaired["operator"]["dataset_validity"]["valid_dataset_run"] is True

