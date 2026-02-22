from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis import menu


def test_build_scoped_counts_ignore_legacy_runs() -> None:
    menu._RUN_IDENTITY_CACHE.clear()
    runs = [
        {
            "run_id": "r_old_b",
            "ended_at": "2026-02-20T10:00:00Z",
            "run_profile": "baseline_idle",
            "valid_dataset_run": True,
            "countable": True,
            "version_code": "100",
            "base_apk_sha256": "a" * 64,
        },
        {
            "run_id": "r_old_i1",
            "ended_at": "2026-02-20T10:10:00Z",
            "run_profile": "interactive_use",
            "valid_dataset_run": True,
            "countable": True,
            "version_code": "100",
            "base_apk_sha256": "a" * 64,
        },
        {
            "run_id": "r_old_i2",
            "ended_at": "2026-02-20T10:20:00Z",
            "run_profile": "interactive_use",
            "valid_dataset_run": True,
            "countable": True,
            "version_code": "100",
            "base_apk_sha256": "a" * 64,
        },
        {
            "run_id": "r_new_b",
            "ended_at": "2026-02-21T10:00:00Z",
            "run_profile": "baseline_idle",
            "valid_dataset_run": True,
            "countable": True,
            "version_code": "200",
            "base_apk_sha256": "b" * 64,
        },
    ]
    counts = menu._build_scoped_dataset_counts("com.example.app", runs)
    assert counts["baseline_countable"] == 1
    assert counts["interactive_countable"] == 0
    assert counts["legacy_valid"] == 3


def test_run_identity_fallback_reads_run_manifest(tmp_path, monkeypatch) -> None:
    menu._RUN_IDENTITY_CACHE.clear()
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path))
    run_id = "rid_1"
    manifest_path = tmp_path / "evidence" / "dynamic" / run_id / "run_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "package_name": "com.example.app",
                    "version_code": "300",
                    "run_identity": {
                        "version_code": "300",
                        "base_apk_sha256": "c" * 64,
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    run = {
        "run_id": run_id,
        "run_profile": "baseline_idle",
        "valid_dataset_run": True,
        "countable": True,
    }
    ident = menu._resolve_tracker_run_identity("com.example.app", run)
    assert ident == ("300", "c" * 64)


def test_build_scoped_counts_recompute_countable_within_active_build() -> None:
    menu._RUN_IDENTITY_CACHE.clear()
    runs = [
        {
            "run_id": "r_old_counted",
            "ended_at": "2026-02-20T10:00:00Z",
            "run_profile": "baseline_idle",
            "valid_dataset_run": True,
            "countable": True,
            "version_code": "100",
            "base_apk_sha256": "a" * 64,
        },
        {
            "run_id": "r_new",
            "ended_at": "2026-02-21T10:00:00Z",
            "run_profile": "baseline_idle",
            "valid_dataset_run": True,
            "countable": False,
            "version_code": "200",
            "base_apk_sha256": "b" * 64,
        },
    ]
    counts = menu._build_scoped_dataset_counts("com.example.app", runs)
    assert counts["baseline_countable"] == 1
    assert counts["baseline_extra"] == 0
    assert counts["legacy_valid"] == 1
