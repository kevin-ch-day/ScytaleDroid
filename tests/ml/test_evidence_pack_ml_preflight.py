from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import (
    RunInputs,
    derive_run_mode,
    load_run_inputs,
)


def _inputs(tmp_path: Path, run_profile: str) -> RunInputs:
    return RunInputs(
        run_id="run-1",
        run_dir=tmp_path / "run-1",
        manifest={},
        plan=None,
        summary=None,
        pcap_report=None,
        pcap_features=None,
        pcap_path=None,
        identity_key=None,
        package_name="com.example.app",
        run_profile=run_profile,
    )


def test_derive_run_mode_treats_interaction_profiles_as_interactive(tmp_path: Path) -> None:
    assert derive_run_mode(_inputs(tmp_path, "interaction_manual")) == ("interactive", "run_profile")
    assert derive_run_mode(_inputs(tmp_path, "interaction_scripted")) == ("interactive", "run_profile")


def test_derive_run_mode_keeps_baseline_and_unknown_profiles(tmp_path: Path) -> None:
    assert derive_run_mode(_inputs(tmp_path, "baseline_idle")) == ("baseline", "run_profile")
    assert derive_run_mode(_inputs(tmp_path, "freeform")) == ("unknown", "missing")


def test_load_run_inputs_does_not_follow_pcap_path_outside_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"pcap")
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "artifacts": [
                    {
                        "type": "pcapdroid_capture",
                        "relative_path": "../outside.pcap",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    inputs = load_run_inputs(run_dir)

    assert inputs is not None
    assert inputs.pcap_path is None


def test_load_run_inputs_rejects_manifest_run_id_mismatch(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "run_manifest.json").write_text(
        json.dumps({"dynamic_run_id": "run-2"}),
        encoding="utf-8",
    )

    assert load_run_inputs(run_dir) is None


def test_load_run_inputs_rejects_non_object_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "run_manifest.json").write_text("[]", encoding="utf-8")

    assert load_run_inputs(run_dir) is None


def test_load_run_inputs_keeps_legacy_directory_id_fallback(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "run_manifest.json").write_text("{}", encoding="utf-8")

    inputs = load_run_inputs(run_dir)

    assert inputs is not None
    assert inputs.run_id == "run-1"
