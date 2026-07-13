from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import RunInputs, derive_run_mode


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
