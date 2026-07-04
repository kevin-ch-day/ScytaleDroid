from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.core.run_context import RunContext


def _ctx(tmp_path: Path) -> RunContext:
    run_dir = tmp_path / "run"
    return RunContext(
        dynamic_run_id="r1",
        package_name="com.facebook.katana",
        duration_seconds=1,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        device_serial="SERIAL",
    )
