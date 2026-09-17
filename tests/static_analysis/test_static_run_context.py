from __future__ import annotations

from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.core.run_context import build_static_run_context
from scytaledroid.StaticAnalysis.cli.core.run_specs import StaticRunSpec


def test_build_static_run_context_preserves_split_scan_policy() -> None:
    spec = StaticRunSpec(
        selection=ScopeSelection(scope="all", label="x", groups=()),
        params=RunParameters(profile="full", scope="all", scope_label="x", scan_splits=False),
        base_dir=Path("."),
    )

    ctx = build_static_run_context(spec)

    assert ctx.scan_splits_enabled is False
