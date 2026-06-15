from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution.scan_identity_helpers import select_group_artifacts


def test_select_group_artifacts_moves_base_to_end_when_scanning_splits() -> None:
    base = SimpleNamespace(name="base", is_split_member=False)
    split_a = SimpleNamespace(name="split_a", is_split_member=True)
    split_b = SimpleNamespace(name="split_b", is_split_member=True)
    group = SimpleNamespace(
        artifacts=(base, split_a, split_b),
        base_artifact=base,
    )

    selected = select_group_artifacts(group, scan_splits=True)

    assert [artifact.name for artifact in selected] == ["split_a", "split_b", "base"]


def test_select_group_artifacts_base_only_mode_keeps_base_only() -> None:
    base = SimpleNamespace(name="base", is_split_member=False)
    split_a = SimpleNamespace(name="split_a", is_split_member=True)
    group = SimpleNamespace(
        artifacts=(base, split_a),
        base_artifact=base,
    )

    selected = select_group_artifacts(group, scan_splits=False)

    assert [artifact.name for artifact in selected] == ["base"]
