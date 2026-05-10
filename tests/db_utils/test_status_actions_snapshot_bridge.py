"""Schema snapshot bridge posture helper (no live DB)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.Database.db_utils.action_groups import status_actions as sa


def test_bridge_posture_snapshot_block_success(monkeypatch: pytest.MonkeyPatch) -> None:
    row = SimpleNamespace(
        table="android_permission_dict_aosp",
        posture="derived_review",
        owner="core",
        rationale="test",
        current_writers=("w",),
        current_readers=("r",),
    )
    monkeypatch.setattr(sa, "bridge_posture_summary", lambda: {"freeze_candidate": 1})
    monkeypatch.setattr(sa, "list_bridge_postures", lambda: [row])

    block, err = sa._bridge_posture_snapshot_block()

    assert err is None
    assert block["summary"] == {"freeze_candidate": 1}
    assert block["tables"] == [
        {
            "table": "android_permission_dict_aosp",
            "posture": "derived_review",
            "owner": "core",
            "rationale": "test",
            "current_writers": ["w"],
            "current_readers": ["r"],
        }
    ]


@pytest.mark.parametrize("failing_fn", ("summary", "list_rows"))
def test_bridge_posture_snapshot_block_failure_safe_defaults(
    monkeypatch: pytest.MonkeyPatch, failing_fn: str
) -> None:
    row = SimpleNamespace(
        table="t",
        posture="p",
        owner="o",
        rationale="r",
        current_writers=(),
        current_readers=(),
    )
    if failing_fn == "summary":
        monkeypatch.setattr(
            sa,
            "bridge_posture_summary",
            lambda: (_ for _ in ()).throw(RuntimeError("summary boom")),
        )
        monkeypatch.setattr(sa, "list_bridge_postures", lambda: [row])
    else:
        monkeypatch.setattr(sa, "bridge_posture_summary", lambda: {"a": 0})
        monkeypatch.setattr(
            sa,
            "list_bridge_postures",
            lambda: (_ for _ in ()).throw(OSError("list boom")),
        )

    block, err = sa._bridge_posture_snapshot_block()

    assert block == {"summary": {}, "tables": []}
    assert err is not None
    assert "boom" in err
