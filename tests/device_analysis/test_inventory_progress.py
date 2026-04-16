from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.inventory import progress
from scytaledroid.Utils.DisplayUtils import colors


def test_render_snapshot_block_uses_labeled_lines_and_compact_non_root_warning(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        progress,
        "_FALLBACK_WARNED_KEYS",
        set(),
    )
    monkeypatch.setattr(progress.colors, "colors_enabled", lambda: False)
    monkeypatch.setattr(
        progress,
        "INVENTORY_STALE_SECONDS",
        24 * 60 * 60,
    )

    meta = SimpleNamespace(
        captured_at=None,
        snapshot_id=26,
        package_count=546,
    )

    progress.render_snapshot_block(
        meta,
        mode="baseline",
        serial="ZY22JK89DR",
        allow_fallbacks=True,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Refresh Inventory" in out
    assert "Device       : ZY22JK89DR" in out
    assert "Previous snap: 26" in out
    assert "Inventory    : UNKNOWN" in out
    assert "Last sync    : unknown ago" in out
    assert "Packages     : —" in out
    assert "Mode         : baseline" in out
    assert "Non-root collection active" in out
    assert "Readable user-space APK paths only." in out
    assert "Harvest will be policy-filtered." in out
