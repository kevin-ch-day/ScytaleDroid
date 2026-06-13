from __future__ import annotations

from scytaledroid.DeviceAnalysis.apk import ui
from scytaledroid.Utils.DisplayUtils import colors


def test_describe_harvest_policy_mentions_product_partition_for_non_root() -> None:
    text = ui._describe_harvest_policy("non_root_paths", is_rooted=False)

    assert text == "non-root paths (system/product/vendor APK paths not harvested)"


def test_report_harvest_started_retains_non_root_policy_context(capsys) -> None:
    ui.report_harvest_started(
        selection_label="All pullable packages (full inventory)",
        candidate_count=578,
        selected_count=578,
        policy_eligible=152,
        scheduled=152,
        blocked_policy=426,
        blocked_scope=0,
        artifacts=571,
        policy="non_root_paths",
        harvest_mode="full_refresh",
        delta_filter_applied=False,
        is_rooted=False,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Harvest start: All pullable packages (full inventory) · pulling 152 packages · ~571 APK paths" in out
    assert "inventory snapshot=578" in out
    assert "pullable=152" in out
    assert "policy-blocked=426" in out
    assert "policy=non-root paths (system/product/vendor APK paths not harvested)" in out
    assert "harvest_mode=full_refresh" in out
    assert "delta=off" in out
