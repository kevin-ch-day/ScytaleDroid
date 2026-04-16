from collections import Counter

from scytaledroid.DeviceAnalysis.harvest.summary import HarvestRunMetrics, _build_summary_card_lines


def test_build_summary_card_lines_surfaces_executed_and_blocked_counts():
    metrics = HarvestRunMetrics(
        total_packages=546,
        blocked_packages=429,
        executed_packages=117,
        planned_artifacts=446,
        artifacts_written=117,
        artifacts_failed=0,
        artifact_status_counter=Counter({"written": 446}),
        packages_with_writes=117,
        packages_with_errors=0,
        packages_failed=0,
        packages_drifted=0,
        packages_with_mirror_failures=0,
        packages_skipped_runtime=0,
        runtime_skips=Counter(),
        runtime_notes=Counter(),
        preflight_skips=Counter({"policy_non_root": 411, "no_paths": 18}),
    )

    lines = _build_summary_card_lines(
        selection_label="Everything",
        pull_mode="inventory",
        metadata={"candidate_count": 546, "selected_count": 546},
        guard_brief=None,
        metrics=metrics,
        pull_errors=0,
    )

    assert any("Packages" in line and "546 total" in line and "117 executed" in line and "429 blocked" in line for line in lines)
    assert any("Results" in line and "clean" in line for line in lines)
