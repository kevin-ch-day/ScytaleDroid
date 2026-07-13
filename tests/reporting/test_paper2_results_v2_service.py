from __future__ import annotations

import csv
import math
from pathlib import Path

from scytaledroid.Reporting.services import paper2_results_v2_service as svc


def _write_scores(path: Path, values: list[bool]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["window_start_s", "window_end_s", "score", "threshold", "is_anomalous"])
        writer.writeheader()
        for idx, anomalous in enumerate(values):
            writer.writerow(
                {
                    "window_start_s": idx * 5,
                    "window_end_s": idx * 5 + 10,
                    "score": f"{0.1 + idx / 1000:.17g}",
                    "threshold": "0.5",
                    "is_anomalous": str(anomalous),
                }
            )


def test_read_score_metrics_uses_full_precision_window_flags(tmp_path: Path) -> None:
    path = tmp_path / "run" / "analysis" / "ml" / "v1" / "anomaly_scores_iforest.csv"
    _write_scores(path, [True, False, True, False, False])

    metrics = svc._read_score_metrics(path)

    assert metrics.windows == 5
    assert metrics.anomalous_windows == 2
    assert metrics.rdi == 0.4
    assert metrics.threshold == 0.5


def test_paired_stats_records_exact_two_sided_wilcoxon_details() -> None:
    deltas = [0.1 + i / 100 for i in range(15)]

    paired = svc._paired_stats(deltas)

    assert paired["n_pairs"] == 15
    assert paired["positive_differences"] == 15
    assert paired["zero_differences"] == 0
    assert paired["wilcoxon_alternative"] == "two-sided"
    assert paired["wilcoxon_method"] == "exact"
    assert paired["wilcoxon_zero_method"] == "wilcox"
    assert math.isclose(paired["wilcoxon_p_value_full_precision"], 0.00006103515625)
    assert math.isclose(paired["wilcoxon_greater_p_value_reference"], 0.000030517578125)
    assert paired["matched_pairs_rank_biserial"] == 1.0


def test_standard_duration_only_policy_filters_extended_runs() -> None:
    records = [
        svc.RunMetric(
            package_name="com.example",
            display_name="Example",
            category="Test",
            run_id="b1",
            phase="baseline",
            duration_s=300,
            duration_tier="standard",
            duration_tier_label="Standard",
            artifact_set_hash="a",
            base_apk_sha256="b",
            version_code="1",
            version_name="1.0",
            iforest=svc.ScoreMetrics(windows=10, anomalous_windows=1, rdi=0.1),
            ocsvm=svc.ScoreMetrics(windows=10, anomalous_windows=2, rdi=0.2),
            inclusion_reason="test",
            exclusion_reason="",
            run_profile="baseline_idle",
            interaction_level="minimal",
            static_run_id="1",
        ),
        svc.RunMetric(
            package_name="com.example",
            display_name="Example",
            category="Test",
            run_id="i1",
            phase="interactive",
            duration_s=300,
            duration_tier="standard",
            duration_tier_label="Standard",
            artifact_set_hash="a",
            base_apk_sha256="b",
            version_code="1",
            version_name="1.0",
            iforest=svc.ScoreMetrics(windows=10, anomalous_windows=9, rdi=0.9),
            ocsvm=svc.ScoreMetrics(windows=10, anomalous_windows=8, rdi=0.8),
            inclusion_reason="test",
            exclusion_reason="",
            run_profile="interaction_manual",
            interaction_level="manual",
            static_run_id="1",
        ),
        svc.RunMetric(
            package_name="com.example",
            display_name="Example",
            category="Test",
            run_id="i2",
            phase="interactive",
            duration_s=700,
            duration_tier="extended",
            duration_tier_label="Extended",
            artifact_set_hash="a",
            base_apk_sha256="b",
            version_code="1",
            version_name="1.0",
            iforest=svc.ScoreMetrics(windows=100, anomalous_windows=0, rdi=0.0),
            ocsvm=svc.ScoreMetrics(windows=100, anomalous_windows=0, rdi=0.0),
            inclusion_reason="test",
            exclusion_reason="",
            run_profile="interaction_manual",
            interaction_level="manual",
            static_run_id="1",
        ),
    ]

    pooled = svc._aggregate_app_phase_values(records, model="iforest", policy="pooled_window_weighted")
    standard = svc._aggregate_app_phase_values(records, model="iforest", policy="standard_duration_only")

    assert math.isclose(pooled["com.example"]["interactive_rdi"], 9 / 110)
    assert standard["com.example"]["interactive_rdi"] == 0.9


def test_hash_manifest_is_deterministic_and_relative(tmp_path: Path) -> None:
    output_root = tmp_path / "out"
    table = output_root / "paper2_statistics_v2.csv"
    table.parent.mkdir(parents=True)
    table.write_text("metric,value\nx,1\n", encoding="utf-8")

    manifest = svc._write_hash_manifest(
        output_root / "manifest" / "paper2_results_v2_manifest.json",
        [table],
        base_dir=output_root,
    )

    first = manifest.read_text(encoding="utf-8")
    second_path = svc._write_hash_manifest(manifest, [table], base_dir=output_root)
    second = second_path.read_text(encoding="utf-8")

    assert first == second
    assert "generated_at_utc" not in first
    assert '"path": "paper2_statistics_v2.csv"' in first
