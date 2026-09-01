from __future__ import annotations

import json
import os
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml import menu as ml_menu
from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import dataset_level_table_names


def test_machine_learning_menu_exposes_freeze_operational_and_static_dynamic_workflows(monkeypatch) -> None:
    rendered: list[list[str]] = []

    monkeypatch.setattr(ml_menu, "_print_ml_status", lambda **_kwargs: None)

    def _capture_menu(items, **_kwargs):
        rendered.append([item.label for item in items])

    monkeypatch.setattr(ml_menu.menu_utils, "print_menu", _capture_menu)
    monkeypatch.setattr(ml_menu.prompt_utils, "menu_choice", lambda *_a, **_k: "0")

    ml_menu.machine_learning_menu()

    assert rendered == [
        [
            "Details and output paths",
            "Rebuild locked dataset anchor",
            "Refresh ML scoring",
            "Refresh locked dataset bundle",
            "QA audit",
        ],
        [
            "Run operational snapshot",
            "Runtime behavior report",
            "Static + dynamic score report",
            "Commands and output map",
        ]
    ]


def test_run_action_handles_system_exit_message(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ml_menu.prompt_utils, "press_enter_to_continue", lambda: None)

    def _raises_message():
        raise SystemExit("Missing freeze anchor")

    ml_menu._run_action(title="ML QA Audit", action=_raises_message)

    out = capsys.readouterr().out
    assert "ML QA Audit failed: Missing freeze anchor" in out


def test_display_freeze_anchor_uses_active_path_when_missing(monkeypatch, tmp_path) -> None:
    active = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    legacy = tmp_path / "archive" / "dataset_freeze.json"

    monkeypatch.setattr(ml_menu, "default_freeze_manifest_path", lambda: legacy)
    monkeypatch.setattr(ml_menu, "active_dataset_freeze_path", lambda: active)

    assert ml_menu._display_freeze_anchor_path() == active


def test_display_freeze_anchor_keeps_existing_resolved_path(monkeypatch, tmp_path) -> None:
    active = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    legacy = tmp_path / "archive" / "dataset_freeze.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(ml_menu, "default_freeze_manifest_path", lambda: legacy)
    monkeypatch.setattr(ml_menu, "active_dataset_freeze_path", lambda: active)

    assert ml_menu._display_freeze_anchor_path() == legacy


def test_plan_cohort_alignment_blocks_extra_package(monkeypatch, tmp_path) -> None:
    plan = tmp_path / "dataset_plan.json"
    plan.write_text(
        json.dumps(
            {
                "apps": {
                    "com.facebook.katana": {},
                    "com.espn.score_center": {},
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ml_menu, "active_research_cohort_packages", lambda: ("com.facebook.katana",))

    ok, message = ml_menu._plan_cohort_alignment(plan)

    assert ok is False
    assert "extra=1" in message
    assert "com.espn.score_center" in message


def test_freeze_build_status_reports_plan_cohort_blocker(monkeypatch, tmp_path) -> None:
    plan = tmp_path / "dataset_plan.json"
    evidence_root = tmp_path / "evidence"
    freeze = tmp_path / "dataset_freeze.json"
    evidence_root.mkdir()
    plan.write_text(json.dumps({"apps": {"com.espn.score_center": {}}}), encoding="utf-8")
    monkeypatch.setattr(ml_menu, "active_research_cohort_packages", lambda: ("com.facebook.katana",))

    status = ml_menu._freeze_build_status(freeze_path=freeze, plan_path=plan, evidence_root=evidence_root)

    assert status.startswith("blocked -")
    assert "extra=1" in status


def test_dataset_level_table_contract_includes_all_freeze_outputs() -> None:
    assert dataset_level_table_names() == (
        "anomaly_prevalence_per_app_phase.csv",
        "model_overlap_per_run.csv",
        "transport_mix_by_phase.csv",
        "ml_audit_per_app_model.csv",
        "dars_components_per_run.csv",
        "baseline_score_stability_per_app_model.csv",
        "static_dynamic_stratification_per_app.csv",
    )


def test_operational_snapshot_status_reports_latest(monkeypatch, tmp_path) -> None:
    root = tmp_path / "output"
    older = root / "operational" / "query-older"
    newer = root / "operational" / "query-newer"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    os.utime(older, (1_700_000_000, 1_700_000_000))
    os.utime(newer, (1_700_000_100, 1_700_000_100))

    monkeypatch.setattr(ml_menu.app_config, "OUTPUT_DIR", str(root))

    status = ml_menu._operational_snapshot_status()

    assert status.startswith("2 snapshot(s)")
    assert "query-newer" in status


def test_operational_snapshot_status_compact_reports_latest_name(monkeypatch, tmp_path) -> None:
    root = tmp_path / "output"
    older = root / "operational" / "query-older"
    newer = root / "operational" / "query-newer"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    os.utime(older, (1_700_000_000, 1_700_000_000))
    os.utime(newer, (1_700_000_100, 1_700_000_100))

    monkeypatch.setattr(ml_menu.app_config, "OUTPUT_DIR", str(root))

    assert ml_menu._operational_snapshot_status(compact=True) == "2 snapshot(s) · latest query-newer"


def test_table_counts_mark_outputs_stale_after_anchor_rebuild(tmp_path: Path) -> None:
    anchor = tmp_path / "dataset_freeze.json"
    anchor.write_text("{}", encoding="utf-8")
    table_dir = tmp_path / "tables"
    table_dir.mkdir()
    old = table_dir / "one.csv"
    old.write_text("a\n1\n", encoding="utf-8")
    fresh = table_dir / "two.csv"
    fresh.write_text("a\n2\n", encoding="utf-8")
    os.utime(old, (1_700_000_000, 1_700_000_000))
    os.utime(anchor, (1_700_000_100, 1_700_000_100))
    os.utime(fresh, (1_700_000_200, 1_700_000_200))

    assert ml_menu._dataset_table_counts(
        dataset_tables=table_dir,
        required_tables=("one.csv", "two.csv", "missing.csv"),
        anchor_path=anchor,
    ) == (1, 1)
    assert ml_menu._table_state_label(1, 3, 1) == "1/3 current · 1 stale"


def test_qa_status_distinguishes_secondary_model_caveats(tmp_path: Path) -> None:
    anchor = tmp_path / "dataset_freeze.json"
    anchor.write_text("{}", encoding="utf-8")
    qa = tmp_path / "ml_audit_report_v1.json"
    qa.write_text(
        json.dumps(
            {
                "errors": [],
                "warnings": ["BASELINE_AGGREGATE_EXCEEDANCE_OUT_OF_RANGE:pkg:one_class_svm"],
                "readiness": {
                    "status": "OK_WITH_SECONDARY_CAVEATS",
                    "primary_model_calibration": "OK",
                    "secondary_model_calibration": "WARN",
                },
            }
        ),
        encoding="utf-8",
    )
    os.utime(anchor, (1_700_000_000, 1_700_000_000))
    os.utime(qa, (1_700_000_100, 1_700_000_100))

    assert ml_menu._qa_status_label(qa, anchor_path=anchor) == (
        "ready - primary OK · secondary caveats (1 warning(s))"
    )


def test_recommended_next_step_points_to_bundle_after_current_qa(tmp_path: Path) -> None:
    freeze = tmp_path / "dataset_freeze.json"
    artifacts = tmp_path / "paper_artifacts.json"
    freeze.write_text("{}", encoding="utf-8")
    artifacts.write_text("{}", encoding="utf-8")

    assert ml_menu._recommended_next_step(
        {
            "freeze_path": freeze,
            "artifacts_path": artifacts,
            "existing_tables": 7,
            "required_tables": 7,
            "stale_tables": 0,
            "lockfile_state": "ready",
            "freeze_status": "ready - 15 apps · 112 runs · selected build groups",
            "qa_status": "ready - primary OK · secondary caveats (12 warning(s))",
            "bundle_status": "missing",
        }
    ) == "5) Refresh locked dataset bundle"


def test_recommended_next_step_reports_ready_after_current_bundle(tmp_path: Path) -> None:
    freeze = tmp_path / "dataset_freeze.json"
    artifacts = tmp_path / "paper_artifacts.json"
    freeze.write_text("{}", encoding="utf-8")
    artifacts.write_text("{}", encoding="utf-8")

    assert ml_menu._recommended_next_step(
        {
            "freeze_path": freeze,
            "artifacts_path": artifacts,
            "existing_tables": 7,
            "required_tables": 7,
            "stale_tables": 0,
            "lockfile_state": "ready",
            "freeze_status": "ready - 15 apps · 112 runs · selected build groups",
            "qa_status": "ready - primary OK · secondary caveats (12 warning(s))",
            "bundle_status": "ready - 8 table CSV(s) · 5 figure PNG(s)",
        }
    ) == "Ready for review"


def test_bundle_status_marks_stale_when_anchor_is_newer(tmp_path: Path) -> None:
    anchor = tmp_path / "dataset_freeze.json"
    artifacts = tmp_path / "paper_artifacts.json"
    bundle = tmp_path / "phase_e_artifacts_manifest.json"
    anchor.write_text("{}", encoding="utf-8")
    artifacts.write_text("{}", encoding="utf-8")
    bundle.write_text(
        json.dumps(
            {
                "files": {
                    "table_1_csv": {"path": "table_1.csv"},
                    "fig_b1_png": {"path": "fig_b1.png"},
                }
            }
        ),
        encoding="utf-8",
    )
    os.utime(bundle, (1_700_000_000, 1_700_000_000))
    os.utime(anchor, (1_700_000_100, 1_700_000_100))
    os.utime(artifacts, (1_700_000_000, 1_700_000_000))

    assert ml_menu._bundle_status_label(bundle, anchor_path=anchor, artifacts_path=artifacts) == (
        "stale - regenerate locked dataset bundle"
    )


def test_bundle_status_counts_tables_and_figures(tmp_path: Path) -> None:
    anchor = tmp_path / "dataset_freeze.json"
    artifacts = tmp_path / "paper_artifacts.json"
    bundle = tmp_path / "phase_e_artifacts_manifest.json"
    anchor.write_text("{}", encoding="utf-8")
    artifacts.write_text("{}", encoding="utf-8")
    bundle.write_text(
        json.dumps(
            {
                "files": {
                    "table_1_csv": {"path": "table_1.csv"},
                    "table_2_csv": {"path": "table_2.csv"},
                    "table_2_tex": {"path": "table_2.tex"},
                    "fig_b1_png": {"path": "fig_b1.png"},
                    "fig_b1_pdf": {"path": "fig_b1.pdf"},
                }
            }
        ),
        encoding="utf-8",
    )
    os.utime(anchor, (1_700_000_000, 1_700_000_000))
    os.utime(artifacts, (1_700_000_000, 1_700_000_000))
    os.utime(bundle, (1_700_000_100, 1_700_000_100))

    assert ml_menu._bundle_status_label(bundle, anchor_path=anchor, artifacts_path=artifacts) == (
        "ready - 2 table CSV(s) · 1 figure PNG(s)"
    )


def _write_duration_run(root: Path, run_id: str, duration_s: float) -> None:
    run_dir = root / run_id
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps({"dynamic_run_id": run_id, "target": {"package_name": "com.example"}}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {"sampling_duration_seconds": duration_s}}}),
        encoding="utf-8",
    )


def test_duration_tier_status_summarizes_locked_dataset_runs(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_duration_run(evidence, "standard-run", 240)
    _write_duration_run(evidence, "extended-run", 480)
    _write_duration_run(evidence, "long-run", 900)
    _write_duration_run(evidence, "soak-run", 1800)
    freeze = tmp_path / "dataset_freeze.json"
    freeze.write_text(
        json.dumps({"included_run_ids": ["standard-run", "extended-run", "long-run", "soak-run"]}),
        encoding="utf-8",
    )

    assert (
        ml_menu._duration_tier_status(freeze_path=freeze, evidence_root=evidence)
        == "Standard 1 · Extended 1 · Long observation 1 · Soak 1"
    )


def test_duration_tier_status_does_not_follow_unsafe_run_id(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_duration_run(tmp_path, "outside-run", 1800)
    freeze = tmp_path / "dataset_freeze.json"
    freeze.write_text(json.dumps({"included_run_ids": ["../outside-run"]}), encoding="utf-8")

    assert ml_menu._duration_tier_status(freeze_path=freeze, evidence_root=evidence) == "Unknown 1"


def test_freeze_status_summary_shortens_insufficient_runs_blocker() -> None:
    status = (
        "blocked - FREEZE_INSUFFICIENT_ELIGIBLE_RUNS:6 app(s):"
        "com.instagram.android:baseline=12/1:interactive=1/2;"
        "com.pinterest:baseline=11/1:interactive=0/2"
    )

    assert ml_menu._freeze_status_summary(status) == "blocked - insufficient eligible runs for 6 app(s)"
    assert ml_menu._freeze_status_details(status) == [
        "blocked - insufficient eligible runs for 6 app(s)",
        "Locked ML dataset requires 1 baseline + 2 interactive eligible run(s) per app in data/evidence/dynamic; extra eligible runs in the selected 14-day build group are included.",
        "- com.instagram.android: baseline=12/1:interactive=1/2",
        "- com.pinterest: baseline=11/1:interactive=0/2",
    ]


def test_machine_learning_menu_avoids_paper_numbered_operator_labels(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ml_menu, "_print_ml_status", lambda **_kwargs: None)
    monkeypatch.setattr(ml_menu.prompt_utils, "menu_choice", lambda *_a, **_k: "0")

    ml_menu.machine_learning_menu()

    out = capsys.readouterr().out
    assert "Paper 1" not in out
    assert "Paper 2" not in out
