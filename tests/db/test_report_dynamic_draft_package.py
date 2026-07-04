from scripts.db import report_dynamic_draft_package as subject


def test_mode_from_profile_classifies_idle_and_interactive() -> None:
    assert subject._mode_from_profile("baseline_idle") == "idle"
    assert subject._mode_from_profile("baseline_connected") == "idle"
    assert subject._mode_from_profile("interaction_scripted") == "interactive"
    assert subject._mode_from_profile("interaction_manual") == "interactive"
    assert subject._mode_from_profile("something_else") == "unknown"


def test_interaction_label_classifies_run_type() -> None:
    assert subject._interaction_label("baseline_idle") == "baseline"
    assert subject._interaction_label("interaction_scripted") == "scripted"
    assert subject._interaction_label("interaction_manual") == "manual"
    assert subject._interaction_label("") == "unknown"


def test_window_scores_expected_only_for_profile_v3_scenarios() -> None:
    assert (
        subject._window_scores_expected_for_manifest({"scenario": {"id": "basic_usage"}}) is False
    )
    assert (
        subject._window_scores_expected_for_manifest({"scenario": {"id": "paper3_profile_v3"}})
        is True
    )
    assert (
        subject._window_scores_expected_for_manifest(
            {"scenario": {"id": "profile_v3_phase2_capture"}}
        )
        is True
    )


def test_evidence_governance_class_separates_countable_and_supplemental_modes() -> None:
    assert (
        subject._evidence_governance_class(
            valid_dataset_run=True,
            countable=True,
            low_signal=False,
            paper_eligible=True,
            cohort_eligibility="COUNTABLE",
        )
        == "COUNTABLE"
    )
    assert (
        subject._evidence_governance_class(
            valid_dataset_run=True,
            countable=False,
            low_signal=True,
            paper_eligible=True,
            cohort_eligibility="EXTRA",
        )
        == "SUPPLEMENTAL_LOW_SIGNAL"
    )
    assert (
        subject._evidence_governance_class(
            valid_dataset_run=True,
            countable=False,
            low_signal=False,
            paper_eligible=True,
            cohort_eligibility="EXTRA",
        )
        == "SUPPLEMENTAL_EXTRA"
    )
    assert (
        subject._evidence_governance_class(
            valid_dataset_run=True,
            countable=False,
            low_signal=False,
            paper_eligible=False,
            cohort_eligibility="EXCLUDED",
        )
        == "SUPPLEMENTAL_NONPAPER"
    )
    assert (
        subject._evidence_governance_class(
            valid_dataset_run=False,
            countable=False,
            low_signal=False,
            paper_eligible=False,
            cohort_eligibility="EXCLUDED",
        )
        == "INVALID_OR_EXCLUDED"
    )


def test_evidence_governance_class_from_db_prefers_normalized_quota_state() -> None:
    assert (
        subject._evidence_governance_class_from_db(
            quota_state="QUOTA_VALID",
            technical_validity_state="TECH_VALID",
            valid_dataset_run=True,
            countable=False,
            low_signal=False,
            paper_eligible=True,
            cohort_eligibility="COUNTABLE",
        )
        == "COUNTABLE"
    )
    assert (
        subject._evidence_governance_class_from_db(
            quota_state="SUPPLEMENTAL_VALID",
            technical_validity_state="TECH_VALID",
            valid_dataset_run=True,
            countable=True,
            low_signal=True,
            paper_eligible=True,
            cohort_eligibility="EXTRA",
        )
        == "SUPPLEMENTAL_LOW_SIGNAL"
    )
    assert (
        subject._evidence_governance_class_from_db(
            quota_state="QUOTA_INELIGIBLE",
            technical_validity_state="TECH_INVALID",
            valid_dataset_run=True,
            countable=True,
            low_signal=False,
            paper_eligible=False,
            cohort_eligibility="EXCLUDED",
        )
        == "INVALID_OR_EXCLUDED"
    )


def test_build_identity_key_prefers_version_code_then_sha_and_name() -> None:
    assert subject._build_identity_key(
        {"version_code": "312031000", "base_apk_sha256": "abc", "version_name": "12.3.1"}
    ) == (312031000, "abc", "12.3.1")
    assert subject._build_identity_key(
        {"version_code": None, "base_apk_sha256": "", "version_name": ""}
    ) == (-1, "", "")


def test_current_build_phase_status_uses_baseline_then_interactive_targets() -> None:
    assert subject._current_build_phase_status(baseline_countable=0, interactive_countable=0) == (
        "BASELINE_NEEDED",
        "baseline",
    )
    assert subject._current_build_phase_status(baseline_countable=3, interactive_countable=0) == (
        "INTERACTIVE_NEEDED",
        "interactive",
    )
    assert subject._current_build_phase_status(baseline_countable=3, interactive_countable=4) == (
        "COMPLETE",
        "—",
    )


def test_normalize_boolish_accepts_db_int_flags() -> None:
    assert subject._normalize_boolish(1) is True
    assert subject._normalize_boolish(0) is False
    assert subject._normalize_boolish("1") is True
    assert subject._normalize_boolish("0") is False
    assert subject._normalize_boolish(None) is None


def test_draft_bullets_mentions_missing_rdi_when_unavailable() -> None:
    summary = {
        "dynamic_runs_scanned": 26,
        "dynamic_sessions_in_db": 168,
        "valid_dataset_runs_scanned": 23,
        "countable_runs_scanned": 14,
        "apps_seen": 6,
        "runs_with_pcap": 24,
        "runs_with_pcap_report": 26,
        "runs_with_pcap_features": 26,
        "runs_with_window_scores_expected": 5,
        "runs_with_window_scores_available": 0,
        "runs_missing_window_scores_when_expected": 5,
        "valid_supplemental_runs_scanned": 4,
        "supplemental_low_signal_runs_scanned": 1,
        "supplemental_extra_runs_scanned": 3,
        "supplemental_nonpaper_runs_scanned": 0,
        "current_build_valid_runs_scanned": 18,
        "historical_valid_runs_scanned": 5,
        "packages_with_multiple_builds_in_corpus": 2,
        "apps_current_build_complete": 1,
        "apps_current_build_need_baseline": 3,
        "apps_current_build_need_interactive": 2,
        "active_cohort_label": "Research Dataset Beta",
        "active_cohort_app_count": 15,
        "active_cohort_apps_with_local_evidence": 9,
        "active_cohort_apps_complete": 2,
        "active_cohort_apps_need_baseline": 10,
        "active_cohort_apps_need_interactive": 3,
        "runs_with_domain_observations_db": 19,
        "runs_missing_domain_observations_db": 7,
        "runs_missing_domain_observations_invalid_pcap": 2,
        "runs_missing_domain_observations_invalid_pcap_by_raw_detail": {
            "PCAP_DEVICE_FILE_MISSING": 1,
            "PCAP_LOCAL_FILE_MISSING": 1,
        },
        "runs_missing_domain_observations_index_lag": 5,
        "proposed_domain_backfill_command": "PYTHONPATH=. python scripts/db/backfill_dynamic_domain_context.py --apply --json",
    }
    bullets = subject._draft_bullets(
        summary,
        [{"mode": "idle", "valid_dataset_run": 1, "domain_observations_in_db": 0}],
        {"current_rdi_available": False},
    )
    assert "Current X/Twitter RDI is not available" in bullets
    assert "backfill_dynamic_domain_context.py" in bullets
    assert "invalid PCAP evidence: 2" in bullets
    assert "possible DB index lag: 5" in bullets
    assert "PCAP_DEVICE_FILE_MISSING=1" in bullets
    assert "current evidence-backed runs still appear consistent with domain-index lag" in bullets
    assert (
        "Some runs that were expected to materialize per-run ML window scores are still missing those artifacts."
        in bullets
    )
    assert "Valid supplemental runs retained outside quota: 4." in bullets
    assert "Supplemental low-signal runs retained: 1." in bullets
    assert "Current-build valid runs in the local corpus: 18." in bullets
    assert "Packages with multiple build variants in the local corpus: 2." in bullets
    assert "Apps current-build complete by 3+4 phase targets: 1." in bullets
    assert "Active cohort: Research Dataset Beta (15 apps)." in bullets


def test_draft_bullets_call_out_zero_index_lag_when_remaining_rows_are_invalid_pcap() -> None:
    summary = {
        "dynamic_runs_scanned": 28,
        "dynamic_sessions_in_db": 170,
        "valid_dataset_runs_scanned": 25,
        "countable_runs_scanned": 21,
        "apps_seen": 6,
        "runs_with_pcap": 26,
        "runs_with_pcap_report": 28,
        "runs_with_pcap_features": 28,
        "runs_with_window_scores_expected": 0,
        "runs_with_window_scores_available": 0,
        "runs_missing_window_scores_when_expected": 0,
        "valid_supplemental_runs_scanned": 5,
        "supplemental_low_signal_runs_scanned": 2,
        "supplemental_extra_runs_scanned": 2,
        "supplemental_nonpaper_runs_scanned": 1,
        "current_build_valid_runs_scanned": 20,
        "historical_valid_runs_scanned": 5,
        "packages_with_multiple_builds_in_corpus": 2,
        "apps_current_build_complete": 1,
        "apps_current_build_need_baseline": 3,
        "apps_current_build_need_interactive": 2,
        "active_cohort_label": "Research Dataset Beta",
        "active_cohort_app_count": 15,
        "active_cohort_apps_with_local_evidence": 9,
        "active_cohort_apps_complete": 2,
        "active_cohort_apps_need_baseline": 10,
        "active_cohort_apps_need_interactive": 3,
        "runs_with_domain_observations_db": 26,
        "runs_missing_domain_observations_db": 2,
        "runs_missing_domain_observations_invalid_pcap": 2,
        "runs_missing_domain_observations_invalid_pcap_by_raw_detail": {
            "PCAP_DEVICE_FILE_MISSING": 1,
            "PCAP_LOCAL_FILE_MISSING": 1,
        },
        "runs_missing_domain_observations_index_lag": 0,
        "proposed_domain_backfill_command": "PYTHONPATH=. python scripts/db/backfill_dynamic_domain_context.py --apply --json",
    }
    bullets = subject._draft_bullets(
        summary,
        [{"mode": "idle", "valid_dataset_run": 1, "domain_observations_in_db": 1}],
        {"current_rdi_available": False},
    )
    assert (
        "No current evidence-backed runs are still classified as DB domain-index lag candidates."
        in bullets
    )
    assert (
        "Remaining missing `dynamic_domain_observations` rows are invalid-PCAP exclusions, not indexing debt."
        in bullets
    )
    assert "aligned for current valid evidence" in bullets
    assert "Current corpus is composed of `basic_usage` runs" in bullets


def test_draft_paragraphs_highlight_zero_index_lag_and_invalid_pcap_exclusions() -> None:
    summary = {
        "dynamic_runs_scanned": 28,
        "dynamic_sessions_in_db": 170,
        "valid_dataset_runs_scanned": 25,
        "countable_runs_scanned": 21,
        "apps_seen": 6,
        "runs_with_pcap_report": 28,
        "runs_with_pcap_features": 28,
        "runs_with_window_scores_expected": 0,
        "runs_with_window_scores_available": 0,
        "runs_missing_window_scores_when_expected": 0,
        "valid_supplemental_runs_scanned": 5,
        "supplemental_low_signal_runs_scanned": 2,
        "supplemental_extra_runs_scanned": 2,
        "supplemental_nonpaper_runs_scanned": 1,
        "current_build_valid_runs_scanned": 20,
        "historical_valid_runs_scanned": 5,
        "packages_with_multiple_builds_in_corpus": 2,
        "apps_current_build_complete": 1,
        "apps_current_build_need_baseline": 3,
        "apps_current_build_need_interactive": 2,
        "active_cohort_label": "Research Dataset Beta",
        "active_cohort_app_count": 15,
        "active_cohort_apps_with_local_evidence": 9,
        "active_cohort_apps_complete": 2,
        "active_cohort_apps_need_baseline": 10,
        "active_cohort_apps_need_interactive": 3,
        "runs_with_domain_observations_db": 26,
        "runs_missing_domain_observations_db": 2,
        "runs_missing_domain_observations_invalid_pcap": 2,
        "runs_missing_domain_observations_invalid_pcap_by_raw_detail": {
            "PCAP_DEVICE_FILE_MISSING": 1,
            "PCAP_LOCAL_FILE_MISSING": 1,
        },
        "runs_missing_domain_observations_index_lag": 0,
    }
    paragraphs = subject._draft_paragraphs(
        summary,
        [
            {"mode": "idle", "valid_dataset_run": 1, "domain_observations_in_db": 1},
            {"mode": "idle", "valid_dataset_run": 1, "domain_observations_in_db": 1},
        ],
        {"current_rdi_available": False},
    )
    assert (
        "no remaining runs are currently classified as evidence-backed index-lag candidates"
        in paragraphs
    )
    assert "invalid-PCAP exclusions rather than indexing debt" in paragraphs
    assert (
        "prior paper anchor remains the only directly reportable X/Twitter RDI reference tonight"
        in paragraphs
    )
    assert (
        "composed of `basic_usage` scenario runs rather than profile-v3 strict captures"
        in paragraphs
    )
    assert "retains 5 valid supplemental runs" in paragraphs
    assert "20 valid runs align to the latest observed build per app" in paragraphs
    assert (
        "1 apps are complete, 3 still need baseline coverage, and 2 still need interactive coverage"
        in paragraphs
    )
    assert "currently classified as quota-valid under the cohort protocol" in paragraphs
    assert "3-baseline / 4-interactive target" in paragraphs
    assert "9 of 15 cohort apps currently have local evidence" in paragraphs


def test_classify_missing_domain_observation_case_marks_invalid_pcap_artifact() -> None:
    row = {
        "pcap_report_exists": 1,
        "domain_observations_in_db": 0,
        "valid_dataset_run": 0,
        "invalid_reason_code": "PCAP_MISSING",
    }
    verify_row = {
        "issues": [
            {"code": "pcap_artifact_missing"},
            {"code": "protocol_empty_no_reason"},
        ]
    }
    reason, summary = subject._classify_missing_domain_observation_case(row, verify_row)
    assert reason == "invalid_pcap_artifact_missing"
    assert "not DB index lag" in summary


def test_raw_pcap_failure_detail_falls_back_to_canonical_artifact_missing(tmp_path) -> None:
    run_dir = tmp_path / "run-broken"
    run_dir.mkdir(parents=True, exist_ok=True)
    row = {
        "pcap_report_exists": 1,
        "invalid_reason_code": "PCAP_MISSING",
        "pcap_bytes": 0,
    }
    verify_row = {"issues": [{"code": "pcap_artifact_missing"}]}
    assert (
        subject._raw_pcap_failure_detail(run_dir, {"dataset": {}}, row, verify_row)
        == "PCAP_ARTIFACT_MISSING"
    )


def test_classify_missing_domain_observation_case_marks_true_index_lag_candidate() -> None:
    row = {
        "pcap_report_exists": 1,
        "domain_observations_in_db": 0,
        "valid_dataset_run": 1,
        "invalid_reason_code": "",
    }
    reason, summary = subject._classify_missing_domain_observation_case(row, {})
    assert reason == "index_lag_candidate"
    assert "index lag" in summary


def test_split_missing_domain_rows_separates_invalid_and_index_lag() -> None:
    invalid_rows, index_lag_rows = subject._split_missing_domain_rows(
        [
            {"dynamic_run_id": "run-invalid", "reason": "invalid_pcap_artifact_missing"},
            {"dynamic_run_id": "run-lag", "reason": "index_lag_candidate"},
            {"dynamic_run_id": "run-invalid-other", "reason": "invalid_excluded_run"},
        ]
    )
    assert [row["dynamic_run_id"] for row in invalid_rows] == ["run-invalid", "run-invalid-other"]
    assert [row["dynamic_run_id"] for row in index_lag_rows] == ["run-lag"]


def test_normalize_issues_csv_dedupes_codes() -> None:
    verify_row = {
        "issues": [
            {"code": "pcap_artifact_missing"},
            {"code": "pcap_artifact_missing"},
            {"code": "protocol_empty_no_reason"},
        ]
    }
    assert (
        subject._normalize_issues_csv(verify_row)
        == "pcap_artifact_missing;protocol_empty_no_reason"
    )
