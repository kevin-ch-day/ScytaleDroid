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
        "runs_with_domain_observations_db": 19,
        "runs_missing_domain_observations_db": 7,
        "runs_missing_domain_observations_invalid_pcap": 2,
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


def test_normalize_issues_csv_dedupes_codes() -> None:
    verify_row = {
        "issues": [
            {"code": "pcap_artifact_missing"},
            {"code": "pcap_artifact_missing"},
            {"code": "protocol_empty_no_reason"},
        ]
    }
    assert subject._normalize_issues_csv(verify_row) == "pcap_artifact_missing;protocol_empty_no_reason"
