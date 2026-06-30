from __future__ import annotations

def test_report_research_cohorts_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/report_research_cohorts.py")


def test_report_research_cohorts_all_members_help_is_safe(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_research_cohorts.py")
    assert "--all-members" in out
