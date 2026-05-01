from scytaledroid.DynamicAnalysis.controllers.guided_run import (
    _apply_messaging_baseline_countability_policy,
)


def test_messaging_baseline_none_downgrades_to_exploratory() -> None:
    countable, reason = _apply_messaging_baseline_countability_policy(
        package_name="org.telegram.messenger",
        run_profile="baseline_idle",
        messaging_activity="none",
        counts_toward_completion=True,
    )
    assert countable is False
    assert reason == "MESSAGING_BASELINE_NONE_EXPLORATORY"


def test_messaging_baseline_text_can_still_count() -> None:
    countable, reason = _apply_messaging_baseline_countability_policy(
        package_name="org.telegram.messenger",
        run_profile="baseline_idle",
        messaging_activity="text_only",
        counts_toward_completion=True,
    )
    assert countable is True
    assert reason is None


def test_messaging_baseline_connected_can_still_count() -> None:
    countable, reason = _apply_messaging_baseline_countability_policy(
        package_name="org.telegram.messenger",
        run_profile="baseline_connected",
        messaging_activity="connected_idle",
        counts_toward_completion=True,
    )
    assert countable is True
    assert reason is None


def test_non_messaging_baseline_none_unchanged() -> None:
    countable, reason = _apply_messaging_baseline_countability_policy(
        package_name="com.twitter.android",
        run_profile="baseline_idle",
        messaging_activity="none",
        counts_toward_completion=True,
    )
    assert countable is True
    assert reason is None


def test_category_mapped_messaging_baseline_none_downgrades(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.controllers.guided_run.category_for_package",
        lambda _pkg: "messaging",
    )
    countable, reason = _apply_messaging_baseline_countability_policy(
        package_name="com.twitter.android",
        run_profile="baseline_idle",
        messaging_activity="none",
        counts_toward_completion=True,
    )
    assert countable is False
    assert reason == "MESSAGING_BASELINE_NONE_EXPLORATORY"
