from __future__ import annotations

from scytaledroid.DynamicAnalysis.scenarios import baseline_guidance


def test_social_feed_baseline_guidance_for_x_mentions_stable_screen() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.twitter.android",
        target_label="4 mins 0 sec (240s)",
    )
    text = "\n".join(lines)

    assert "Avoid Home / For You / feed timelines" in text
    assert "Avoid video/media-heavy screens" in text
    assert "Prefer a stable low-motion screen" in text
    assert "Stop near the" in text
    assert "target; longer capture is optional evidence" in text
    assert "X baseline tip" in text


def test_generic_baseline_guidance_remains_compact_for_unknown_package() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.example.unknown",
        target_label="4 mins 0 sec (240s)",
    )

    assert lines == [
        "  - Get the app running, then leave it in the foreground",
        "  - Best-effort idle; interact only if needed (e.g., prevent screen lock)",
    ]


def test_social_feed_baseline_warning_only_applies_to_baseline_profiles() -> None:
    warning = baseline_guidance.baseline_idle_quota_warning(
        "com.twitter.android", profile="baseline_idle"
    )
    no_warning = baseline_guidance.baseline_idle_quota_warning(
        "com.cnn.mobile.android.phone", profile="baseline_idle"
    )
    interactive_warning = baseline_guidance.baseline_idle_quota_warning(
        "com.twitter.android", profile="interaction_manual"
    )

    assert "Quota baseline requires quiet foreground behavior" in str(warning)
    assert no_warning is None
    assert interactive_warning is None


def test_social_feed_non_idle_next_step_is_specific_for_x() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("com.twitter.android")

    assert "stable non-feed/non-video X screen" in text
