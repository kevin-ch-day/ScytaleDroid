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
    assert "video autoplay is enabled" in text


def test_generic_baseline_guidance_remains_compact_for_unknown_package() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.example.unknown",
        target_label="4 mins 0 sec (240s)",
    )

    assert lines == [
        "  - Get the app running, then leave it in the foreground",
        "  - Best-effort idle; interact only if needed (e.g., prevent screen lock)",
    ]


def test_signal_messaging_connected_guidance_mentions_quiet_baseline() -> None:
    lines = baseline_guidance.messaging_connected_behavior_lines("org.thoughtcrime.securesms")
    text = "\n".join(lines)

    assert "Open an existing conversation thread and keep it visible" in text
    assert "Do not type, send, call, upload media, search, or open external links" in text
    assert "quiet foreground thread can produce very little traffic" in text
    assert "do not force extra actions just to raise bytes or packets" in text


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


def test_facebook_baseline_guidance_is_surface_specific() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.facebook.katana",
        target_label="4 mins 0 sec (240s)",
    )
    text = "\n".join(lines)

    assert "Avoid Home / For You / feed timelines" in text
    assert "Avoid video/media-heavy screens" in text
    assert "profile, Friends, Menu, Notifications" in text
    assert "If Facebook relaunches to Home, Reels, or Marketplace" in text
    assert "Facebook baseline tip" in text
    assert "embedded content" in text


def test_facebook_baseline_warning_mentions_reels_marketplace_and_embedded_content() -> None:
    warning = baseline_guidance.baseline_idle_quota_warning(
        "com.facebook.katana", profile="baseline_idle"
    )

    assert warning is not None
    assert "Reels, Stories, Marketplace" in warning
    assert "embedded-browser/content flows" in warning


def test_facebook_checkpoint_messages_are_surface_specific() -> None:
    messages = baseline_guidance.baseline_idle_checkpoint_messages("com.facebook.katana")

    assert "Home, Reels, Stories, or Marketplace" in messages[60]
    assert "profile, Friends, Menu, Notifications" in messages[60]
    assert "embedded browser flows" in messages[120]


def test_facebook_ready_note_mentions_switch_before_timer() -> None:
    note = baseline_guidance.baseline_idle_ready_note("com.facebook.katana")

    assert note is not None
    assert "Facebook often reopens on Home, Reels, or Marketplace" in note
    assert "Before pressing Enter, switch once" in note


def test_facebook_non_idle_next_step_mentions_calm_facebook_surfaces() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("com.facebook.katana")

    assert "profile, Friends, Menu, Notifications" in text
    assert "non-feed/non-reels/non-marketplace Facebook screen" in text


def test_social_feed_non_idle_next_step_is_specific_for_x() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("com.twitter.android")

    assert "stable non-feed/non-video X screen" in text


def test_linkedin_baseline_guidance_is_surface_specific() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.linkedin.android",
        target_label="4 mins 0 sec (240s)",
    )
    text = "\n".join(lines)

    assert "Avoid Home / For You / feed timelines" in text
    assert "Avoid video/media-heavy screens" in text
    assert "My Network, Jobs, profile, settings, or a static company/profile page" in text
    assert "If LinkedIn launches to Home, switch once" in text
    assert "LinkedIn baseline tip" in text


def test_linkedin_non_idle_next_step_mentions_stable_linkedin_surfaces() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("com.linkedin.android")

    assert "My Network, Jobs, profile, settings, or a static company/profile page" in text


def test_linkedin_baseline_warning_mentions_home_and_video_surfaces() -> None:
    warning = baseline_guidance.baseline_idle_quota_warning(
        "com.linkedin.android", profile="baseline_idle"
    )

    assert warning is not None
    assert "Home feed, Video, and active messaging surfaces" in warning


def test_linkedin_checkpoint_messages_are_surface_specific() -> None:
    messages = baseline_guidance.baseline_idle_checkpoint_messages("com.linkedin.android")

    assert "Home or Video" in messages[60]
    assert "My Network, Jobs, profile, settings, or a static company/profile page" in messages[60]
    assert "messaging surfaces" in messages[120]


def test_linkedin_ready_note_mentions_switch_before_timer() -> None:
    note = baseline_guidance.baseline_idle_ready_note("com.linkedin.android")

    assert note is not None
    assert "Before pressing Enter, switch once" in note
    assert "if Home is still selected" in note


def test_pinterest_baseline_guidance_is_surface_specific() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.pinterest",
        target_label="4 mins 0 sec (240s)",
    )
    text = "\n".join(lines)

    assert "Avoid Home / For You / feed timelines" in text
    assert "Avoid video/media-heavy screens" in text
    assert "profile, settings, saved items, a static board page" in text
    assert "If Pinterest launches to Home, switch once" in text
    assert "Pinterest baseline tip" in text
    assert "promoted pins, media cards, and video-capable content" in text


def test_pinterest_baseline_warning_mentions_promoted_and_video_pins() -> None:
    warning = baseline_guidance.baseline_idle_quota_warning(
        "com.pinterest", profile="baseline_idle"
    )

    assert warning is not None
    assert "promoted pins" in warning
    assert "video-capable pins" in warning


def test_pinterest_checkpoint_messages_are_surface_specific() -> None:
    messages = baseline_guidance.baseline_idle_checkpoint_messages("com.pinterest")

    assert "Home, a promoted pin, or a video-capable pin surface" in messages[60]
    assert "profile, saved items, a static board page, settings" in messages[60]
    assert "promoted pins, and video/media cards" in messages[120]


def test_pinterest_ready_note_mentions_switch_before_timer() -> None:
    note = baseline_guidance.baseline_idle_ready_note("com.pinterest")

    assert note is not None
    assert "Pinterest often reopens on Home after relaunch" in note
    assert "Before pressing Enter, switch once" in note


def test_pinterest_non_idle_next_step_mentions_stable_pinterest_surfaces() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("com.pinterest")

    assert "static board page" in text
    assert "non-video/non-promoted Pinterest screen" in text


def test_instagram_baseline_guidance_is_surface_specific() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.instagram.android",
        target_label="4 mins 0 sec (240s)",
    )
    text = "\n".join(lines)

    assert "Avoid Home / For You / feed timelines" in text
    assert "Avoid video/media-heavy screens" in text
    assert "Settings and activity, Saved, Archive" in text
    assert "If Instagram relaunches to Home, switch once" in text
    assert "Instagram baseline tip" in text
    assert "Stories, Reels" in text


def test_instagram_baseline_warning_mentions_home_stories_reels_and_profile_grid() -> None:
    warning = baseline_guidance.baseline_idle_quota_warning(
        "com.instagram.android", profile="baseline_idle"
    )

    assert warning is not None
    assert "Home feed, Stories, Reels" in warning
    assert "profile-grid browsing" in warning


def test_instagram_checkpoint_messages_are_surface_specific() -> None:
    messages = baseline_guidance.baseline_idle_checkpoint_messages("com.instagram.android")

    assert "Home, Stories, Reels" in messages[60]
    assert "Settings and activity, Saved, Archive" in messages[60]
    assert "profile-grid browsing" in messages[120]


def test_instagram_ready_note_mentions_switch_before_timer() -> None:
    note = baseline_guidance.baseline_idle_ready_note("com.instagram.android")

    assert note is not None
    assert "Instagram often reopens on Home after relaunch" in note
    assert "Before pressing Enter, switch once" in note


def test_instagram_non_idle_next_step_mentions_calm_instagram_surfaces() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("com.instagram.android")

    assert "Settings and activity, Saved, Archive" in text
    assert "non-feed/non-reels/non-story Instagram screen" in text


def test_guardian_baseline_guidance_is_surface_specific() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "com.guardian",
        target_label="4 mins 0 sec (240s)",
    )
    text = "\n".join(lines)

    assert "Avoid Home and article-open flows" in text
    assert "My Guardian, Profile, Menu" in text
    assert "Follow, Podcasts playback" in text
    assert "section/search navigation, native podcast-playback" in text


def test_bbc_baseline_guidance_is_surface_specific() -> None:
    lines = baseline_guidance.baseline_idle_behavior_lines(
        "bbc.mobile.news.ww",
        target_label="4 mins 0 sec (240s)",
    )
    text = "\n".join(lines)

    assert "Avoid the Home top-story rail" in text
    assert "News / Business / Technology" in text
    assert "Avoid Video, Live" in text
    assert "sign-in / register prompts" in text
    assert "manual/scripted interactive instead" in text


def test_bbc_baseline_warning_mentions_register_flows() -> None:
    warning = baseline_guidance.baseline_idle_quota_warning(
        "bbc.mobile.news.ww", profile="baseline_idle"
    )

    assert warning is not None
    assert "sign-in-register flows" in warning
    assert "interactive evidence" in warning


def test_bbc_non_idle_next_step_mentions_calm_section_or_more() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("bbc.mobile.news.ww")

    assert "BBC More or a calm section tab" in text
    assert "sign-in/register-wall" in text


def test_guardian_baseline_warning_mentions_registration_wall() -> None:
    warning = baseline_guidance.baseline_idle_quota_warning(
        "com.guardian", profile="baseline_idle"
    )

    assert warning is not None
    assert "free-registration walls" in warning
    assert "Follow actions" in warning
    assert "interactive evidence" in warning


def test_guardian_non_idle_next_step_mentions_interactive_mode() -> None:
    text = baseline_guidance.baseline_not_idle_next_step("com.guardian")

    assert "My Guardian, Profile, Menu" in text
    assert "section/search navigation" in text
    assert "native podcast playback" in text
    assert "Follow/auth-gate" in text
