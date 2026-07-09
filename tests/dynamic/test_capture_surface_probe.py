from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.capture.state import CaptureState, CaptureStatus, ObserverStatus
from scytaledroid.DynamicAnalysis.capture.surface_probe import (
    infer_bbc_surface,
    infer_guardian_surface,
    infer_instagram_surface,
    infer_messenger_surface,
    infer_runtime_surface,
    infer_signal_surface,
    infer_telegram_surface,
    infer_x_surface,
)
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios import manual
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import ActiveCaptureRuntime


def _guardian_state(
    *,
    foreground_package: str = "com.guardian",
    foreground_component: str = "com.guardian.feature.stream.HomeActivity",
) -> CaptureState:
    return CaptureState(
        app_name="Guardian",
        package_name="com.guardian",
        expected_package="com.guardian",
        version_code="23011",
        phase="Baseline idle",
        status=CaptureStatus.RUNNING_VALID,
        foreground_package=foreground_package,
        foreground_component=foreground_component,
        observer_status=ObserverStatus(),
        target_duration_s=240,
        minimum_duration_s=180,
    )


def test_infer_guardian_surface_detects_my_guardian() -> None:
    label, detail = infer_guardian_surface(
        package_name="com.guardian",
        component_name="com.guardian.feature.stream.HomeActivity",
        ui_strings=[
            "Following",
            "Saved",
            "History",
        ],
    )

    assert label == "my_guardian"
    assert detail == "personalized guardian lane"


def test_infer_guardian_surface_detects_support_paywall() -> None:
    label, detail = infer_guardian_surface(
        package_name="com.guardian",
        component_name="com.guardian.feature.stream.HomeActivity",
        ui_strings=[
            "Support the Guardian",
            "I already support the Guardian",
        ],
    )

    assert label == "support_paywall"
    assert detail == "support / subscription wall"


def test_infer_runtime_surface_detects_guardian_article_auth_wall(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: [
            "You now need to sign in",
            "Register for free",
        ],
    )

    label, detail = infer_runtime_surface(
        expected_package="com.guardian",
        foreground_package="com.guardian",
        foreground_component="com.guardian.feature.renderedarticle.NewArticleActivity",
        device_serial="SERIAL",
    )

    assert label == "article_auth_wall"
    assert detail == "registration / sign-in wall"


def test_infer_bbc_surface_detects_audio_hub_with_miniplayer() -> None:
    label, detail = infer_bbc_surface(
        package_name="bbc.mobile.news.ww",
        component_name="com.mobile.MainActivity",
        ui_strings=[
            "Audio",
            "Podcast Categories",
            "Radio Stations",
            "Audio FAQs",
            "The Global Story: Is the American century over? Your questions answered",
        ],
    )

    assert label == "audio_hub_with_miniplayer"
    assert detail == "audio hub with active miniplayer"


def test_infer_bbc_surface_detects_settings() -> None:
    label, detail = infer_bbc_surface(
        package_name="bbc.mobile.news.ww",
        component_name="com.mobile.MainActivity",
        ui_strings=[
            "Settings",
            "Text size",
            "Theme",
            "Privacy",
            "Sign out",
        ],
    )

    assert label == "settings"
    assert detail == "bbc settings"


def test_infer_bbc_surface_detects_verify_article_detail() -> None:
    label, detail = infer_bbc_surface(
        package_name="bbc.mobile.news.ww",
        component_name="com.mobile.MainActivity",
        ui_strings=[
            "BBC Verify",
            "These Taylor Swift wedding pictures are not real",
            "More on this story.",
            "Artificial intelligence",
        ],
    )

    assert label == "verify_article_detail"
    assert detail == "bbc verify article detail"


def test_infer_runtime_surface_detects_bbc_video_player(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: [
            "Video",
            "EXPLORE MORE",
            "Player",
            "'The spectacle Iran wants the world to see': Lyse Doucet in Tehran",
        ],
    )

    label, detail = infer_runtime_surface(
        expected_package="bbc.mobile.news.ww",
        foreground_package="bbc.mobile.news.ww",
        foreground_component="com.mobile.MainActivity",
        device_serial="SERIAL",
    )

    assert label == "video_player"
    assert detail == "video feed with inline player"


def test_infer_messenger_surface_detects_rtc_audio_call_surface() -> None:
    label, detail = infer_messenger_surface(
        package_name="com.facebook.orca",
        component_name="com.facebook.messaging.rtc.incall.activity.InCallActivity",
        ui_strings=[
            "End-to-end encrypted call with Emily Adou, camera off",
            "Emily Adou",
            "02:00",
            "Turn camera on",
            "Mute microphone",
            "Expand activities",
            "Turn Speaker on",
            "End",
        ],
    )

    assert label == "rtc_call_audio_surface"
    assert detail == "messenger rtc audio call surface"


def test_infer_messenger_surface_detects_rtc_video_call_surface() -> None:
    label, detail = infer_messenger_surface(
        package_name="com.facebook.orca",
        component_name="com.facebook.messaging.rtc.incall.activity.InCallActivity",
        ui_strings=[
            "End-to-end encrypted call with Emily Adou",
            "You, Showing front camera, Microphone on",
            "Effects",
            "Mute microphone",
            "End",
        ],
    )

    assert label == "rtc_call_video_surface"
    assert detail == "messenger rtc video call surface"


def test_infer_runtime_surface_detects_messenger_rtc_call(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: [
            "End-to-end encrypted call with Emily Adou, camera off",
            "Emily Adou",
            "Turn camera on",
            "Mute microphone",
            "Expand activities",
            "Turn Speaker on",
            "End",
        ],
    )

    label, detail = infer_runtime_surface(
        expected_package="com.facebook.orca",
        foreground_package="com.facebook.orca",
        foreground_component="com.facebook.messaging.rtc.incall.activity.InCallActivity",
        device_serial="SERIAL",
    )

    assert label == "rtc_call_audio_surface"
    assert detail == "messenger rtc audio call surface"


def test_infer_signal_surface_detects_webrtc_video_call_surface() -> None:
    label, detail = infer_signal_surface(
        package_name="org.thoughtcrime.securesms",
        component_name="org.thoughtcrime.securesms.components.webrtc.v2.WebRtcCallActivity",
        ui_strings=["Turn camera off", "Flip camera", "Mute microphone", "End call"],
    )

    assert label == "webrtc_video_call_surface"
    assert detail == "signal webrtc video call surface"


def test_infer_runtime_surface_detects_signal_webrtc_call(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: ["Turn camera on", "Speaker", "Mute microphone", "End call"],
    )

    label, detail = infer_runtime_surface(
        expected_package="org.thoughtcrime.securesms",
        foreground_package="org.thoughtcrime.securesms",
        foreground_component="org.thoughtcrime.securesms.components.webrtc.v2.WebRtcCallActivity",
        device_serial="SERIAL",
    )

    assert label == "webrtc_voice_call_surface"
    assert detail == "signal webrtc voice call surface"


def test_infer_telegram_surface_detects_voice_call_surface() -> None:
    label, detail = infer_telegram_surface(
        package_name="org.telegram.messenger",
        component_name="org.telegram.messenger.DefaultIcon",
        ui_strings=[
            "Telegram Call",
            "Encryption key of this call",
            "Speaker",
            "Start Video",
            "Mute",
            "End Call",
        ],
    )

    assert label == "telegram_voice_call_surface"
    assert detail == "telegram voice call surface"


def test_infer_runtime_surface_detects_telegram_voice_call(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: [
            "Telegram Call",
            "Encryption key of this call",
            "Speaker",
            "Start Video",
            "Mute",
            "End Call",
        ],
    )

    label, detail = infer_runtime_surface(
        expected_package="org.telegram.messenger",
        foreground_package="org.telegram.messenger",
        foreground_component="org.telegram.messenger.DefaultIcon",
        device_serial="SERIAL",
    )

    assert label == "telegram_voice_call_surface"
    assert detail == "telegram voice call surface"


def test_infer_telegram_surface_detects_minimal_video_call_surface() -> None:
    label, detail = infer_telegram_surface(
        package_name="org.telegram.messenger",
        component_name="org.telegram.messenger.DefaultIcon",
        ui_strings=[
            "Telegram Video Call",
            "Encryption key of this call",
        ],
    )

    assert label == "telegram_video_call_surface"
    assert detail == "telegram video call surface"


def test_infer_instagram_surface_detects_home_feed() -> None:
    label, detail = infer_instagram_surface(
        package_name="com.instagram.android",
        component_name="com.instagram.android.activity.MainTabActivity",
        ui_strings=[
            "Instagram Home Feed",
            "Turn sound off",
            "Suggested for you",
            "Original audio",
            "More actions for this post",
            "Reels",
        ],
    )

    assert label == "home_feed"
    assert detail == "instagram home feed"


def test_infer_instagram_surface_detects_settings_activity() -> None:
    label, detail = infer_instagram_surface(
        package_name="com.instagram.android",
        component_name="com.instagram.android.activity.MainTabActivity",
        ui_strings=[
            "Settings and activity",
            "Accounts Center",
            "Your activity",
            "Time management",
        ],
    )

    assert label == "settings_activity"
    assert detail == "instagram settings and activity"


def test_infer_instagram_surface_detects_saved_items() -> None:
    label, detail = infer_instagram_surface(
        package_name="com.instagram.android",
        component_name="com.instagram.android.activity.MainTabActivity",
        ui_strings=[
            "Back",
            "Saved",
            "All Posts",
            "Collections",
        ],
    )

    assert label == "saved_items"
    assert detail == "instagram saved items"


def test_infer_runtime_surface_detects_instagram_profile(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: [
            "Your profile. Seen story",
            "Edit profile",
            "Share profile",
            "Posts",
            "followers",
            "following",
            "Profile",
        ],
    )

    label, detail = infer_runtime_surface(
        expected_package="com.instagram.android",
        foreground_package="com.instagram.android",
        foreground_component="com.instagram.android.activity.MainTabActivity",
        device_serial="SERIAL",
    )

    assert label == "profile_surface"
    assert detail == "instagram profile"


def test_infer_runtime_surface_detects_messenger_rtc_video_call(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: [
            "End-to-end encrypted call with Emily Adou",
            "You, Showing front camera, Microphone on",
            "Effects",
            "Mute microphone",
            "End",
        ],
    )

    label, detail = infer_runtime_surface(
        expected_package="com.facebook.orca",
        foreground_package="com.facebook.orca",
        foreground_component="com.facebook.messaging.rtc.incall.activity.InCallActivity",
        device_serial="SERIAL",
    )

    assert label == "rtc_call_video_surface"
    assert detail == "messenger rtc video call surface"


def test_infer_x_surface_detects_home_feed() -> None:
    label, detail = infer_x_surface(
        package_name="com.twitter.android",
        component_name="com.twitter.app.main.MainActivity",
        ui_strings=[
            "Home timeline list",
            "For you",
            "Following",
            "New post",
        ],
    )

    assert label == "home_feed"
    assert detail == "home timeline"


def test_infer_x_surface_detects_explore_surface() -> None:
    label, detail = infer_x_surface(
        package_name="com.twitter.android",
        component_name="com.twitter.app.main.MainActivity",
        ui_strings=[
            "Search and Explore",
            "Trending",
            "News",
            "Trending in United States",
            "Posts For You",
        ],
    )

    assert label == "explore_surface"
    assert detail == "search and explore / trends"


def test_infer_x_surface_detects_profile_surface() -> None:
    label, detail = infer_x_surface(
        package_name="com.twitter.android",
        component_name="com.twitter.app.profiles.ProfileActivity",
        ui_strings=[
            "Posts",
            "Replies",
            "Followers",
            "Following",
        ],
    )

    assert label == "profile_surface"
    assert detail == "profile timeline"


def test_infer_x_surface_detects_profile_surface_hosted_in_mainactivity() -> None:
    label, detail = infer_x_surface(
        package_name="com.twitter.android",
        component_name="com.twitter.app.main.MainActivity",
        ui_strings=[
            "Posts",
            "Replies",
            "Highlights",
            "Media",
            "Followers",
            "Following",
            "Profile image",
        ],
    )

    assert label == "profile_surface"
    assert detail == "profile timeline hosted in mainactivity"


def test_infer_x_surface_detects_search_results() -> None:
    label, detail = infer_x_surface(
        package_name="com.twitter.android",
        component_name="com.twitter.android.search.implementation.results.SearchActivity",
        ui_strings=[
            "openai",
            "Top",
            "Latest",
            "People",
            "Media",
            "Lists",
            "Search X",
        ],
    )

    assert label == "search_results"
    assert detail == "search results"


def test_infer_x_surface_detects_tweet_detail() -> None:
    label, detail = infer_x_surface(
        package_name="com.twitter.android",
        component_name="com.twitter.tweetdetail.TweetDetailActivity",
        ui_strings=[
            "Post",
            "Most relevant replies",
            "Post your reply",
            "Discover more",
        ],
    )

    assert label == "tweet_detail"
    assert detail == "post detail / replies"


def test_infer_x_surface_detects_compose_actions() -> None:
    label, detail = infer_x_surface(
        package_name="com.twitter.android",
        component_name="com.twitter.app.main.MainActivity",
        ui_strings=[
            "Go Live",
            "Spaces",
            "Photos",
            "New post",
            "Post",
        ],
    )

    assert label == "compose_actions"
    assert detail == "composer radial actions"


def test_infer_runtime_surface_detects_x_explore(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.surface_probe._read_ui_strings",
        lambda _serial: [
            "Search and Explore",
            "Trending",
            "News",
            "Trending in United States",
        ],
    )

    label, detail = infer_runtime_surface(
        expected_package="com.twitter.android",
        foreground_package="com.twitter.android",
        foreground_component="com.twitter.app.main.MainActivity",
        device_serial="SERIAL",
    )

    assert label == "explore_surface"
    assert detail == "search and explore / trends"


def test_infer_runtime_surface_detects_x_custom_tab() -> None:
    label, detail = infer_runtime_surface(
        expected_package="com.twitter.android",
        foreground_package="com.android.chrome",
        foreground_component="org.chromium.chrome.browser.customtabs.CustomTabActivity",
        device_serial="SERIAL",
    )

    assert label == "external_custom_tab"
    assert detail == "browser-backed x flow"


def test_guardian_runtime_surface_probe_throttles_repeated_reads(monkeypatch, tmp_path: Path) -> None:
    ctx = RunContext(
        dynamic_run_id="r-guardian",
        package_name="com.guardian",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="baseline_idle",
        interaction_level="minimal",
        device_serial="SERIAL",
        static_plan={"display_label": "Guardian"},
    )
    calls: list[tuple[str, str]] = []
    ticks = iter([0.0, 1.0, 9.5])

    monkeypatch.setattr(manual.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        manual,
        "_infer_runtime_surface",
        lambda **kwargs: (
            calls.append(
                (
                    str(kwargs.get("foreground_package") or ""),
                    str(kwargs.get("foreground_component") or ""),
                )
            )
            or ("home_feed", "front page feed")
        ),
    )

    probe = manual._make_runtime_surface_probe(ctx)
    state = _guardian_state()

    assert probe is not None
    assert probe(state) == ("home_feed", "front page feed")
    assert probe(state) == ("home_feed", "front page feed")
    state.foreground_component = "com.guardian.feature.search.SearchActivity"
    assert probe(state) == ("home_feed", "front page feed")

    assert calls == [
        ("com.guardian", "com.guardian.feature.stream.HomeActivity"),
        ("com.guardian", "com.guardian.feature.search.SearchActivity"),
    ]


def test_x_runtime_surface_probe_is_wired_and_throttled(monkeypatch, tmp_path: Path) -> None:
    ctx = RunContext(
        dynamic_run_id="r-x",
        package_name="com.twitter.android",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="interaction_manual",
        interaction_level="normal",
        device_serial="SERIAL",
        static_plan={"display_label": "X"},
    )
    calls: list[tuple[str, str]] = []
    ticks = iter([0.0, 1.0, 9.5])

    monkeypatch.setattr(manual.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        manual,
        "_infer_runtime_surface",
        lambda **kwargs: (
            calls.append(
                (
                    str(kwargs.get("foreground_package") or ""),
                    str(kwargs.get("foreground_component") or ""),
                )
            )
            or ("search_results", "search results")
        ),
    )

    probe = manual._make_runtime_surface_probe(ctx)
    state = CaptureState(
        app_name="X",
        package_name="com.twitter.android",
        expected_package="com.twitter.android",
        version_code="312050000",
        phase="Manual interactive",
        status=CaptureStatus.RUNNING_VALID,
        foreground_package="com.twitter.android",
        foreground_component="com.twitter.android.search.implementation.results.SearchActivity",
        observer_status=ObserverStatus(),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    assert probe is not None
    assert probe(state) == ("search_results", "search results")
    assert probe(state) == ("search_results", "search results")
    state.foreground_component = "com.twitter.tweetdetail.TweetDetailActivity"
    assert probe(state) == ("search_results", "search results")

    assert calls == [
        ("com.twitter.android", "com.twitter.android.search.implementation.results.SearchActivity"),
        ("com.twitter.android", "com.twitter.tweetdetail.TweetDetailActivity"),
    ]


def test_messenger_runtime_surface_probe_is_wired_and_throttled(monkeypatch, tmp_path: Path) -> None:
    ctx = RunContext(
        dynamic_run_id="r-orca",
        package_name="com.facebook.orca",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="interaction_manual",
        interaction_level="normal",
        device_serial="SERIAL",
        static_plan={"display_label": "Messenger"},
    )
    calls: list[tuple[str, str]] = []
    ticks = iter([0.0, 1.0, 9.5])

    monkeypatch.setattr(manual.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        manual,
        "_infer_runtime_surface",
        lambda **kwargs: (
            calls.append(
                (
                    str(kwargs.get("foreground_package") or ""),
                    str(kwargs.get("foreground_component") or ""),
                )
            )
            or ("rtc_call_audio_surface", "messenger rtc audio call surface")
        ),
    )

    probe = manual._make_runtime_surface_probe(ctx)
    state = CaptureState(
        app_name="Messenger",
        package_name="com.facebook.orca",
        expected_package="com.facebook.orca",
        version_code="343612216",
        phase="Manual interactive",
        status=CaptureStatus.RUNNING_VALID,
        foreground_package="com.facebook.orca",
        foreground_component="com.facebook.messaging.rtc.incall.activity.InCallActivity",
        observer_status=ObserverStatus(),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    assert probe is not None
    assert probe(state) == ("rtc_call_audio_surface", "messenger rtc audio call surface")
    assert probe(state) == ("rtc_call_audio_surface", "messenger rtc audio call surface")
    state.foreground_component = "com.facebook.messenger.neue.MainActivity"
    assert probe(state) == ("rtc_call_audio_surface", "messenger rtc audio call surface")

    assert calls == [
        ("com.facebook.orca", "com.facebook.messaging.rtc.incall.activity.InCallActivity"),
        ("com.facebook.orca", "com.facebook.messenger.neue.MainActivity"),
    ]


def test_bbc_runtime_surface_probe_is_wired_and_throttled(monkeypatch, tmp_path: Path) -> None:
    ctx = RunContext(
        dynamic_run_id="r-bbc",
        package_name="bbc.mobile.news.ww",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="interaction_manual",
        interaction_level="normal",
        device_serial="SERIAL",
        static_plan={"display_label": "BBC News"},
    )
    calls: list[tuple[str, str]] = []
    ticks = iter([0.0, 1.0, 9.5])

    monkeypatch.setattr(manual.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        manual,
        "_infer_runtime_surface",
        lambda **kwargs: (
            calls.append(
                (
                    str(kwargs.get("foreground_package") or ""),
                    str(kwargs.get("foreground_component") or ""),
                )
            )
            or ("audio_hub_with_miniplayer", "audio hub with active miniplayer")
        ),
    )

    probe = manual._make_runtime_surface_probe(ctx)
    state = CaptureState(
        app_name="BBC News",
        package_name="bbc.mobile.news.ww",
        expected_package="bbc.mobile.news.ww",
        version_code="10007091",
        phase="Manual interactive",
        status=CaptureStatus.RUNNING_VALID,
        foreground_package="bbc.mobile.news.ww",
        foreground_component="com.mobile.MainActivity",
        observer_status=ObserverStatus(),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    assert probe is not None
    assert probe(state) == ("audio_hub_with_miniplayer", "audio hub with active miniplayer")
    assert probe(state) == ("audio_hub_with_miniplayer", "audio hub with active miniplayer")
    state.foreground_component = "com.mobile.MainActivity#verify"
    assert probe(state) == ("audio_hub_with_miniplayer", "audio hub with active miniplayer")

    assert calls == [
        ("bbc.mobile.news.ww", "com.mobile.MainActivity"),
        ("bbc.mobile.news.ww", "com.mobile.MainActivity#verify"),
    ]


def test_telegram_runtime_surface_probe_is_wired_and_throttled(monkeypatch, tmp_path: Path) -> None:
    ctx = RunContext(
        dynamic_run_id="r-telegram",
        package_name="org.telegram.messenger",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="interaction_manual",
        interaction_level="normal",
        device_serial="SERIAL",
        static_plan={"display_label": "Telegram"},
    )
    calls: list[tuple[str, str]] = []
    ticks = iter([0.0, 1.0, 9.5])

    monkeypatch.setattr(manual.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        manual,
        "_infer_runtime_surface",
        lambda **kwargs: (
            calls.append(
                (
                    str(kwargs.get("foreground_package") or ""),
                    str(kwargs.get("foreground_component") or ""),
                )
            )
            or ("telegram_voice_call_surface", "telegram voice call surface")
        ),
    )

    probe = manual._make_runtime_surface_probe(ctx)
    state = CaptureState(
        app_name="Telegram",
        package_name="org.telegram.messenger",
        expected_package="org.telegram.messenger",
        version_code="400",
        phase="Manual interactive",
        status=CaptureStatus.RUNNING_VALID,
        foreground_package="org.telegram.messenger",
        foreground_component="org.telegram.messenger.DefaultIcon",
        observer_status=ObserverStatus(),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    assert probe is not None
    assert probe(state) == ("telegram_voice_call_surface", "telegram voice call surface")
    assert probe(state) == ("telegram_voice_call_surface", "telegram voice call surface")
    state.foreground_component = "org.telegram.messenger.LaunchActivity"
    assert probe(state) == ("telegram_voice_call_surface", "telegram voice call surface")

    assert calls == [
        ("org.telegram.messenger", "org.telegram.messenger.DefaultIcon"),
        ("org.telegram.messenger", "org.telegram.messenger.LaunchActivity"),
    ]


def test_tick_console_emits_surface_change_only_on_change() -> None:
    runtime = ActiveCaptureRuntime(
        build_capture_state=lambda **_kwargs: None,
        observer_status_provider_factory=lambda **_kwargs: None,
        read_foreground_target=lambda _serial: (None, None),
        foreground_surface_validator_factory=None,
        launch_package_to_foreground=lambda _serial, _package: None,
        should_continue_collecting=lambda **_kwargs: False,
        console_class=object,
        input_reader_factory=lambda _stdin: None,
        terminal_factory=lambda **_kwargs: None,
        clock=lambda: 0.0,
        stdin=SimpleNamespace(isatty=lambda: False),
        stdout=SimpleNamespace(),
        status_printer=lambda _message, level="info": None,
    )
    state = _guardian_state()
    events: list[tuple[str, dict[str, object]]] = []
    emitted_status: list[tuple[str, str]] = []
    last_status = {"value": None}
    last_surface = {"value": None}

    runtime._tick_console(
        state,
        lambda message, level="info": emitted_status.append((message, level)),
        checkpoint_messages=None,
        checkpoint_emitted=set(),
        continue_after_target=True,
        target_duration_s=240,
        target_reached_announced_ref={"value": False},
        last_status_ref=last_status,
        last_surface_ref=last_surface,
        surface_probe=lambda _state: ("home_feed", "front page feed"),
        on_elapsed=None,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )
    runtime._tick_console(
        state,
        lambda message, level="info": emitted_status.append((message, level)),
        checkpoint_messages=None,
        checkpoint_emitted=set(),
        continue_after_target=True,
        target_duration_s=240,
        target_reached_announced_ref={"value": False},
        last_status_ref=last_status,
        last_surface_ref=last_surface,
        surface_probe=lambda _state: ("home_feed", "front page feed"),
        on_elapsed=None,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )

    assert state.foreground_surface_label == "home_feed"
    assert events == [
        (
            "FOREGROUND_SURFACE_CHANGE",
            {
                "elapsed_s": 0,
                "foreground_package": "com.guardian",
                "foreground_component": "com.guardian.feature.stream.HomeActivity",
                "surface_label": "home_feed",
                "surface_detail": "front page feed",
            },
        )
    ]
