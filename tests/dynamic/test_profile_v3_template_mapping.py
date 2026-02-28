from __future__ import annotations

import os


def test_profile_v3_template_mapping_resolves_from_catalog(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_TEMPLATE_MAP_PROFILE", "v3")
    from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package

    assert resolved_template_for_package("com.adobe.reader") == "cloud_productivity_basic_v1"
    assert resolved_template_for_package("com.discord") == "discord_basic_v1"
    assert resolved_template_for_package("com.google.android.apps.tachyon") == "meet_join_mic_on_cam_off_v1"
    assert resolved_template_for_package("us.zoom.videomeetings") == "zoom_join_audio_only_v1"
    assert resolved_template_for_package("com.google.android.apps.docs") == "drive_browse_search_open_star_v1"
    assert resolved_template_for_package("com.google.android.apps.docs.editors.docs") == "docs_open_edit_comment_refresh_v1"
    assert (
        resolved_template_for_package("com.google.android.apps.docs.editors.sheets")
        == "sheets_open_edit_sort_row_refresh_v1"
    )
    assert resolved_template_for_package("com.facebook.katana") == "social_messaging_basic_v1"
    assert resolved_template_for_package("com.zhiliaoapp.musically") == "tiktok_basic_v2"


def test_profile_v2_mapping_unchanged_by_default() -> None:
    os.environ.pop("SCYTALEDROID_TEMPLATE_MAP_PROFILE", None)
    from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package

    # V2 mapping should remain intact for paper2 apps.
    assert resolved_template_for_package("com.facebook.katana") in {"facebook_basic_v2", "social_feed_basic_v2"}
    assert resolved_template_for_package("com.whatsapp") in {"whatsapp_basic_v1", "messaging_basic_v1"}


def test_profile_v3_manual_template_resolves(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_TEMPLATE_MAP_PROFILE", "v3")
    from scytaledroid.DynamicAnalysis.scenarios.manual_templates import resolve_script_template

    tid, steps = resolve_script_template(package_name="com.adobe.reader")
    assert tid == "cloud_productivity_basic_v1"
    assert steps and isinstance(steps, tuple)

    tid, steps = resolve_script_template(package_name="com.google.android.apps.tachyon")
    assert tid == "meet_join_mic_on_cam_off_v1"
    assert steps and isinstance(steps, tuple)
