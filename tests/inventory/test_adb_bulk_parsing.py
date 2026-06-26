from __future__ import annotations

import pytest

from scytaledroid.DeviceAnalysis.inventory import adb_bulk


pytestmark = [pytest.mark.unit]


def test_parse_bulk_package_listing_captures_path_installer_uid_and_version_code():
    entry = adb_bulk._parse_pm_list_line(
        "package:/data/app/~~abc/pkg-base/base.apk=com.example.app "
        "installer=com.android.vending uid:10234 versionCode:77 user:0"
    )

    assert entry is not None
    assert entry.package_name == "com.example.app"
    assert entry.apk_path == "/data/app/~~abc/pkg-base/base.apk"
    assert entry.installer == "com.android.vending"
    assert entry.uid == 10234
    assert entry.version_code == "77"
    assert entry.user == "0"


def test_parse_bulk_package_listing_real_android15_line_tolerates_null_installer():
    entry = adb_bulk._parse_pm_list_line(
        "package:/product/priv-app/VzwDeviceSetup/VzwDeviceSetup.apk="
        "com.motorola.setupwizard.devicesetup versionCode:35 installer=null uid:10281"
    )

    assert entry is not None
    assert entry.package_name == "com.motorola.setupwizard.devicesetup"
    assert entry.apk_path == "/product/priv-app/VzwDeviceSetup/VzwDeviceSetup.apk"
    assert entry.version_code == "35"
    assert entry.installer is None
    assert entry.uid == 10281


def test_parse_bulk_package_listing_tolerates_missing_uid():
    entry = adb_bulk._parse_pm_list_line(
        "package:/data/app/~~abc/pkg-base/base.apk=com.example.app "
        "versionCode:77 installer=com.android.vending"
    )

    assert entry is not None
    assert entry.package_name == "com.example.app"
    assert entry.uid is None
    assert entry.installer == "com.android.vending"
    assert entry.version_code == "77"


def test_parse_dumpsys_package_extracts_inventory_relevant_metadata():
    parsed = adb_bulk.parse_dumpsys_package(
        """
  Package [com.example.one] (abc123):
    appId=10234
    versionCode=77 minSdk=26 targetSdk=35
    versionName=7.7.0
    lastUpdateTime=2026-06-14 00:40:13
    installerPackageName=com.android.vending
    User 0: ceDataInode=123 installed=true
      firstInstallTime=2026-05-08 16:33:35
  Package [com.example.two] (def456):
    appId=10001
    versionName=1.0
    lastUpdateTime=2026-06-01 10:11:12
    installerPackageName=null
    User 0: ceDataInode=456 installed=true
      firstInstallTime=2026-06-01 10:11:12
        """
    )

    assert parsed["com.example.one"]["package_name"] == "com.example.one"
    assert parsed["com.example.one"]["user_id"] == "10234"
    assert parsed["com.example.one"]["version_code"] == "77"
    assert parsed["com.example.one"]["version_name"] == "7.7.0"
    assert parsed["com.example.one"]["last_update"] == "2026-06-14 00:40:13"
    assert parsed["com.example.one"]["installer"] == "com.android.vending"
    assert parsed["com.example.one"]["first_install"] == "2026-05-08 16:33:35"
    assert parsed["com.example.two"]["installer"] is None


def test_parse_dumpsys_package_prefers_better_duplicate_section_for_updated_system_app():
    parsed = adb_bulk.parse_dumpsys_package(
        """
  Package [com.android.vending] (old111):
    appId=10273
    versionCode=84502130 minSdk=32 targetSdk=37
    versionName=45.0.21-31 [0] [PR] 728331212
    lastUpdateTime=1969-12-31 17:59:59
    installerPackageName=null
    User 0: ceDataInode=123 installed=true
      firstInstallTime=1969-12-31 17:59:59
  Package [com.android.vending] (new222):
    appId=10273
    versionCode=85180930 minSdk=32 targetSdk=37
    versionName=51.8.09-31 [0] [PR] 927580062
    lastUpdateTime=2026-06-11 13:43:29
    installerPackageName=com.android.vending
    User 0: ceDataInode=456 installed=true
      firstInstallTime=2008-12-31 18:00:00
        """
    )

    assert parsed["com.android.vending"]["version_code"] == "85180930"
    assert parsed["com.android.vending"]["version_name"] == "51.8.09-31 [0] [PR] 927580062"
    assert parsed["com.android.vending"]["last_update"] == "2026-06-11 13:43:29"
    assert parsed["com.android.vending"]["installer"] == "com.android.vending"
    assert parsed["com.android.vending"]["first_install"] == "2008-12-31 18:00:00"


def test_reconstruct_apk_paths_for_data_app_splits():
    paths = adb_bulk.reconstruct_apk_paths(
        {
            "code_path": "/data/app/~~abc/com.example.app-123",
            "split_names": ["base", "config.arm64_v8a", "feature.chat"],
        }
    )

    assert paths == [
        "/data/app/~~abc/com.example.app-123/base.apk",
        "/data/app/~~abc/com.example.app-123/split_config.arm64_v8a.apk",
        "/data/app/~~abc/com.example.app-123/split_feature.chat.apk",
    ]


def test_reconstruct_apk_paths_for_system_base_only_package():
    paths = adb_bulk.reconstruct_apk_paths(
        {
            "code_path": "/system/priv-app/SoundPicker",
            "split_names": ["base"],
        }
    )

    assert paths == ["/system/priv-app/SoundPicker/SoundPicker.apk"]


def test_reconstruct_apk_paths_refuses_overlay_and_apex_guessing():
    assert adb_bulk.reconstruct_apk_paths(
        {
            "code_path": "/product/overlay/DisplayCutoutEmulationNoCutout",
            "split_names": ["base"],
        }
    ) is None
    assert adb_bulk.reconstruct_apk_paths(
        {
            "code_path": "/apex/com.android.tethering/priv-app/TetheringGoogle@361524140",
            "split_names": ["base"],
        }
    ) is None
