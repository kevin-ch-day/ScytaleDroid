from __future__ import annotations

from scytaledroid.Database.db_utils.package_utils import (
    is_invalid_package_name,
    is_suspicious_package_name,
    normalize_package_name,
)


def test_normalize_package_name_rejects_numeric_only_token() -> None:
    assert normalize_package_name("20260204", context="test") == ""
    assert is_invalid_package_name("20260204") is True


def test_apk_suffix_package_is_quarantined_not_rejected() -> None:
    package_name = "com.google.android.appsearch.apk"
    assert normalize_package_name(package_name, context="test") == package_name
    assert is_invalid_package_name(package_name) is False
    assert is_suspicious_package_name(package_name) is True
