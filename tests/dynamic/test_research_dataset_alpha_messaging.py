from __future__ import annotations

from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import MESSAGING_PACKAGES


def test_messaging_packages_contains_expected_apps() -> None:
    pkgs = set(MESSAGING_PACKAGES)
    assert "com.facebook.orca" in pkgs
    assert "com.whatsapp" in pkgs
    assert "org.telegram.messenger" in pkgs
    assert "org.thoughtcrime.securesms" in pkgs

