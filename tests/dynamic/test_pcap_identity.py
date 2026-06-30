from __future__ import annotations

from scytaledroid.DynamicAnalysis.pcap.identity import (
    build_capture_identity,
    ensure_features_capture_identity,
    ensure_report_capture_identity,
    infer_pcap_capture_name,
)


def test_infer_pcap_capture_name_falls_back_to_pcap_path_basename() -> None:
    report = {"pcap_path": "artifacts/pcapdroid_capture/app_capture.pcap"}
    assert infer_pcap_capture_name(report) == "app_capture.pcap"


def test_build_capture_identity_uses_package_slug_and_name() -> None:
    ident = build_capture_identity(
        dynamic_run_id="run-1",
        package_name="com.whatsapp",
        app_label="WhatsApp",
        pcap_capture_name="capture.pcap",
    )
    assert ident["dynamic_run_id"] == "run-1"
    assert ident["package_name"] == "com.whatsapp"
    assert ident["package_slug"] == "com_whatsapp"
    assert ident["app_label"] == "WhatsApp"
    assert ident["pcap_capture_name"] == "capture.pcap"


def test_ensure_report_capture_identity_populates_missing_fields() -> None:
    report = {"pcap_path": "artifacts/pcapdroid_capture/legacy_capture.pcap", "app_label": "BBC News"}
    changed = ensure_report_capture_identity(
        report,
        dynamic_run_id="run-2",
        package_name="bbc.mobile.news.ww",
        app_label=None,
    )
    assert changed is True
    assert report["pcap_capture_name"] == "legacy_capture.pcap"
    assert report["capture_identity"]["dynamic_run_id"] == "run-2"
    assert report["capture_identity"]["package_slug"] == "bbc_mobile_news_ww"
    assert report["capture_identity"]["app_label"] == "BBC News"


def test_ensure_features_capture_identity_creates_quality_block_when_missing() -> None:
    features: dict[str, object] = {}
    report = {"pcap_path": "artifacts/pcapdroid_capture/legacy_capture.pcap"}
    changed = ensure_features_capture_identity(
        features,
        dynamic_run_id="run-3",
        package_name="com.cnn.mobile.android.phone",
        app_label="CNN",
        report=report,
    )
    assert changed is True
    quality = features["quality"]
    assert isinstance(quality, dict)
    ident = quality["capture_identity"]
    assert ident["dynamic_run_id"] == "run-3"
    assert ident["package_slug"] == "com_cnn_mobile_android_phone"
    assert ident["pcap_capture_name"] == "legacy_capture.pcap"
