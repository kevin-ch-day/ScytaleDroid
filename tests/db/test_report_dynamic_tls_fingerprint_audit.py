from __future__ import annotations

from scripts.db import report_dynamic_tls_fingerprint_audit as report


def test_report_dynamic_tls_fingerprint_audit_help_is_safe(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_dynamic_tls_fingerprint_audit.py")
    assert "Read-only audit of TLS fingerprint population" in out
    assert "--recompute-top-values" in out


def test_find_pcap_path_supports_pcapng(tmp_path) -> None:
    capture_dir = tmp_path / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    pcapng = capture_dir / "capture.pcapng"
    pcapng.write_bytes(b"pcapng")

    assert report._find_pcap_path(tmp_path) == pcapng


def test_write_csv_can_emit_empty_schema(tmp_path) -> None:
    path = tmp_path / "fingerprint_recompute_mismatches.csv"

    report._write_csv(path, [], fieldnames=report.FINGERPRINT_RECOMPUTE_MISMATCH_FIELDS)

    assert path.read_text(encoding="utf-8").strip() == ",".join(report.FINGERPRINT_RECOMPUTE_MISMATCH_FIELDS)


def test_interpret_rollup_uses_service_families_observed() -> None:
    assert report._interpret_rollup(
        {
            "app_label": "Messaging App",
            "baseline_median_unique_ja4_count": 1,
            "interactive_median_unique_ja4_count": 1,
            "median_top_ja4_share": 0.9,
            "service_families_observed": "messaging, social_platform",
        }
    ) == "Low-volume messaging baseline with a small, stable encrypted-service stack."

    assert report._interpret_rollup(
        {
            "app_label": "Ad App",
            "baseline_median_unique_ja4_count": 2,
            "interactive_median_unique_ja4_count": 2,
            "median_top_ja4_share": 0.4,
            "service_families_observed": "adtech, analytics",
        }
    ) == "High fingerprint diversity consistent with adtech, analytics, and CDN-mediated traffic."
