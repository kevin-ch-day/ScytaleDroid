from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_paper_exports as report


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_paper_exports.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "paper-facing exports" in out


def test_generate_report_excludes_broken_pack_from_valid_summaries(tmp_path: Path, monkeypatch) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"

    valid_run = dynamic_root / "run-valid"
    _write_json(
        valid_run / "run_manifest.json",
        {
            "dynamic_run_id": "run-valid",
            "status": "completed",
            "target": {"package_name": "bbc.mobile.news.ww", "display_name": "BBC News"},
            "operator": {"run_profile": "interaction_manual", "interaction_level": "active"},
            "dataset": {"valid_dataset_run": True},
            "artifacts": [
                {
                    "relative_path": "artifacts/pcapdroid_capture/app.pcap",
                    "type": "pcapdroid_capture",
                    "produced_by": "pcapdroid_capture",
                }
            ],
        },
    )
    (valid_run / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (valid_run / "artifacts" / "pcapdroid_capture" / "app.pcap").write_bytes(b"pcap")
    _write_json(
        valid_run / "analysis" / "pcap_report.json",
        {
            "report_status": "ok",
            "protocol_hierarchy": [{"protocol": "tcp", "bytes": 10, "frames": 1}],
            "top_dns": [
                {"value": "bbc-global-app.api.bbc.com", "count": 4},
                {"value": "googleads.g.doubleclick.net", "count": 3},
            ],
            "top_sni": [],
            "service_context": {
                "observed_domain_count": 2,
                "service_count": 2,
                "unresolved_domain_count": 0,
                "services": [
                    {
                        "service_key": "bbc_first_party",
                        "service_display_name": "BBC First-Party Services",
                        "owner_name": "BBC",
                        "owner_class": "first_party",
                        "service_category": "publisher",
                        "total_hits": 4,
                        "domains": [{"domain": "bbc.com", "total_hits": 4}],
                    },
                    {
                        "service_key": "google_ads",
                        "service_display_name": "Google Ads / DoubleClick",
                        "owner_name": "Google",
                        "owner_class": "third_party",
                        "service_category": "adtech",
                        "total_hits": 3,
                        "domains": [{"domain": "doubleclick.net", "total_hits": 3}],
                    },
                ],
                "unresolved_domains": [],
            },
            "service_signals": {
                "signal_count": 2,
                "services_without_signal_mappings": [],
                "signals": [
                    {
                        "signal_key": "first_party_publisher_api",
                        "signal_family": "first_party_content",
                        "focus_area": "context",
                        "total_hits": 4,
                        "services": [{"domain": "bbc.com"}],
                    },
                    {
                        "signal_key": "third_party_advertising",
                        "signal_family": "advertising",
                        "focus_area": "privacy",
                        "total_hits": 3,
                        "services": [{"domain": "doubleclick.net"}],
                    },
                ],
            },
        },
    )
    _write_json(
        valid_run / "analysis" / "pcap_features.json",
        {
            "proxies": {
                "privacy_signal_hits": 3,
                "third_party_service_hits": 3,
            }
        },
    )

    broken_run = dynamic_root / "run-broken"
    _write_json(
        broken_run / "run_manifest.json",
        {
            "dynamic_run_id": "run-broken",
            "status": "completed",
            "target": {"package_name": "com.twitter.android", "display_name": "X (Twitter)"},
            "operator": {"run_profile": "baseline_idle", "interaction_level": "minimal"},
            "dataset": {"valid_dataset_run": False, "invalid_reason_code": "legacy_broken_pack"},
            "artifacts": [],
        },
    )
    _write_json(
        broken_run / "analysis" / "pcap_report.json",
        {
            "report_status": "skip",
            "protocol_hierarchy": [],
            "reason_codes": ["pcap_artifact_missing"],
            "service_context": {
                "observed_domain_count": 0,
                "service_count": 0,
                "unresolved_domain_count": 0,
                "services": [],
                "unresolved_domains": [],
            },
            "service_signals": {
                "signal_count": 0,
                "services_without_signal_mappings": [],
                "signals": [],
            },
        },
    )
    _write_json(broken_run / "analysis" / "pcap_features.json", {"proxies": {}})

    monkeypatch.setattr(report, "_dynamic_root", lambda: dynamic_root)
    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["runs_exported"] == 2
    assert summary["apps_exported"] == 2
    assert summary["valid_run_count"] == 1
    assert summary["invalid_or_skipped_pack_count"] == 1
    assert summary["unresolved_service_rows"] == 0
    assert summary["unresolved_signal_rows"] == 0

    with (out_dir / "per_run_summary.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert any(row["package"] == "bbc.mobile.news.ww" and row["valid_pack"] == "1" for row in rows)
    assert any(row["package"] == "com.twitter.android" and row["evidence_status"] == "legacy_broken_skipped" for row in rows)

    with (out_dir / "invalid_or_skipped_packs.csv").open(encoding="utf-8") as handle:
        invalid_rows = list(csv.DictReader(handle))
    assert len(invalid_rows) == 1
    assert invalid_rows[0]["package"] == "com.twitter.android"
    assert "recollect" in invalid_rows[0]["recommended_action"]

    with (out_dir / "per_app_summary.csv").open(encoding="utf-8") as handle:
        app_rows = list(csv.DictReader(handle))
    bbc = next(row for row in app_rows if row["package"] == "bbc.mobile.news.ww")
    xt = next(row for row in app_rows if row["package"] == "com.twitter.android")
    assert bbc["valid_run_count"] == "1"
    assert bbc["service_count"] == "2"
    assert bbc["signal_count"] == "3"
    assert xt["valid_run_count"] == "0"
    assert xt["skipped_or_invalid_run_count"] == "1"

    with (out_dir / "provider_signal_matrix.csv").open(encoding="utf-8") as handle:
        matrix_rows = list(csv.DictReader(handle))
    assert len(matrix_rows) == 1
    assert matrix_rows[0]["package"] == "bbc.mobile.news.ww"
    assert matrix_rows[0]["service__publisher"] == "4"
    assert matrix_rows[0]["signal__advertising"] == "3"


def test_generate_report_recomputes_service_context_from_top_indicators(tmp_path: Path, monkeypatch) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"

    run_dir = dynamic_root / "run-twitter"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-twitter",
            "status": "completed",
            "target": {"package_name": "com.twitter.android", "display_name": "X"},
            "operator": {"run_profile": "baseline_idle", "interaction_level": "minimal"},
            "dataset": {"valid_dataset_run": True},
            "artifacts": [
                {
                    "relative_path": "artifacts/pcapdroid_capture/app.pcap",
                    "type": "pcapdroid_capture",
                    "produced_by": "pcapdroid_capture",
                }
            ],
        },
    )
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "app.pcap").write_bytes(b"pcap")
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "ok",
            "protocol_hierarchy": [{"protocol": "tcp", "bytes": 10, "frames": 1}],
            "top_dns": [
                {"value": "api.x.com", "count": 4},
                {"value": "time.google.com", "count": 2},
            ],
            "top_sni": [
                {"value": "pbs.twimg.com", "count": 6},
            ],
            "service_context": {
                "observed_domain_count": 3,
                "service_count": 0,
                "unresolved_domain_count": 3,
                "services": [],
                "unresolved_domains": [
                    {"domain": "api.x.com", "root_domain": "x.com", "total_hits": 4},
                    {"domain": "pbs.twimg.com", "root_domain": "twimg.com", "total_hits": 6},
                    {"domain": "time.google.com", "root_domain": "google.com", "total_hits": 2},
                ],
            },
            "service_signals": {
                "signal_count": 0,
                "services_without_signal_mappings": [],
                "signals": [],
            },
        },
    )
    _write_json(run_dir / "analysis" / "pcap_features.json", {"proxies": {}})

    monkeypatch.setattr(report, "_dynamic_root", lambda: dynamic_root)
    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["unresolved_service_rows"] == 0
    assert summary["unresolved_signal_rows"] == 0
    assert summary["top_services_by_app"]["com.twitter.android"][0].startswith("x_media_cdn:")


def test_generate_report_recomputes_cnn_streaming_and_adtech_context(tmp_path: Path, monkeypatch) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"

    run_dir = dynamic_root / "run-cnn"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-cnn",
            "status": "completed",
            "target": {"package_name": "com.cnn.mobile.android.phone", "display_name": "CNN"},
            "operator": {"run_profile": "interaction_manual", "interaction_level": "active"},
            "dataset": {"valid_dataset_run": True},
            "artifacts": [
                {
                    "relative_path": "artifacts/pcapdroid_capture/app.pcap",
                    "type": "pcapdroid_capture",
                    "produced_by": "pcapdroid_capture",
                }
            ],
        },
    )
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "app.pcap").write_bytes(b"pcap")
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "ok",
            "protocol_hierarchy": [{"protocol": "tcp", "bytes": 10, "frames": 1}],
            "top_dns": [
                {"value": "out053a3bejgh7t0phqa0csou.litix.io", "count": 13},
                {"value": "bea4.v.fwmrm.net", "count": 10},
                {"value": "default.any-any.prd.api.discomax.com", "count": 4},
                {"value": "gpp-decoder.dianomi.workers.dev", "count": 4},
            ],
            "top_sni": [
                {"value": "cdn-media.brightline.tv", "count": 4},
                {"value": "top.warnermediacdn.com", "count": 4},
                {"value": "freeview.ngtv.io", "count": 8},
            ],
            "service_context": {
                "observed_domain_count": 7,
                "service_count": 0,
                "unresolved_domain_count": 7,
                "services": [],
                "unresolved_domains": [
                    {"domain": "out053a3bejgh7t0phqa0csou.litix.io", "root_domain": "litix.io", "total_hits": 13},
                    {"domain": "bea4.v.fwmrm.net", "root_domain": "fwmrm.net", "total_hits": 10},
                    {"domain": "default.any-any.prd.api.discomax.com", "root_domain": "discomax.com", "total_hits": 4},
                    {"domain": "gpp-decoder.dianomi.workers.dev", "root_domain": "workers.dev", "total_hits": 4},
                    {"domain": "cdn-media.brightline.tv", "root_domain": "brightline.tv", "total_hits": 4},
                    {"domain": "top.warnermediacdn.com", "root_domain": "warnermediacdn.com", "total_hits": 4},
                    {"domain": "freeview.ngtv.io", "root_domain": "ngtv.io", "total_hits": 8},
                ],
            },
            "service_signals": {
                "signal_count": 0,
                "services_without_signal_mappings": [],
                "signals": [],
            },
        },
    )
    _write_json(run_dir / "analysis" / "pcap_features.json", {"proxies": {}})

    monkeypatch.setattr(report, "_dynamic_root", lambda: dynamic_root)
    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["unresolved_service_rows"] == 0
    assert summary["unresolved_signal_rows"] == 0
    top_services = summary["top_services_by_app"]["com.cnn.mobile.android.phone"]
    assert any(item.startswith("mux_data:") for item in top_services)
    assert any(item.startswith("freewheel:") for item in top_services)
    assert any(item.startswith("wbd_streaming_platform:") for item in top_services)

    with (out_dir / "per_run_summary.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    row = rows[0]
    assert row["package"] == "com.cnn.mobile.android.phone"
    assert row["unresolved_service_count"] == "0"
    assert row["service_count"] == "5"

    with (out_dir / "per_app_service_summary.csv").open(encoding="utf-8") as handle:
        service_rows = list(csv.DictReader(handle))
    service_keys = {row["service_key"] for row in service_rows}
    assert {"mux_data", "freewheel", "wbd_streaming_platform", "dianomi", "brightline_ctv"} <= service_keys


def test_generate_report_separates_x_ads_from_platform_traffic(tmp_path: Path, monkeypatch) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"

    run_dir = dynamic_root / "run-twitter-ads"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-twitter-ads",
            "status": "completed",
            "target": {"package_name": "com.twitter.android", "display_name": "X"},
            "operator": {"run_profile": "baseline_idle", "interaction_level": "minimal"},
            "dataset": {"valid_dataset_run": True},
            "artifacts": [
                {
                    "relative_path": "artifacts/pcapdroid_capture/app.pcap",
                    "type": "pcapdroid_capture",
                    "produced_by": "pcapdroid_capture",
                }
            ],
        },
    )
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "app.pcap").write_bytes(b"pcap")
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "ok",
            "protocol_hierarchy": [{"protocol": "tcp", "bytes": 10, "frames": 1}],
            "top_dns": [
                {"value": "ads-api.x.com", "count": 4},
                {"value": "api.x.com", "count": 3},
                {"value": "time.google.com", "count": 2},
            ],
            "top_sni": [],
            "service_context": {
                "observed_domain_count": 3,
                "service_count": 0,
                "unresolved_domain_count": 3,
                "services": [],
                "unresolved_domains": [
                    {"domain": "ads-api.x.com", "root_domain": "x.com", "total_hits": 4},
                    {"domain": "api.x.com", "root_domain": "x.com", "total_hits": 3},
                    {"domain": "time.google.com", "root_domain": "google.com", "total_hits": 2},
                ],
            },
            "service_signals": {
                "signal_count": 0,
                "services_without_signal_mappings": [],
                "signals": [],
            },
        },
    )
    _write_json(run_dir / "analysis" / "pcap_features.json", {"proxies": {}})

    monkeypatch.setattr(report, "_dynamic_root", lambda: dynamic_root)
    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["unresolved_service_rows"] == 0
    assert summary["unresolved_signal_rows"] == 0

    with (out_dir / "per_app_service_summary.csv").open(encoding="utf-8") as handle:
        service_rows = list(csv.DictReader(handle))
    by_key = {row["service_key"]: row for row in service_rows}
    assert by_key["x_ads_platform"]["provider_or_owner"] == "X"
    assert by_key["x_ads_platform"]["role_or_category"] == "adtech"
    assert by_key["x_platform"]["role_or_category"] == "social_platform"
    assert by_key["google_platform"]["provider_or_owner"] == "Google"
