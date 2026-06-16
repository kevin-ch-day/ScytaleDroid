from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_hidden_patterns as report


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_hidden_patterns.py"
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
    assert "hidden-pattern exports" in out


def _make_run(
    *,
    package: str,
    app_label: str,
    run_id: str,
    interaction_mode: str,
    valid_pack: bool,
    static_run_id: int,
    permissions_total: int,
    high_value_permission_count: int,
    uses_cleartext: bool,
    network_security_config_present: bool,
    allow_backup: bool = False,
    debuggable: bool = False,
    uses_webview: bool = False,
    static_endpoint_roots: list[str] | None = None,
    static_http_endpoint_roots: list[str] | None = None,
    service_rows: list[dict[str, object]] | None = None,
    signal_rows: list[dict[str, object]] | None = None,
    dynamic_domains: set[str] | None = None,
    visibility_loss_flag: bool = False,
    http_observed: bool = False,
) -> dict[str, object]:
    static_endpoint_roots = static_endpoint_roots or []
    static_http_endpoint_roots = static_http_endpoint_roots or []
    service_rows = service_rows or []
    signal_rows = signal_rows or []
    dynamic_domains = dynamic_domains or set()
    return {
        "package": package,
        "app_label": app_label,
        "run_id": run_id,
        "interaction_mode": interaction_mode,
        "valid_pack": valid_pack,
        "evidence_status": "valid" if valid_pack else "invalid",
        "static_plan": {
            "static_run_id": static_run_id,
            "static_features": {
                "permissions_total": permissions_total,
                "high_value_permission_count": high_value_permission_count,
                "uses_cleartext_traffic": uses_cleartext,
                "uses_webview": uses_webview,
            },
            "risk_flags": {
                "uses_cleartext_traffic": uses_cleartext,
                "network_security_config": network_security_config_present,
                "allow_backup": allow_backup,
                "debuggable": debuggable,
            },
            "exported_components": {
                "activities": ["A1", "A2", "A3", "A4", "A5", "A6"],
                "services": ["S1", "S2", "S3", "S4"],
                "receivers": ["R1", "R2", "R3"],
                "providers": ["P1", "P2"],
                "total": 15,
            },
            "network_targets": {
                "domain_sources": [
                    {"domain": domain, "scheme": "https"} for domain in static_endpoint_roots
                ]
                + [{"domain": domain, "scheme": "http"} for domain in static_http_endpoint_roots],
                "domains": static_endpoint_roots + static_http_endpoint_roots,
                "cleartext_domains": static_http_endpoint_roots if uses_cleartext else [],
            },
        },
        "pcap_report": {},
        "service_context": {},
        "service_signals": {},
        "dynamic_domains": dynamic_domains,
        "service_rows": service_rows,
        "signal_rows": signal_rows,
        "visibility_loss_flag": visibility_loss_flag,
        "http_observed": http_observed,
    }


def test_generate_report_exports_hidden_patterns_without_secret_values(tmp_path: Path, monkeypatch) -> None:
    package_alpha = "com.example.alpha"
    package_beta = "com.example.beta"
    package_gamma = "com.example.gamma"

    runs = [
        _make_run(
            package=package_alpha,
            app_label="Alpha",
            run_id="run-alpha-baseline",
            interaction_mode="baseline",
            valid_pack=True,
            static_run_id=1001,
            permissions_total=8,
            high_value_permission_count=1,
            uses_cleartext=False,
            network_security_config_present=True,
            static_endpoint_roots=["alpha.example.com", "cdn.alpha.example.com", "api.alpha.example.com"],
            static_http_endpoint_roots=["legacy.alpha.example.com"],
            service_rows=[
                {"service_key": "adtech_one", "owner_class": "third_party", "total_hits": 5},
                {"service_key": "adtech_two", "owner_class": "third_party", "total_hits": 4},
                {"service_key": "analytics_one", "owner_class": "third_party", "total_hits": 3},
                {"service_key": "alpha_first_party", "owner_class": "first_party", "total_hits": 2},
            ],
            signal_rows=[
                {"signal_key": "third_party_advertising"},
                {"signal_key": "third_party_analytics_measurement"},
            ],
            dynamic_domains={"ads.thirdparty.example", "metrics.thirdparty.example", "alpha.example.com"},
        ),
        _make_run(
            package=package_alpha,
            app_label="Alpha",
            run_id="run-alpha-manual",
            interaction_mode="manual",
            valid_pack=True,
            static_run_id=1001,
            permissions_total=8,
            high_value_permission_count=1,
            uses_cleartext=False,
            network_security_config_present=True,
            static_endpoint_roots=["alpha.example.com", "cdn.alpha.example.com", "api.alpha.example.com"],
            static_http_endpoint_roots=["legacy.alpha.example.com"],
            service_rows=[
                {"service_key": "adtech_one", "owner_class": "third_party", "total_hits": 6},
                {"service_key": "manual_cdn", "owner_class": "third_party", "total_hits": 3},
                {"service_key": "alpha_first_party", "owner_class": "first_party", "total_hits": 1},
            ],
            signal_rows=[
                {"signal_key": "third_party_advertising"},
            ],
            dynamic_domains={"ads.thirdparty.example", "metrics.thirdparty.example", "manual-only.example", "alpha.example.com"},
        ),
        _make_run(
            package=package_beta,
            app_label="Beta",
            run_id="run-beta-baseline",
            interaction_mode="baseline",
            valid_pack=True,
            static_run_id=1002,
            permissions_total=24,
            high_value_permission_count=3,
            uses_cleartext=True,
            network_security_config_present=False,
            allow_backup=True,
            debuggable=True,
            uses_webview=True,
            static_endpoint_roots=["api.beta.example.com", "config.beta.example.com", "AKIASECRETVALUE.beta.example.com"],
            static_http_endpoint_roots=["legacy.beta.example.com"],
            service_rows=[
                {"service_key": "beta_ads", "owner_class": "third_party", "total_hits": 7},
                {"service_key": "beta_measure", "owner_class": "third_party", "total_hits": 6},
            ],
            signal_rows=[
                {"signal_key": "third_party_advertising"},
                {"signal_key": "identity_or_tag_management"},
            ],
            dynamic_domains={"betaads.example", "betameasure.example"},
            visibility_loss_flag=True,
            http_observed=False,
        ),
        _make_run(
            package=package_gamma,
            app_label="Gamma",
            run_id="run-gamma-invalid",
            interaction_mode="baseline",
            valid_pack=False,
            static_run_id=1003,
            permissions_total=2,
            high_value_permission_count=0,
            uses_cleartext=False,
            network_security_config_present=True,
        ),
    ]

    monkeypatch.setattr(report, "_iter_dynamic_runs", lambda: runs)
    monkeypatch.setattr(
        report,
        "_load_static_finding_features",
        lambda run_ids: {
            1001: {
                "exported_without_permission_count": 3,
                "sdk_tracker_overlap_count": 0,
                "webview_indicator_count": 0,
                "pinning_indicator_present": 0,
            },
            1002: {
                "exported_without_permission_count": 2,
                "sdk_tracker_overlap_count": 2,
                "webview_indicator_count": 1,
                "pinning_indicator_present": 0,
            },
        },
    )
    monkeypatch.setattr(
        report,
        "_load_permission_features",
        lambda run_ids: {
            1001: {"custom_permission_count": 1, "dangerous_or_weak_custom_permission_count": 1},
            1002: {"custom_permission_count": 3, "dangerous_or_weak_custom_permission_count": 2},
        },
    )
    monkeypatch.setattr(
        report,
        "_load_provider_features",
        lambda packages: {
            package_alpha: {"provider_authority_count": 2, "grant_uri_permissions_count": 1},
            package_beta: {"provider_authority_count": 1, "grant_uri_permissions_count": 0},
        },
    )
    monkeypatch.setattr(
        report,
        "_load_string_endpoint_features",
        lambda run_ids: {
            1001: {
                "summary_endpoint_count": 4,
                "summary_http_count": 1,
                "sample_endpoint_roots": ["alpha.example", "thirdparty.example"],
                "sample_http_roots": ["alpha.example"],
            },
            1002: {
                "summary_endpoint_count": 4,
                "summary_http_count": 1,
                "sample_endpoint_roots": ["beta.example"],
                "sample_http_roots": ["beta.example"],
            },
        },
    )
    monkeypatch.setattr(report, "_dynamic_root", lambda: tmp_path / "dynamic")

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["apps_exported"] == 2
    assert summary["valid_dynamic_runs"] == 3
    assert summary["hidden_pattern_candidate_rows"] >= 3

    with (out_dir / "static_dynamic_join_summary.csv").open(encoding="utf-8") as handle:
        join_rows = list(csv.DictReader(handle))
    assert {row["package"] for row in join_rows} == {package_alpha, package_beta}
    alpha = next(row for row in join_rows if row["package"] == package_alpha)
    beta = next(row for row in join_rows if row["package"] == package_beta)
    assert alpha["dynamic_valid_run_count"] == "2"
    assert alpha["manual_only_domain_count"] == "1"
    assert alpha["third_party_service_hits"] == "21"
    assert beta["visibility_loss_flag"] == "True"

    with (out_dir / "component_exposure_summary.csv").open(encoding="utf-8") as handle:
        component_rows = list(csv.DictReader(handle))
    alpha_component = next(row for row in component_rows if row["package"] == package_alpha)
    assert alpha_component["exported_without_permission_count"] == "3"
    assert alpha_component["grant_uri_permissions_count"] == "1"

    with (out_dir / "network_security_policy_summary.csv").open(encoding="utf-8") as handle:
        network_rows = list(csv.DictReader(handle))
    beta_network = next(row for row in network_rows if row["package"] == package_beta)
    assert beta_network["uses_cleartext_traffic"] == "True"
    assert beta_network["http_like_static_endpoint_count"] == "1"

    with (out_dir / "hidden_pattern_candidates.csv").open(encoding="utf-8") as handle:
        candidate_rows = list(csv.DictReader(handle))
    keys = {(row["package"], row["pattern_key"]) for row in candidate_rows}
    assert (package_alpha, "few_permissions_many_third_party_services") in keys
    assert (package_alpha, "manual_only_provider_expansion") in keys
    assert (package_beta, "visibility_loss_present") in keys
    assert all(row["package"] != package_gamma for row in candidate_rows)

    all_text = "\n".join(path.read_text(encoding="utf-8") for path in out_dir.iterdir() if path.suffix in {".csv", ".json"})
    assert "AKIASECRETVALUE" not in all_text


def test_hidden_patterns_mark_many_static_endpoints_and_dynamic_only_domains(tmp_path: Path, monkeypatch) -> None:
    package = "com.example.delta"
    runs = [
        _make_run(
            package=package,
            app_label="Delta",
            run_id="run-delta-baseline",
            interaction_mode="baseline",
            valid_pack=True,
            static_run_id=1004,
            permissions_total=18,
            high_value_permission_count=0,
            uses_cleartext=False,
            network_security_config_present=True,
            static_endpoint_roots=[
                "one.delta.example",
                "two.delta.example",
                "three.delta.example",
                "four.delta.example",
                "five.delta.example",
                "six.delta.example",
                "seven.delta.example",
                "eight.delta.example",
                "nine.delta.example",
                "ten.delta.example",
                "eleven.delta.example",
                "twelve.delta.example",
            ],
            service_rows=[
                {"service_key": "delta_first_party", "owner_class": "first_party", "total_hits": 2},
            ],
            signal_rows=[],
            dynamic_domains={"one.delta.example", "runtime-only.delta.example", "config.delta.example"},
        ),
        _make_run(
            package=package,
            app_label="Delta",
            run_id="run-delta-manual",
            interaction_mode="manual",
            valid_pack=True,
            static_run_id=1004,
            permissions_total=18,
            high_value_permission_count=0,
            uses_cleartext=False,
            network_security_config_present=True,
            static_endpoint_roots=[
                "one.delta.example",
                "two.delta.example",
                "three.delta.example",
                "four.delta.example",
                "five.delta.example",
                "six.delta.example",
                "seven.delta.example",
                "eight.delta.example",
                "nine.delta.example",
                "ten.delta.example",
                "eleven.delta.example",
                "twelve.delta.example",
            ],
            service_rows=[
                {"service_key": "delta_first_party", "owner_class": "first_party", "total_hits": 2},
            ],
            signal_rows=[],
            dynamic_domains={"one.delta.example", "runtime-only.delta.example", "config.delta.example", "manual-only.delta.example"},
        ),
    ]
    monkeypatch.setattr(report, "_iter_dynamic_runs", lambda: runs)
    monkeypatch.setattr(report, "_load_static_finding_features", lambda run_ids: {1004: {}})
    monkeypatch.setattr(report, "_load_permission_features", lambda run_ids: {1004: {"custom_permission_count": 0, "dangerous_or_weak_custom_permission_count": 0}})
    monkeypatch.setattr(report, "_load_provider_features", lambda packages: {package: {"provider_authority_count": 0, "grant_uri_permissions_count": 0}})
    monkeypatch.setattr(report, "_load_string_endpoint_features", lambda run_ids: {1004: {"summary_endpoint_count": 12, "summary_http_count": 0, "sample_endpoint_roots": [], "sample_http_roots": []}})
    monkeypatch.setattr(report, "_dynamic_root", lambda: tmp_path / "dynamic")

    out_dir = tmp_path / "audit"
    report.generate_report(output_dir=out_dir)

    with (out_dir / "hidden_pattern_candidates.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    keys = {row["pattern_key"] for row in rows}
    assert "many_static_endpoints_few_observed_endpoints" in keys
    assert "observed_endpoints_absent_from_static_strings" in keys


def test_hidden_patterns_do_not_claim_dynamic_only_endpoints_when_static_endpoint_inventory_missing(tmp_path: Path, monkeypatch) -> None:
    package = "com.example.missing"
    runs = [
        _make_run(
            package=package,
            app_label="Missing",
            run_id="run-missing-baseline",
            interaction_mode="baseline",
            valid_pack=True,
            static_run_id=1005,
            permissions_total=12,
            high_value_permission_count=0,
            uses_cleartext=False,
            network_security_config_present=True,
            static_endpoint_roots=[],
            service_rows=[
                {"service_key": "measurement", "owner_class": "third_party", "total_hits": 4},
            ],
            signal_rows=[],
            dynamic_domains={"one.runtime.example", "two.runtime.example", "three.runtime.example"},
        )
    ]
    monkeypatch.setattr(report, "_iter_dynamic_runs", lambda: runs)
    monkeypatch.setattr(report, "_load_static_finding_features", lambda run_ids: {1005: {}})
    monkeypatch.setattr(report, "_load_permission_features", lambda run_ids: {1005: {"custom_permission_count": 0, "dangerous_or_weak_custom_permission_count": 0}})
    monkeypatch.setattr(report, "_load_provider_features", lambda packages: {package: {"provider_authority_count": 0, "grant_uri_permissions_count": 0}})
    monkeypatch.setattr(report, "_load_string_endpoint_features", lambda run_ids: {1005: {"summary_endpoint_count": 0, "summary_http_count": 0, "sample_endpoint_roots": [], "sample_http_roots": []}})
    monkeypatch.setattr(report, "_dynamic_root", lambda: tmp_path / "dynamic")

    out_dir = tmp_path / "audit"
    report.generate_report(output_dir=out_dir)

    with (out_dir / "hidden_pattern_candidates.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    keys = {row["pattern_key"] for row in rows}
    assert "observed_endpoints_absent_from_static_strings" not in keys

    with (out_dir / "static_dynamic_join_summary.csv").open(encoding="utf-8") as handle:
        join_rows = list(csv.DictReader(handle))
    row = next(row for row in join_rows if row["package"] == package)
    assert row["static_endpoint_root_count"] == "0"


def test_hidden_patterns_suppress_single_run_policy_and_privacy_noise(tmp_path: Path, monkeypatch) -> None:
    package = "com.example.single"
    runs = [
        _make_run(
            package=package,
            app_label="Single",
            run_id="run-single-baseline",
            interaction_mode="baseline",
            valid_pack=True,
            static_run_id=1006,
            permissions_total=40,
            high_value_permission_count=5,
            uses_cleartext=True,
            network_security_config_present=False,
            static_endpoint_roots=["single.example", "cdn.single.example", "ads.single.example"],
            static_http_endpoint_roots=["legacy.single.example", "legacy2.single.example"],
            service_rows=[
                {"service_key": "single_first_party", "owner_class": "first_party", "total_hits": 5},
                {"service_key": "ads_one", "owner_class": "third_party", "total_hits": 6},
                {"service_key": "ads_two", "owner_class": "third_party", "total_hits": 4},
            ],
            signal_rows=[{"signal_key": "third_party_advertising"}],
            dynamic_domains={"single.example", "ads.example", "cdn.example", "google.example"},
            http_observed=False,
        )
    ]
    monkeypatch.setattr(report, "_iter_dynamic_runs", lambda: runs)
    monkeypatch.setattr(
        report,
        "_load_static_finding_features",
        lambda run_ids: {
            1006: {
                "exported_without_permission_count": 30,
                "sdk_tracker_overlap_count": 1,
                "webview_indicator_count": 1,
                "pinning_indicator_present": 0,
            }
        },
    )
    monkeypatch.setattr(report, "_load_permission_features", lambda run_ids: {1006: {"custom_permission_count": 0, "dangerous_or_weak_custom_permission_count": 0}})
    monkeypatch.setattr(report, "_load_provider_features", lambda packages: {package: {"provider_authority_count": 0, "grant_uri_permissions_count": 0}})
    monkeypatch.setattr(
        report,
        "_load_string_endpoint_features",
        lambda run_ids: {
            1006: {
                "summary_endpoint_count": 4,
                "summary_http_count": 2,
                "sample_endpoint_roots": ["single.example"],
                "sample_http_roots": ["single.example"],
            }
        },
    )
    monkeypatch.setattr(report, "_dynamic_root", lambda: tmp_path / "dynamic")

    out_dir = tmp_path / "audit"
    report.generate_report(output_dir=out_dir)

    with (out_dir / "hidden_pattern_candidates.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    keys = {row["pattern_key"] for row in rows}
    assert "privacy_sensitive_static_tags_with_third_party_activation" not in keys
    assert "cleartext_allowed_not_observed" not in keys
    assert "exported_surface_with_broad_network_activation" not in keys
