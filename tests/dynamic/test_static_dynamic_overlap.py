from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import RunManifest
from scytaledroid.DynamicAnalysis.pcap.correlate import write_static_dynamic_overlap


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_write_static_dynamic_overlap_reports_actionable_and_pair_corroboration(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "top_dns": [{"value": "google.com", "count": 3}],
            "top_sni": [{"value": "cdn.example.com", "count": 1}],
        },
    )
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "network_targets": {
                "domains": ["google.com", "docs.example.org"],
                "cleartext_domains": [],
                "domain_sources": [
                    {
                        "domain": "google.com",
                        "sources": ["strings"],
                        "postures": ["actionable"],
                        "ownership_classes": ["unknown_third_party"],
                        "pair_groups": ["google:token_endpoint_family"],
                        "api_contexts": ["auth_flow"],
                        "verification_statuses": ["supported_opt_in"],
                        "buckets": ["api_keys", "endpoints"],
                    },
                    {
                        "domain": "docs.example.org",
                        "sources": ["strings", "nsc"],
                        "postures": ["exploratory"],
                        "ownership_classes": ["documentary"],
                        "pair_groups": [],
                        "api_contexts": [],
                        "verification_statuses": [],
                        "buckets": ["endpoints"],
                    },
                ],
            }
        },
    )
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        target={"package_name": "com.example.app", "static_plan_path": "inputs/static_dynamic_plan.json"},
    )

    artifact = write_static_dynamic_overlap(manifest, run_dir)

    assert artifact is not None
    payload = json.loads((run_dir / "analysis" / "static_dynamic_overlap.json").read_text(encoding="utf-8"))
    assert payload["overlap_count"] == 1
    assert payload["actionable_static_domains_count"] == 1
    assert payload["actionable_overlap_count"] == 1
    assert payload["actionable_overlap_ratio"] == 1.0
    assert payload["corroborated_pair_groups"] == ["google:token_endpoint_family"]
    assert payload["overlap_by_posture"]["actionable"]["overlap_count"] == 1
    assert payload["overlap_by_ownership"]["unknown_third_party"]["overlap_count"] == 1
    assert payload["overlap_by_source"]["strings"]["overlap_count"] == 1
