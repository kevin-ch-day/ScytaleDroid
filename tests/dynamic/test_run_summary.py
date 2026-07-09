from __future__ import annotations

import json
from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.core.session import DynamicSessionResult
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.Utils.DisplayUtils import colors
from tests.dynamic._run_summary_support import blocked_result


def test_run_summary_smoke_blocked_plan_validation(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "plan.validation",
        "details": {
            "validation_result": "FAIL",
            "reasons": ["missing required fields: run_signature"],
            "warnings": [],
            "summary": {
                "reason_count": 1,
                "warning_count": 0,
                "mismatch_count": 0,
                "db_row_found": True,
                "has_static_link": True,
            },
        },
    }
    (notes_dir / "run_events.jsonl").write_text(json.dumps(payload) + "\n", encoding="utf-8")

    print_run_summary(blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation." in out
    assert "missing required fields: run_signature" in out


def test_run_summary_surfaces_media_plane_summary(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    (tmp_path / "run_manifest.json").write_text(
        json.dumps(
            {
                "operator": {"run_profile": "interaction_manual"},
                "target": {"package_name": "com.whatsapp", "display_name": "WhatsApp"},
                "dataset": {"valid_dataset_run": True, "countable": True, "min_pcap_bytes": 50000},
                "artifacts": [],
                "outputs": [],
                "observers": [],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 180.0,
                        "packet_count": 1000,
                        "data_size_bytes": 1000000,
                        "avg_packet_rate_pps": 5.5,
                        "data_byte_rate_bps": 120000,
                    }
                },
                "top_dns": [{"value": "api.whatsapp.net", "count": 4}],
                "top_sni": [{"value": "graph.whatsapp.com", "count": 3}],
                "media_plane": {
                    "status": "ok",
                    "summary": {
                        "classification": "relay_media_likely",
                        "rtc_sustained_session_count": 2,
                        "rtc_total_bytes": 623350,
                        "rtc_relay_peer_count": 2,
                        "relay_endpoint_count": 2,
                        "turn_allocate_success_count": 8,
                        "relay_endpoints": [{"ip": "157.240.146.35", "port": 3478}],
                        "dominant_udp_flow": {
                            "endpoint_a": "10.0.0.2:46485",
                            "endpoint_b": "157.240.146.35:3478",
                            "share_of_udp_bytes": 0.99,
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "proxies": {
                    "tls_ratio": 0.1,
                    "quic_ratio": 0.05,
                    "tcp_ratio": 0.1,
                    "udp_ratio": 0.9,
                    "unique_dns_topn": 1,
                    "unique_sni_topn": 1,
                    "unique_domains_topn": 2,
                },
                "media_plane": {
                    "status": "ok",
                    "summary": {
                        "classification": "relay_media_likely",
                        "rtc_sustained_session_count": 2,
                        "rtc_total_bytes": 623350,
                        "rtc_relay_peer_count": 2,
                        "relay_endpoint_count": 2,
                        "turn_allocate_success_count": 8,
                        "dominant_udp_flow": {"share_of_udp_bytes": 0.99},
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._dataset_quota_label", lambda *_a, **_k: "1/7")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._countability_detail", lambda *_a, **_k: "")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._three_verdict_label", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_db_persistence_status", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_summary", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_engine_summary", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary.prompt_utils.prompt_yes_no", lambda *_a, **_k: False)

    print_run_summary(
        DynamicSessionResult(
            package_name="com.whatsapp",
            duration_seconds=180,
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
            status="success",
            dynamic_run_id="run-1",
            evidence_path=str(tmp_path),
        ),
        "Cohort",
    )

    out = colors.strip(capsys.readouterr().out)
    assert "media: relay media likely rtc_sessions=2 rtc_bytes=608.7KB rtc_peers=2 relay_endpoints=2 dominant_udp=0.99 turn_alloc=8" in out
    assert "media: relay media likely | rtc_sessions=2 | rtc_bytes=608.7KB | rtc_peers=2 | relays=157.240.146.35:3478" in out


def test_run_summary_surfaces_manual_call_outcome(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    (tmp_path / "run_manifest.json").write_text(
        json.dumps(
            {
                "operator": {
                    "run_profile": "interaction_manual",
                    "interaction_level": "manual",
                    "messaging_activity": "video_call",
                    "call_type": "video",
                    "call_attempted": True,
                    "call_connected": False,
                    "call_outcome_reason": "CALL_NOT_CONNECTED",
                    "call_attempt_count": 3,
                    "call_connected_count": 1,
                    "call_not_connected_count": 2,
                    "call_canceled_count": 0,
                    "call_outcome_summary": "attempts=3;connected=1;not_connected=2;canceled=0",
                },
                "target": {"package_name": "com.facebook.orca", "display_name": "Messenger"},
                "dataset": {"valid_dataset_run": True, "countable": True, "min_pcap_bytes": 50000},
                "artifacts": [],
                "outputs": [],
                "observers": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._dataset_quota_label", lambda *_a, **_k: "3/7")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._countability_detail", lambda *_a, **_k: "")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._three_verdict_label", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_db_persistence_status", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_summary", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_engine_summary", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary.prompt_utils.prompt_yes_no", lambda *_a, **_k: False)

    print_run_summary(
        DynamicSessionResult(
            package_name="com.facebook.orca",
            duration_seconds=240,
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
            status="success",
            dynamic_run_id="run-manual-call",
            evidence_path=str(tmp_path),
        ),
        "Cohort",
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Messaging" in out and "Video Call" in out
    assert "video_call" not in out
    assert "Call type" in out and "video" in out
    assert "Call attempted" in out and "true" in out
    assert "Call connected" in out and "false" in out
    assert "Call outcome" in out and "CALL_NOT_CONNECTED" in out
    assert "Call attempts" in out and "3" in out
    assert "No-connect/ringing attempts" in out and "2" in out


def test_run_summary_displays_manual_messaging_tags_with_operator_labels(
    tmp_path, monkeypatch, capsys
) -> None:
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    (tmp_path / "run_manifest.json").write_text(
        json.dumps(
            {
                "operator": {
                    "run_profile": "interaction_manual",
                    "interaction_level": "manual",
                    "messaging_activity": "manual_mixed",
                },
                "target": {"package_name": "org.telegram.messenger", "display_name": "Telegram"},
                "dataset": {"valid_dataset_run": True, "countable": True, "min_pcap_bytes": 50000},
                "artifacts": [],
                "outputs": [],
                "observers": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._dataset_quota_label", lambda *_a, **_k: "4/7")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._countability_detail", lambda *_a, **_k: "")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._three_verdict_label", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_db_persistence_status", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_summary", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_engine_summary", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary.prompt_utils.prompt_yes_no", lambda *_a, **_k: False)

    print_run_summary(
        DynamicSessionResult(
            package_name="org.telegram.messenger",
            duration_seconds=240,
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
            status="success",
            dynamic_run_id="run-manual-mixed",
            evidence_path=str(tmp_path),
        ),
        "Cohort",
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Messaging" in out and "Mixed known activities" in out
    assert "manual_mixed" not in out


def test_run_summary_surfaces_runtime_surface_sequence(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    (tmp_path / "run_manifest.json").write_text(
        json.dumps(
            {
                "operator": {"run_profile": "interaction_manual", "interaction_level": "manual"},
                "target": {"package_name": "com.facebook.orca", "display_name": "Messenger"},
                "dataset": {"valid_dataset_run": True, "countable": True, "min_pcap_bytes": 50000},
                "artifacts": [],
                "outputs": [],
                "observers": [],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "analysis" / "summary.json").write_text(
        json.dumps(
            {
                "indicators": {
                    "runtime_surfaces": {
                        "labels": ["thread_surface", "rtc_call_video_surface"],
                        "primary_label": "thread_surface",
                        "primary_detail": "messenger conversation thread",
                        "transitions": [
                            {"elapsed_s": 10, "surface_label": "thread_surface"},
                            {"elapsed_s": 65, "surface_label": "rtc_call_video_surface"},
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._dataset_quota_label", lambda *_a, **_k: "4/7")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._countability_detail", lambda *_a, **_k: "")
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._three_verdict_label", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_db_persistence_status", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary._load_engine_summary", lambda *_a, **_k: None)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.run_summary.prompt_utils.prompt_yes_no", lambda *_a, **_k: False)

    print_run_summary(
        DynamicSessionResult(
            package_name="com.facebook.orca",
            duration_seconds=240,
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
            status="success",
            dynamic_run_id="run-surfaces",
            evidence_path=str(tmp_path),
        ),
        "Cohort",
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Runtime surfaces" in out
    assert "observed: thread_surface, rtc_call_video_surface" in out
    assert "primary: thread_surface (messenger conversation thread)" in out
    assert "sequence: 10s thread_surface -> 65s rtc_call_video_surface" in out
