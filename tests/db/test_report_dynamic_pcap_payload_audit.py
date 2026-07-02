from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_pcap_payload_audit as report


def test_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_pcap_payload_audit.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("usage:")
    assert "payload-surface audit" in proc.stdout


def test_sanitize_http_path_drops_query_and_token_segments() -> None:
    sanitized, path_class = report._sanitize_http_path(
        "/api/v1/user/1234567890/messages/abcdef1234567890abcdef?token=SECRET&email=a@example.com"
    )

    assert sanitized == "/api/v1/user/{id}/messages/{id}"
    assert path_class == "parameterized"
    assert "SECRET" not in sanitized
    assert "example.com" not in sanitized


def test_write_csv_writes_header_for_empty_rows(tmp_path: Path) -> None:
    path = tmp_path / "empty.csv"

    report._write_csv(path, [], fieldnames=report.HTTP_FIELDS)

    assert path.read_text(encoding="utf-8").strip() == ",".join(report.HTTP_FIELDS)


def test_iter_runs_uses_display_name_map_when_manifest_label_missing(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run-1"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    pcap = capture_dir / "capture.pcap"
    pcap.write_bytes(b"pcap")
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "target": {"package_name": "com.example.app"},
                "operator": {"run_profile": "baseline_idle"},
                "dataset": {"valid_dataset_run": True},
                "artifacts": [
                    {
                        "type": "pcapdroid_capture",
                        "relative_path": "artifacts/pcapdroid_capture/capture.pcap",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report, "_dynamic_root", lambda: tmp_path)
    monkeypatch.setattr(report, "_display_name_map", lambda _packages: {"com.example.app": "Example App"})

    rows = list(report._iter_runs([], []))

    assert rows[0]["app_label"] == "Example App"


def test_iter_runs_prefers_manifest_label_over_display_name_map(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run-1"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    pcap = capture_dir / "capture.pcap"
    pcap.write_bytes(b"pcap")
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "target": {"package_name": "com.example.app", "display_name": "Manifest App"},
                "operator": {"run_profile": "baseline_idle"},
                "dataset": {"valid_dataset_run": True},
                "artifacts": [
                    {
                        "type": "pcapdroid_capture",
                        "relative_path": "artifacts/pcapdroid_capture/capture.pcap",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report, "_dynamic_root", lambda: tmp_path)
    monkeypatch.setattr(report, "_display_name_map", lambda _packages: {"com.example.app": "DB App"})

    rows = list(report._iter_runs([], []))

    assert rows[0]["app_label"] == "Manifest App"


def test_app_rollup_summarizes_payload_visibility() -> None:
    run_rows = [
        {
            "package": "com.example",
            "app_label": "Example",
            "valid_dataset_run": 1,
            "pcap_bytes": 100,
            "payload_visibility_class": "encrypted_or_opaque_dominant",
            "http_frames": 0,
            "http_host_count": 0,
            "http_request_rows": 0,
            "http_response_rows": 0,
            "dns_frames": 2,
            "tls_frames": 5,
            "quic_frames": 0,
            "plaintext_protocol_frames": 0,
        },
        {
            "package": "com.example",
            "app_label": "Example",
            "valid_dataset_run": 0,
            "pcap_bytes": 50,
            "payload_visibility_class": "cleartext_surface_present",
            "http_frames": 1,
            "http_host_count": 1,
            "http_request_rows": 1,
            "http_response_rows": 0,
            "dns_frames": 1,
            "tls_frames": 0,
            "quic_frames": 0,
            "plaintext_protocol_frames": 1,
        },
    ]
    protocol_rows = [
        {"run_id": "run-1", "package": "com.example", "protocol": "tls", "frames": 5, "visibility": "encrypted_or_opaque"},
        {"run_id": "run-1", "package": "com.example", "protocol": "tls", "frames": 2, "visibility": "encrypted_or_opaque"},
        {"run_id": "run-2", "package": "com.example", "protocol": "http", "frames": 1, "visibility": "cleartext_protocol_decoded"},
    ]

    rows = report._app_rollup_rows(run_rows, protocol_rows)

    assert rows == [
        {
            "package": "com.example",
            "app_label": "Example",
            "runs_scanned": 2,
            "valid_dataset_runs": 1,
            "pcap_bytes_total": 150,
            "encrypted_or_opaque_runs": 1,
            "cleartext_surface_runs": 1,
            "http_observed_runs": 1,
            "http_hosts_total": 1,
            "http_request_rows": 1,
            "http_response_rows": 0,
            "dns_frames_total": 3,
            "tls_frames_total": 5,
            "quic_frames_total": 0,
            "plaintext_protocol_frames_total": 1,
            "plaintext_protocols_observed": "http",
            "decoded_cleartext_streams": 0,
            "top_protocols": "tls:5;http:1",
        }
    ]


def test_protocol_frame_counts_uses_max_for_nested_duplicate_protocols() -> None:
    rows = [
        {"protocol": "quic", "frames": 117},
        {"protocol": "quic", "frames": 6},
        {"protocol": "tls", "frames": 588},
        {"protocol": "tls", "frames": 179},
    ]

    assert report._protocol_frame_counts(rows) == {"quic": 117, "tls": 588}


def test_app_rollup_counts_bidirectional_tcp_cleartext_as_one_stream() -> None:
    run_rows = [
        {
            "package": "com.example",
            "app_label": "Example",
            "valid_dataset_run": 1,
            "pcap_bytes": 100,
            "payload_visibility_class": "cleartext_surface_present",
            "http_frames": 0,
            "http_host_count": 0,
            "http_request_rows": 0,
            "http_response_rows": 0,
            "dns_frames": 0,
            "tls_frames": 0,
            "quic_frames": 0,
            "plaintext_protocol_frames": 2,
        },
    ]
    decoded_rows = [
        {
            "package": "com.example",
            "protocol": "xmpp",
            "transport": "tcp",
            "src_port": "5222",
            "dst_port": "47004",
            "tcp_stream": "7",
        },
        {
            "package": "com.example",
            "protocol": "xmpp",
            "transport": "tcp",
            "src_port": "47004",
            "dst_port": "5222",
            "tcp_stream": "7",
        },
    ]

    rows = report._app_rollup_rows(run_rows, [], decoded_rows)

    assert rows[0]["decoded_cleartext_streams"] == 1


def test_decoded_cleartext_rows_aggregates_transport_context(tmp_path: Path, monkeypatch) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"pcap")

    def fake_run_cmd_timeout(_cmd, *, timeout):
        return (
            0,
            "raw:ip:tcp:xmpp\t147\t38672\t5222\t\t\t0\n"
            "raw:ip:tcp:xmpp\t81\t5222\t47004\t\t\t1\n",
            "",
        )

    monkeypatch.setattr(report, "_run_cmd_timeout", fake_run_cmd_timeout)

    rows = report._decoded_cleartext_rows(
        pcap,
        {"run_id": "run-1", "package": "com.example", "app_label": "Example"},
        [{"protocol": "xmpp", "frames": 2, "bytes": 228}],
        timeout=10,
    )

    assert rows == [
        {
            "run_id": "run-1",
            "package": "com.example",
            "app_label": "Example",
            "protocol": "xmpp",
            "transport": "tcp",
            "src_port": "38672",
            "dst_port": "5222",
            "tcp_stream": "0",
            "frames": 1,
            "bytes_total": 147,
            "bytes_min": 147,
            "bytes_max": 147,
        },
        {
            "run_id": "run-1",
            "package": "com.example",
            "app_label": "Example",
            "protocol": "xmpp",
            "transport": "tcp",
            "src_port": "5222",
            "dst_port": "47004",
            "tcp_stream": "1",
            "frames": 1,
            "bytes_total": 81,
            "bytes_min": 81,
            "bytes_max": 81,
        },
    ]
