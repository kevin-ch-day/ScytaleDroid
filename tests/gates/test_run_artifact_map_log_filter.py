from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

import pytest

pytestmark = [pytest.mark.gate, pytest.mark.tier3]


def _load_run_artifact_map():
    path = Path(__file__).resolve().parents[2] / "scripts" / "static_analysis" / "run_artifact_map.py"
    spec = importlib.util.spec_from_file_location("run_artifact_map_audit", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_text_log_session_stamp_exact_match_avoids_prefix_collision() -> None:
    """``session_stamp=20260510-all-full`` must not match ``…-full-145`` in text logs."""

    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "static_analysis.log"
        log.write_text(
            "msg | event=report.saved, session_stamp=20260510-all-full, archive_path=/a\n"
            "msg | event=report.saved, session_stamp=20260510-all-full-145, archive_path=/b\n",
            encoding="utf-8",
        )
        missing_jsonl = Path(td) / "nope.jsonl"
        ev_full, src = mod._collect_report_saved_events(
            "20260510-all-full",
            jsonl_path=missing_jsonl,
            log_path=log,
        )
        ev_145, _ = mod._collect_report_saved_events(
            "20260510-all-full-145",
            jsonl_path=missing_jsonl,
            log_path=log,
        )

    assert src == "static_analysis.log"
    assert len(ev_full) == 1
    assert ev_full[0].get("archive_path") == "/a"
    assert len(ev_145) == 1
    assert ev_145[0].get("archive_path") == "/b"


def test_report_saved_path_rollup_unique_vs_raw_counts_duplicates() -> None:
    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        a = repo / "archive" / "a.json"
        b = repo / "archive" / "b.json"
        a.parent.mkdir(parents=True)
        a.write_text("{}", encoding="utf-8")
        b.write_text("{}", encoding="utf-8")
        sa = str(a.resolve())
        sb = str(b.resolve())
        events = [
            {"archive_path": sa, "event": "report.saved"},
            {"archive_path": sa, "event": "report.saved"},
            {"archive_path": sa, "event": "report.saved"},
            {"archive_path": sb, "event": "report.saved"},
            {"event": "report.saved"},
        ]
        rollup = mod._rollup_report_saved_archive_paths(events, repo=repo)

    assert rollup["raw_report_saved_event_count"] == 5
    assert rollup["unique_archive_path_count"] == 2
    assert rollup["duplicate_archive_path_count"] == 1
    assert rollup["duplicate_archive_event_extra_count"] == 2
    assert rollup["report_saved_events_missing_archive_path"] == 1
    assert rollup["duplicate_report_saved_events"] == 2
    assert any(s.get("event_count") == 3 for s in rollup["duplicate_archive_path_samples"])


def test_collect_permission_parity_generated_packages_from_jsonl() -> None:
    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "static_analysis.jsonl"
        rows = [
            {
                "event": "run.phase",
                "session_stamp": "sess-1",
                "phase": "permission_snapshot_parity",
                "status": "running",
                "report_source": "saved_report",
                "package_name": "com.example.reused",
            },
            {
                "event": "run.phase",
                "session_stamp": "sess-1",
                "phase": "permission_snapshot_parity",
                "status": "running",
                "report_source": "generated",
                "package_name": "com.example.changed",
                "app_label": "Changed",
                "app_index": 2,
                "app_total": 3,
                "ts": "2026-07-02T00:00:00+00:00",
            },
            {
                "event": "run.phase",
                "session_stamp": "other",
                "phase": "permission_snapshot_parity",
                "status": "running",
                "report_source": "generated",
                "package_name": "com.example.other",
            },
        ]
        log.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        generated = mod._collect_permission_parity_generated_packages(
            session="sess-1",
            jsonl_path=log,
        )

    assert generated == [
        {
            "package_name": "com.example.changed",
            "app_label": "Changed",
            "app_index": 2,
            "app_total": 3,
            "ts": "2026-07-02T00:00:00+00:00",
            "report_source": "generated",
        }
    ]


def test_strict_violations_ignore_raw_vs_unique_when_disk_aligns() -> None:
    mod = _load_run_artifact_map()
    report = {
        "selection_contract": {"artifact_count": 2, "group_count": 2, "present": True},
        "per_artifact_scanner_evidence": {
            "archived_json_count": 2,
            "raw_report_saved_event_count": 5,
            "unique_archive_path_count": 2,
            "report_saved_events_missing_archive_path": 0,
            "duplicate_archive_event_extra_count": 3,
        },
        "per_app_db_projection": {
            "available": True,
            "static_analysis_runs_by_status": {"COMPLETED": 2},
            "matrix_risk_mismatch_run_count": 0,
        },
        "post_run_diagnostics": {"persistence_audit": {"present": True}},
        "audit_options": {},
    }
    violations = mod._strict_violations(report)
    assert violations == []

    report_dup_strict = dict(report)
    report_dup_strict["audit_options"] = {"strict_log_duplicates": True}
    assert "duplicate_report_saved_events" in mod._strict_violations(report_dup_strict)


def test_finalize_report_keeps_evidence_status_ok_for_log_dup_only(tmp_path: Path) -> None:
    mod = _load_run_artifact_map()
    report = {
        "selection_contract": {"artifact_count": 2, "group_count": 2, "present": True},
        "per_artifact_scanner_evidence": {
            "archived_json_count": 2,
            "raw_report_saved_event_count": 5,
            "unique_archive_path_count": 2,
            "report_saved_events_missing_archive_path": 0,
            "duplicate_archive_event_extra_count": 3,
            "duplicate_archive_path_count": 1,
            "archive_paths_in_log_missing_on_disk": [],
            "archive_paths_on_disk_not_in_log_events": [],
            "bad_json_count": 0,
        },
        "latest_mirrors": {"duplicate_html_path_count_from_logs": 2},
        "per_app_db_projection": {
            "available": True,
            "static_analysis_runs_by_status": {"COMPLETED": 2},
            "matrix_risk_mismatch_run_count": 0,
        },
        "post_run_diagnostics": {"persistence_audit": {"present": True}},
        "audit_options": {},
        "harvest_linkage": {},
    }

    mod._finalize_artifact_envelope(
        report,
        repo=tmp_path,
        no_db=False,
        data_dir=tmp_path / "data",
        output_dir=tmp_path / "output",
        logs_dir=tmp_path / "logs",
        analysis_apk_root=tmp_path / "apk",
        app_version="test",
    )

    assert report["artifact_audit_verdict"]["evidence_status"] == "OK"
    assert report["artifact_audit_verdict"]["session_state"] == "COMPLETE_WITH_LOG_WARNINGS"
    assert report["artifact_audit_verdict"]["log_stream"]["log_duplication_without_evidence_gap"] is True


def test_finalize_report_marks_parity_explained_log_duplicates_complete(tmp_path: Path) -> None:
    mod = _load_run_artifact_map()
    report = {
        "selection_contract": {"artifact_count": 2, "group_count": 2, "present": True},
        "per_artifact_scanner_evidence": {
            "archived_json_count": 2,
            "raw_report_saved_event_count": 3,
            "unique_archive_path_count": 2,
            "report_saved_events_missing_archive_path": 0,
            "duplicate_archive_event_extra_count": 1,
            "duplicate_archive_path_count": 1,
            "duplicate_archive_path_samples": [
                {
                    "event_count": 2,
                    "archive_path_repo_relative": "data/static_analysis/reports/archive/sess/a.json",
                    "package_names": ["com.example.changed"],
                }
            ],
            "archive_paths_in_log_missing_on_disk": [],
            "archive_paths_on_disk_not_in_log_events": [],
            "bad_json_count": 0,
        },
        "latest_mirrors": {"duplicate_html_path_count_from_logs": 1},
        "permission_audit_directory": {
            "changed_parity_packages": [{"package_name": "com.example.changed"}],
        },
        "per_app_db_projection": {
            "available": True,
            "static_analysis_runs_by_status": {"COMPLETED": 2},
            "matrix_risk_mismatch_run_count": 0,
        },
        "post_run_diagnostics": {"persistence_audit": {"present": True}},
        "audit_options": {},
        "harvest_linkage": {},
    }

    mod._finalize_artifact_envelope(
        report,
        repo=tmp_path,
        no_db=False,
        data_dir=tmp_path / "data",
        output_dir=tmp_path / "output",
        logs_dir=tmp_path / "logs",
        analysis_apk_root=tmp_path / "apk",
        app_version="test",
    )

    verdict = report["artifact_audit_verdict"]
    explanation = verdict["log_stream"]["duplicate_explanation"]
    assert verdict["evidence_status"] == "OK"
    assert verdict["session_state"] == "COMPLETE_WITH_EXPLAINED_LOG_DUPLICATES"
    assert verdict["action_needed"] == "none"
    assert explanation["status"] == "explained"
    assert explanation["reason"] == "permission_snapshot_parity_regenerated_reports"
    assert report["warnings"] == []


def test_strict_violations_does_not_raise_on_non_numeric_counts() -> None:
    mod = _load_run_artifact_map()
    report = {
        "selection_contract": {"artifact_count": 1, "group_count": 1, "present": True},
        "per_artifact_scanner_evidence": {
            "archived_json_count": "not-an-int",
            "unique_archive_path_count": 1,
            "report_saved_events_missing_archive_path": "also-bad",
            "duplicate_archive_event_extra_count": None,
        },
        "per_app_db_projection": {"available": False},
        "post_run_diagnostics": {"persistence_audit": {"present": True}},
        "audit_options": {},
    }
    violations = mod._strict_violations(report)
    assert isinstance(violations, list)


def test_evidence_invariant_summary_warns_when_counts_mismatch() -> None:
    mod = _load_run_artifact_map()
    report = {
        "selection_contract": {"artifact_count": 100},
        "per_artifact_scanner_evidence": {
            "archived_json_count": 50,
            "unique_archive_path_count": 50,
            "raw_report_saved_event_count": 50,
            "duplicate_archive_event_extra_count": 0,
            "archive_paths_in_log_missing_on_disk": [],
            "archive_paths_on_disk_not_in_log_events": [],
            "bad_json_count": 0,
            "report_saved_events_missing_archive_path": 0,
        },
    }
    summary = mod._build_evidence_invariant_summary(report)
    assert summary["evidence_result"] == "WARN"
    assert summary["evidence_invariant_holds"] is False
    assert summary["log_result"] == "OK"


def test_harvest_apk_meta_sidecar_path_matches_double_suffix_convention() -> None:
    mod = _load_run_artifact_map()
    apk = Path("/tmp/pkg__base.apk")
    assert mod._harvest_apk_meta_sidecar_path(apk) == Path("/tmp/pkg__base.apk.meta.json")


def test_harvest_linkage_counts_adjacent_meta_beside_device_apks_path() -> None:
    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        rel = Path("data/device_apks/ZY123/runs/sess-1/com.example__base.apk")
        apk = repo / rel
        apk.parent.mkdir(parents=True)
        apk.write_bytes(b"PK\x03\x04")
        sidecar = mod._harvest_apk_meta_sidecar_path(apk)
        sidecar.write_text("{}", encoding="utf-8")
        selection = {
            "apps": [
                {
                    "package_name": "com.example",
                    "capture_id": "cap",
                    "artifacts": [rel.as_posix()],
                }
            ]
        }
        hl = mod._harvest_linkage_from_selection(selection, repo=repo)
    assert hl.get("skipped") is False
    assert hl["apk_meta_sidecars_found"] == 1
    assert hl["apk_paths_resolving_to_content_store"] == 0
    assert not (hl.get("harvest_meta_sidecar_note") or "").strip()


def test_harvest_linkage_notes_missing_adjacent_meta_for_sha256_store_paths() -> None:
    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        rel = Path("data/store/apk/sha256/ab/cafebabe0123456789abcdef0123456789abcdef0123456789abcdef01234567.apk")
        apk = repo / rel
        apk.parent.mkdir(parents=True)
        apk.write_bytes(b"PK\x03\x04")
        selection = {
            "apps": [
                {
                    "package_name": "com.example",
                    "capture_id": "cap",
                    "artifacts": [rel.as_posix()],
                }
            ]
        }
        hl = mod._harvest_linkage_from_selection(selection, repo=repo)
    assert hl.get("skipped") is False
    assert hl["apk_meta_sidecars_found"] == 0
    assert hl["apk_paths_resolving_to_content_store"] == 1
    assert "device_apks" in (hl.get("harvest_meta_sidecar_note") or "")
    assert "sha256" in (hl.get("harvest_meta_sidecar_note") or "")


def test_harvest_receipt_enrichment_maps_store_path_to_pull_meta() -> None:
    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        canon_rel = Path("data/store/apk/sha256/ab/cafebabe0123456789abcdef0123456789abcdef0123456789abcdef01234567.apk")
        canon = repo / canon_rel
        canon.parent.mkdir(parents=True)
        canon.write_bytes(b"PK\x03\x04")

        pull_rel = Path("ZY1/runs/run-a/com.example.app/v1/base.apk")
        dapk = repo / "data" / "device_apks"
        pull = dapk / pull_rel
        pull.parent.mkdir(parents=True)
        pull.write_bytes(b"PK\x03\x04")
        mod._harvest_apk_meta_sidecar_path(pull).write_text("{}", encoding="utf-8")
        (pull.parent / "harvest_package_manifest.json").write_text('{"schema": "harvest_package_manifest_v1"}', encoding="utf-8")

        rec_root = repo / "data" / "receipts" / "harvest"
        sess = rec_root / "static-sess"
        sess.mkdir(parents=True)
        receipt = {
            "execution": {
                "observed_artifacts": [
                    {
                        "canonical_store_path": canon_rel.as_posix(),
                        "local_artifact_path": pull_rel.as_posix(),
                    }
                ]
            }
        }
        (sess / "com.example.app.json").write_text(json.dumps(receipt), encoding="utf-8")

        selection = {
            "session_stamp": "static-sess",
            "apps": [
                {
                    "package_name": "com.example.app",
                    "capture_id": "cap",
                    "artifacts": [canon_rel.as_posix()],
                }
            ],
        }
        rmap, rstats = mod._harvest_receipt_canonical_to_pull_map(
            selection,
            repo=repo,
            receipts_root=rec_root,
            device_apks_root=dapk,
        )
        assert rstats["receipt_json_files_opened"] >= 1
        assert rstats["indexed_observed_rows"] >= 1
        assert rstats.get("receipt_session_resolution") == "selection_session_stamp_directory"
        assert int(rstats.get("indexed_unique_canonical_paths") or 0) == 1
        hl = mod._harvest_linkage_from_selection(
            selection,
            repo=repo,
            receipt_pull_by_canonical=rmap,
            receipt_scan_stats=rstats,
        )
    rpe = hl.get("receipt_pull_enrichment") or {}
    assert rpe.get("receipt_pull_meta_sidecars_found") == 1
    assert rpe.get("receipt_pull_apk_files_on_disk") == 1
    assert rpe.get("receipt_pull_harvest_manifest_nearby") == 1
    assert rpe.get("apk_paths_with_receipt_pull_mapping") == 1
    assert rpe.get("unmapped_content_store_path_samples") == []


def test_harvest_receipt_map_detects_pull_path_collisions() -> None:
    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        canon_rel = Path("data/store/apk/sha256/ab/cafebabe0123456789abcdef0123456789abcdef0123456789abcdef01234567.apk")
        (repo / canon_rel).parent.mkdir(parents=True)
        (repo / canon_rel).write_bytes(b"PK")
        dapk = repo / "data" / "device_apks"
        pull_a = dapk / "ZY1/runs/r1/pkg/a.apk"
        pull_b = dapk / "ZY1/runs/r1/pkg/b.apk"
        pull_a.parent.mkdir(parents=True)
        pull_a.write_bytes(b"PK")
        pull_b.write_bytes(b"PK")
        rec_root = repo / "data" / "receipts" / "harvest" / "sess"
        rec_root.mkdir(parents=True)
        receipt = {
            "execution": {
                "observed_artifacts": [
                    {
                        "canonical_store_path": canon_rel.as_posix(),
                        "local_artifact_path": "ZY1/runs/r1/pkg/a.apk",
                    },
                    {
                        "canonical_store_path": canon_rel.as_posix(),
                        "local_artifact_path": "ZY1/runs/r1/pkg/b.apk",
                    },
                ]
            }
        }
        (rec_root / "com.example.app.json").write_text(json.dumps(receipt), encoding="utf-8")
        selection = {
            "session_stamp": "sess",
            "apps": [{"package_name": "com.example.app", "capture_id": "c", "artifacts": [canon_rel.as_posix()]}],
        }
        _, rstats = mod._harvest_receipt_canonical_to_pull_map(
            selection, repo=repo, receipts_root=rec_root.parent, device_apks_root=dapk
        )
    assert int(rstats.get("canonical_pull_path_collisions") or 0) == 1
    assert int(rstats.get("indexed_observed_rows") or 0) == 2
    assert int(rstats.get("indexed_unique_canonical_paths") or 0) == 1


def test_harvest_receipt_unmapped_store_paths_surface_samples() -> None:
    mod = _load_run_artifact_map()
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        canon1 = Path("data/store/apk/sha256/ab/aaa1111111111111111111111111111111111111111111111111111111111111.apk")
        canon2 = Path("data/store/apk/sha256/cd/bbb2222222222222222222222222222222222222222222222222222222222222.apk")
        for rel in (canon1, canon2):
            p = repo / rel
            p.parent.mkdir(parents=True)
            p.write_bytes(b"PK")
        dapk = repo / "data" / "device_apks"
        pull = dapk / "ZY1/runs/r1/pkg/x.apk"
        pull.parent.mkdir(parents=True)
        pull.write_bytes(b"PK")
        rec_root = repo / "data" / "receipts" / "harvest" / "sess2"
        rec_root.mkdir(parents=True)
        receipt = {
            "execution": {
                "observed_artifacts": [
                    {
                        "canonical_store_path": canon1.as_posix(),
                        "local_artifact_path": "ZY1/runs/r1/pkg/x.apk",
                    }
                ]
            }
        }
        (rec_root / "com.foo.json").write_text(json.dumps(receipt), encoding="utf-8")
        selection = {
            "session_stamp": "sess2",
            "apps": [
                {
                    "package_name": "com.foo",
                    "capture_id": "c",
                    "artifacts": [canon1.as_posix(), canon2.as_posix()],
                }
            ],
        }
        rmap, rstats = mod._harvest_receipt_canonical_to_pull_map(
            selection, repo=repo, receipts_root=rec_root.parent, device_apks_root=dapk
        )
        hl = mod._harvest_linkage_from_selection(
            selection, repo=repo, receipt_pull_by_canonical=rmap, receipt_scan_stats=rstats
        )
    samples = (hl.get("receipt_pull_enrichment") or {}).get("unmapped_content_store_path_samples") or []
    assert len(samples) == 1
    assert "bbb2222222222222222222222222222222222222222222222222222222222222" in samples[0]


def test_receipt_linkage_incomplete_audit_warns_when_under_mapped() -> None:
    mod = _load_run_artifact_map()
    audit_opts = {"include_harvest_receipt_linkage": True}
    hl = {
        "skipped": False,
        "apk_paths_resolving_to_content_store": 5,
        "receipt_pull_enrichment": {
            "receipt_json_files_opened": 2,
            "apk_paths_with_receipt_pull_mapping": 2,
        },
    }
    inc, lines = mod._harvest_receipt_linkage_incomplete_audit(audit_opts, hl)
    assert inc is True
    assert lines and "2/5" in lines[0]


def test_receipt_linkage_incomplete_audit_warns_when_no_receipts_read() -> None:
    mod = _load_run_artifact_map()
    audit_opts = {"include_harvest_receipt_linkage": True}
    hl = {
        "skipped": False,
        "apk_paths_resolving_to_content_store": 3,
        "receipt_pull_enrichment": {"receipt_json_files_opened": 0, "apk_paths_with_receipt_pull_mapping": 0},
    }
    inc, lines = mod._harvest_receipt_linkage_incomplete_audit(audit_opts, hl)
    assert inc is True
    assert any("no harvest receipt" in x.lower() for x in lines)


def test_receipt_linkage_incomplete_audit_ok_when_fully_mapped() -> None:
    mod = _load_run_artifact_map()
    audit_opts = {"include_harvest_receipt_linkage": True}
    hl = {
        "skipped": False,
        "apk_paths_resolving_to_content_store": 4,
        "receipt_pull_enrichment": {
            "receipt_json_files_opened": 1,
            "apk_paths_with_receipt_pull_mapping": 4,
        },
    }
    assert mod._harvest_receipt_linkage_incomplete_audit(audit_opts, hl) == (False, [])
