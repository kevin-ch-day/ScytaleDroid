from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest


def test_sealed_manifest_cannot_be_rewritten(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-08-13T00:00:00Z",
        status="success",
    )
    manifest.finalize()
    path = writer.write_manifest(manifest)
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(RuntimeError, match="sealed manifest"):
        writer.write_manifest(manifest)

    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert path.read_bytes().endswith(b"\n")
    assert not list(tmp_path.glob(".run_manifest.json.tmp.*"))


def test_manifest_seal_does_not_clobber_concurrent_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-race",
        created_at="2026-08-16T00:00:00Z",
        status="success",
    )
    winner = b'{"dynamic_run_id":"winner"}\n'
    real_link = os.link

    def _publish_winner_then_link(source: Path, destination: Path) -> None:
        Path(destination).write_bytes(winner)
        real_link(source, destination)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.evidence_pack.os.link",
        _publish_winner_then_link,
    )

    with pytest.raises(RuntimeError, match="sealed manifest"):
        writer.write_manifest(manifest)

    assert (tmp_path / "run_manifest.json").read_bytes() == winner
    assert not list(tmp_path.glob(".run_manifest.json.tmp.*"))


def test_manifest_seal_success_is_not_masked_by_temp_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-cleanup",
        created_at="2026-08-16T00:00:00Z",
        status="success",
    )
    real_unlink = Path.unlink

    def _fail_temp_cleanup(path: Path, *args, **kwargs) -> None:
        if path.name.startswith(".run_manifest.json.tmp."):
            raise PermissionError("simulated cleanup failure")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", _fail_temp_cleanup)

    sealed = writer.write_manifest(manifest)

    assert sealed == tmp_path / "run_manifest.json"
    assert sealed.exists()


@pytest.mark.parametrize("relative_path", ["../outside.json", "/tmp/outside.json", "."])
def test_evidence_writer_rejects_paths_outside_run(
    tmp_path: Path,
    relative_path: str,
) -> None:
    run_dir = tmp_path / "run"
    writer = EvidencePackWriter(run_dir)
    writer.ensure_layout()

    with pytest.raises(ValueError, match="must remain inside run directory"):
        writer.write_json(relative_path, {"unsafe": True})

    assert not (tmp_path / "outside.json").exists()


def test_evidence_writer_uses_complete_newline_terminated_json(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()

    path = writer.write_json("analysis/result.json", {"status": "complete"})

    assert path.read_text(encoding="utf-8") == '{\n  "status": "complete"\n}\n'
    assert not list(path.parent.glob(f".{path.name}.tmp.*"))


def _sealed_pack(tmp_path: Path, run_id: str = "run-anchor") -> tuple[EvidencePackWriter, RunManifest, Path]:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    writer.write_json("analysis/summary.json", {"status": "ok"})
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id=run_id,
        created_at="2026-11-01T00:00:00Z",
        status="success",
    )
    manifest.finalize()
    path = writer.write_manifest(manifest)
    return writer, manifest, path


def test_seal_anchors_manifest_bytes_outside_the_inventory(tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.core.sealing_v2 import (
        MANIFEST_ANCHOR,
        MANIFEST_ANCHORED,
        classify_manifest_anchor,
        verify_inventory,
    )

    _writer, _manifest, path = _sealed_pack(tmp_path)
    anchor = tmp_path / MANIFEST_ANCHOR
    assert anchor.read_text(encoding="utf-8") == (
        hashlib.sha256(path.read_bytes()).hexdigest() + "  run_manifest.json\n"
    )
    assert classify_manifest_anchor(tmp_path)["classification"] == MANIFEST_ANCHORED
    integrity = json.loads(path.read_text(encoding="utf-8"))["evidence_integrity"]
    assert "run_manifest.sha256" not in {row["relative_path"] for row in integrity["files"]}
    result = verify_inventory(tmp_path, integrity)
    assert result["valid"], result["issues"]


def test_post_seal_manifest_rewrite_is_detected(tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.core.sealing_v2 import (
        MANIFEST_REWRITTEN_AFTER_SEAL,
        classify_manifest_anchor,
        integrity_grade_reasons,
    )
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import (
        verify_dynamic_evidence_packs,
    )

    root = tmp_path / "root"
    run_dir = root / "run-rewrite"
    _writer, _manifest, path = _sealed_pack(run_dir, run_id="run-rewrite")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = "tampered"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    assert classify_manifest_anchor(run_dir)["classification"] == MANIFEST_REWRITTEN_AFTER_SEAL
    reasons = integrity_grade_reasons(run_dir, payload["evidence_integrity"])
    assert any(r["detail"] == "manifest_anchor:" + MANIFEST_REWRITTEN_AFTER_SEAL for r in reasons)
    report = verify_dynamic_evidence_packs(root)
    codes = {issue["code"] for issue in report["runs"][0]["issues"]}
    assert "manifest_rewritten_after_seal" in codes


def test_packs_sealed_before_anchoring_are_classified_legacy_not_failed(tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.core.sealing_v2 import (
        LEGACY_EXCLUDED,
        LEGACY_MANIFEST_UNHASHED,
        MANIFEST_ANCHOR,
        classify_manifest_anchor,
        integrity_grade_reasons,
        verify_inventory,
    )
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import (
        verify_dynamic_evidence_packs,
    )

    root = tmp_path / "root"
    run_dir = root / "run-legacy"
    _writer, _manifest, path = _sealed_pack(run_dir, run_id="run-legacy")
    # Reproduce a pre-anchor seal: no sidecar and the legacy exclusion set.
    (run_dir / MANIFEST_ANCHOR).unlink()
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["evidence_integrity"]["scope_exclusions"] = LEGACY_EXCLUDED
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    assert classify_manifest_anchor(run_dir)["classification"] == LEGACY_MANIFEST_UNHASHED
    result = verify_inventory(run_dir, payload["evidence_integrity"])
    assert result["valid"], result["issues"]
    # Legacy anchoring is a classification; only byte/inventory failures grade down.
    assert not [
        r for r in integrity_grade_reasons(run_dir, payload["evidence_integrity"])
        if r["code"] == "evidence_integrity_v2_failed"
    ]
    report = verify_dynamic_evidence_packs(root)
    codes = [issue["code"] for issue in report["runs"][0]["issues"]]
    assert "legacy_manifest_unhashed" in codes
    assert "manifest_rewritten_after_seal" not in codes


def test_reseal_records_provenance_and_renews_the_anchor(tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.core.sealing_v2 import (
        MANIFEST_ANCHORED,
        classify_manifest_anchor,
        verify_inventory,
    )

    writer, manifest, path = _sealed_pack(tmp_path, run_id="run-reseal")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="Sealed evidence pack"):
        writer.write_json("analysis/extra.json", {"after": "seal"})
    sidecar = tmp_path / "analysis" / "extra.json"
    sidecar.write_text("{}\n", encoding="utf-8")
    manifest.outputs.append(
        ArtifactRecord(
            relative_path="analysis/extra.json", type="derived", produced_by="repair",
            origin="host", pull_status="n/a",
        )
    )
    writer.reseal(manifest, reason="unit test repair", tool="test")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["reseal_history"][0]["previous_manifest_sha256"] == before
    assert payload["reseal_history"][0]["tool"] == "test"
    assert payload["sealed_by"].endswith("reseal:test")
    assert classify_manifest_anchor(tmp_path)["classification"] == MANIFEST_ANCHORED
    history = (tmp_path / "notes" / "reseal_history.jsonl").read_text(encoding="utf-8")
    assert json.loads(history.splitlines()[0])["reason"] == "unit test repair"
    result = verify_inventory(tmp_path, payload["evidence_integrity"])
    assert result["valid"], result["issues"]
    assert "notes/reseal_history.jsonl" in {r["relative_path"] for r in payload["evidence_integrity"]["files"]}


def test_refresh_script_refuses_sealed_packs_unless_reseal(tmp_path: Path) -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(
        "refresh_analysis_summaries",
        Path(__file__).resolve().parents[2] / "scripts" / "dynamic" / "refresh_analysis_summaries.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    root = tmp_path / "root"
    run_dir = root / "run-refresh"
    _writer, _manifest, path = _sealed_pack(run_dir, run_id="run-refresh")
    before = path.read_bytes()

    refused = module.refresh_summaries(root=root, apply=True)
    assert refused["sealed_packs_refused"] == ["run-refresh"]
    assert refused["runs_updated"] == 0
    assert path.read_bytes() == before

    dry = module.refresh_summaries(root=root, apply=False)
    assert dry["sealed_packs_refused"] == []
    assert path.read_bytes() == before


def test_run_markers_dep_plan_and_security_outputs_carry_complete_provenance(tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.core.orchestrator import DynamicRunOrchestrator
    from scytaledroid.DynamicAnalysis.core.sealing_v2 import seal_inventory

    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    (tmp_path / "analysis" / "security_surface.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "analysis" / "security_review.md").write_text("# review\n", encoding="utf-8")
    records = DynamicRunOrchestrator._security_surface_artifacts(tmp_path)
    assert [(r.relative_path, r.type, r.produced_by, r.origin, r.pull_status) for r in records] == [
        ("analysis/security_surface.json", "security_surface", "pcap_report", "host", "n/a"),
        ("analysis/security_review.md", "security_review", "pcap_report", "host", "n/a"),
    ]
    manifest = RunManifest(
        run_manifest_version=1, dynamic_run_id="run-prov", created_at="2026-11-01T00:00:00Z",
        status="success",
    )
    manifest.outputs.extend(records)
    inventory = seal_inventory(tmp_path, manifest)
    rows = {row["relative_path"]: row for row in inventory["files"]}
    assert rows["analysis/security_surface.json"]["source"] == "pcap_report"
    assert rows["analysis/security_review.md"]["origin"] == "host"
    assert inventory["provenance_complete"] is True
