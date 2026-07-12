from __future__ import annotations

from pathlib import Path

from scripts.db.audit_dynamic_evidence_path_migration import (
    _REPO_ROOT,
    _annotate_missing_run_references,
    _collect_reference_hits,
    _collect_filesystem_alignment,
    normalize_dynamic_evidence_path,
)


def test_normalize_dynamic_evidence_path_rewrites_relative_root() -> None:
    assert (
        normalize_dynamic_evidence_path("output/evidence/dynamic/run-1/run_manifest.json")
        == "data/evidence/dynamic/run-1/run_manifest.json"
    )


def test_normalize_dynamic_evidence_path_rewrites_current_absolute_root() -> None:
    legacy = _REPO_ROOT / "output" / "evidence" / "dynamic" / "run-1" / "run_manifest.json"
    expected = _REPO_ROOT / "data" / "evidence" / "dynamic" / "run-1" / "run_manifest.json"
    assert normalize_dynamic_evidence_path(str(legacy)) == str(expected)


def test_normalize_dynamic_evidence_path_rewrites_old_absolute_root_suffix() -> None:
    legacy = Path("/old/checkout/ScytaleDroid/output/evidence/dynamic/run-1/run_manifest.json")
    expected = _REPO_ROOT / "data" / "evidence" / "dynamic" / "run-1" / "run_manifest.json"
    assert normalize_dynamic_evidence_path(str(legacy)) == str(expected)


def test_normalize_dynamic_evidence_path_ignores_unrelated_paths() -> None:
    assert normalize_dynamic_evidence_path("data/evidence/dynamic/run-1/run_manifest.json") is None


def test_collect_reference_hits_scans_text_files(tmp_path: Path) -> None:
    run_id = "11111111-1111-4111-8111-111111111111"
    (tmp_path / "manifest.json").write_text(f'{{"run_id": "{run_id}"}}', encoding="utf-8")
    (tmp_path / "ignored.bin").write_bytes(run_id.encode("utf-8"))

    hits = _collect_reference_hits([run_id, "missing"], [tmp_path])

    assert hits[run_id] == [str(tmp_path / "manifest.json")]
    assert hits["missing"] == []


def test_annotate_missing_run_references_marks_retirement_candidates() -> None:
    rows = [
        {"dynamic_run_id": "run-1", "classification": "missing_evidence_pack"},
        {"dynamic_run_id": "run-2", "classification": "missing_evidence_pack"},
    ]

    annotated = _annotate_missing_run_references(rows, {"run-1": ["output/paper/freeze.json"], "run-2": []})

    assert annotated[0]["classification"] == "missing_evidence_restore_before_retirement"
    assert annotated[0]["recommended_next_step"] == "restore_pack_before_retirement"
    assert annotated[1]["classification"] == "missing_evidence_db_only_retirement_candidate"
    assert annotated[1]["recommended_next_step"] == "stage_explicit_db_only_retirement_after_review"


def test_collect_filesystem_alignment_classifies_db_and_in_progress(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data" / "evidence" / "dynamic"
    db_run = root / "run-db"
    db_run.mkdir(parents=True)
    (db_run / "run_manifest.json").write_text("{}", encoding="utf-8")
    in_progress = root / "run-in-progress"
    (in_progress / "notes").mkdir(parents=True)
    (in_progress / "notes" / ".scytaledroid_in_progress").write_text("open", encoding="utf-8")

    import scripts.db.audit_dynamic_evidence_path_migration as mod

    monkeypatch.setattr(mod, "_canonical_abs_root", lambda: root)

    def fake_run_sql(_sql: str, *args: object, **kwargs: object) -> list[dict[str, str]]:
        return [{"dynamic_run_id": "run-db"}, {"dynamic_run_id": "run-missing"}]

    rows = _collect_filesystem_alignment(fake_run_sql)
    by_id = {str(row["dynamic_run_id"]): row for row in rows}

    assert by_id["run-db"]["classification"] == "db_backed_manifest"
    assert by_id["run-in-progress"]["classification"] == "filesystem_in_progress_no_manifest"
    assert by_id["run-missing"]["classification"] == "db_missing_filesystem_dir"
