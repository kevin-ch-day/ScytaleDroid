from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

SCRIPT = Path("scripts/dynamic/migrate_dynamic_evidence_to_data_root.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("migrate_dynamic_evidence_to_data_root", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[str(spec.name)] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_pack(root: Path, run_id: str, content: str = "ok") -> Path:
    run_dir = root / run_id
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text('{"ok": true}', encoding="utf-8")
    (run_dir / "analysis" / "summary.json").write_text(content, encoding="utf-8")
    return run_dir


def _write_incomplete_pack(root: Path, run_id: str) -> Path:
    run_dir = root / run_id
    (run_dir / "notes").mkdir(parents=True)
    (run_dir / "notes" / "run_events.jsonl").write_text("{}\n", encoding="utf-8")
    return run_dir


def _latest_actions(receipt_root: Path) -> list[dict[str, str]]:
    latest = sorted(receipt_root.iterdir())[-1]
    with (latest / "actions.csv").open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_dry_run_does_not_copy(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    source = tmp_path / "output" / "evidence" / "dynamic"
    dest = tmp_path / "data" / "evidence" / "dynamic"
    receipt = tmp_path / "receipts"
    _write_pack(source, "run-1")

    assert mod.main(["--source-root", str(source), "--dest-root", str(dest), "--receipt-dir", str(receipt)]) == 0

    rows = _latest_actions(receipt)
    assert rows[0]["status"] == "planned"
    assert not (dest / "run-1").exists()


def test_apply_copies_and_replaces_source_with_symlink(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    source = tmp_path / "output" / "evidence" / "dynamic"
    dest = tmp_path / "data" / "evidence" / "dynamic"
    receipt = tmp_path / "receipts"
    run_dir = _write_pack(source, "run-1")

    assert (
        mod.main(
            [
                "--source-root",
                str(source),
                "--dest-root",
                str(dest),
                "--receipt-dir",
                str(receipt),
                "--apply",
                "--replace-with-symlink",
            ]
        )
        == 0
    )

    rows = _latest_actions(receipt)
    assert rows[0]["status"] == "copied"
    assert rows[0]["source_replaced_with_symlink"] == "True"
    assert run_dir.is_symlink()
    assert (run_dir / "run_manifest.json").exists()
    assert (dest / "run-1" / "analysis" / "summary.json").read_text(encoding="utf-8") == "ok"


def test_existing_destination_hash_mismatch_blocks(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    source = tmp_path / "output" / "evidence" / "dynamic"
    dest = tmp_path / "data" / "evidence" / "dynamic"
    receipt = tmp_path / "receipts"
    _write_pack(source, "run-1", content="source")
    _write_pack(dest, "run-1", content="different")

    assert (
        mod.main(
            [
                "--source-root",
                str(source),
                "--dest-root",
                str(dest),
                "--receipt-dir",
                str(receipt),
                "--apply",
                "--replace-with-symlink",
            ]
        )
        == 0
    )

    rows = _latest_actions(receipt)
    assert rows[0]["status"] == "blocked_existing_mismatch"
    assert rows[0]["source_replaced_with_symlink"] == "False"
    assert not (source / "run-1").is_symlink()


def test_apply_can_symlink_incomplete_pack_without_manifest(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    source = tmp_path / "output" / "evidence" / "dynamic"
    dest = tmp_path / "data" / "evidence" / "dynamic"
    receipt = tmp_path / "receipts"
    run_dir = _write_incomplete_pack(source, "run-ghost")

    assert (
        mod.main(
            [
                "--source-root",
                str(source),
                "--dest-root",
                str(dest),
                "--receipt-dir",
                str(receipt),
                "--apply",
                "--replace-with-symlink",
            ]
        )
        == 0
    )

    rows = _latest_actions(receipt)
    assert rows[0]["status"] == "copied"
    assert rows[0]["source_replaced_with_symlink"] == "True"
    assert run_dir.is_symlink()
    assert (run_dir / "notes" / "run_events.jsonl").exists()
