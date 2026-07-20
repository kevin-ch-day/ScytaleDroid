from __future__ import annotations

import subprocess
from pathlib import Path

from scytaledroid.Utils.System import workspace_maintenance_menu


def test_workspace_size_uses_native_du_for_large_tree(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    calls: list[tuple[str, ...]] = []

    def fake_run(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, stdout="42\t/path\n", stderr="")

    monkeypatch.setattr(workspace_maintenance_menu.subprocess, "run", fake_run)

    assert workspace_maintenance_menu._dir_size_bytes(root) == 42 * 1024
    assert calls == [("du", "-sk", str(root))]


def test_workspace_size_falls_back_when_du_is_unavailable(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "capture.pcap").write_bytes(b"abc")

    def missing_du(*_args, **_kwargs):
        raise OSError("du unavailable")

    monkeypatch.setattr(workspace_maintenance_menu.subprocess, "run", missing_du)

    assert workspace_maintenance_menu._dir_size_bytes(root) == 3


def test_workspace_file_count_uses_native_find_without_path_list(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "apk"
    root.mkdir()
    calls: list[tuple[str, ...]] = []

    def fake_run(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, stdout=b"...", stderr=b"")

    monkeypatch.setattr(workspace_maintenance_menu.subprocess, "run", fake_run)

    assert workspace_maintenance_menu._count_files(root, pattern="**/*.apk") == 3
    assert calls == [("find", str(root), "-type", "f", "-name", "*.apk", "-printf", ".")]


def test_workspace_file_count_falls_back_when_find_is_unavailable(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "batches"
    root.mkdir()
    (root / "one.json").write_text("{}", encoding="utf-8")
    (root / "two.txt").write_text("x", encoding="utf-8")

    def missing_find(*_args, **_kwargs):
        raise OSError("find unavailable")

    monkeypatch.setattr(workspace_maintenance_menu.subprocess, "run", missing_find)

    assert workspace_maintenance_menu._count_files(root, pattern="**/*.json") == 1
