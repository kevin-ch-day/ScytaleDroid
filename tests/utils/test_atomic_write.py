from __future__ import annotations

from pathlib import Path

from scytaledroid.Utils.IO.atomic_write import atomic_write_bytes, atomic_write_text


def test_atomic_write_text_writes_complete_file(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    atomic_write_text(p, "hello\n")
    assert p.read_text(encoding="utf-8") == "hello\n"


def test_atomic_write_bytes_writes_complete_file(tmp_path: Path) -> None:
    p = tmp_path / "x.bin"
    atomic_write_bytes(p, b"\x00\x01\x02")
    assert p.read_bytes() == b"\x00\x01\x02"

