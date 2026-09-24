from __future__ import annotations

import io
from struct import pack
from types import SimpleNamespace

from androguard.core import axml
from scytaledroid.StaticAnalysis.engine.androguard_arsc_compat import (
    FLAG_OFFSET16,
    FLAG_SPARSE,
    NO_ENTRY_16,
    NO_ENTRY_32,
    _complex_parse_plan,
    apply_androguard_arsc_compat,
    offset_from16,
    read_res_table_type_offsets,
)


def test_apply_androguard_arsc_compat_is_idempotent() -> None:
    first = apply_androguard_arsc_compat()
    second = apply_androguard_arsc_compat()

    assert first == second
    assert first["complex_entry_bounds"] == "applied"
    assert first["sparse_type_entries"] in {"applied", "already_present"}
    assert first["compact_entry_precedence"] in {"applied", "already_present"}
    assert first["type_reserved_nonzero"] in {"applied", "already_present"}


def test_sparse_type_entry_walk_is_wired_after_compat_patch() -> None:
    apply_androguard_arsc_compat()

    names = axml.ARSCParser.__init__.__code__.co_names
    varnames = axml.ARSCParser.__init__.__code__.co_varnames
    assert "_scytale_read_type_offsets" in names or "FLAG_SPARSE" in varnames


def test_offset_from16_decodes_sentinel_and_scaled_slots() -> None:
    assert offset_from16(NO_ENTRY_16) == NO_ENTRY_16
    assert offset_from16(3) == 12


def test_read_res_table_type_offsets_sparse_uses_encoded_ids() -> None:
    buff = io.BytesIO(pack("<HH", 1, 1) + pack("<HH", 3, 2))
    package = SimpleNamespace(mResId=0x7F010000)
    table = SimpleNamespace(flags=FLAG_SPARSE, entryCount=2)

    entries = read_res_table_type_offsets(buff, table, package)

    assert entries == [(4, 0x7F010001), (8, 0x7F010003)]
    assert package.mResId == 0x7F010003


def test_read_res_table_type_offsets_dense_skips_no_entry() -> None:
    buff = io.BytesIO(pack("<II", NO_ENTRY_32, 12))
    package = SimpleNamespace(mResId=0x7F020000)
    table = SimpleNamespace(flags=0, entryCount=2)

    entries = read_res_table_type_offsets(buff, table, package)

    assert entries == [(12, 0x7F020001)]


def test_read_res_table_type_offsets_offset16_skips_no_entry() -> None:
    buff = io.BytesIO(pack("<HH", NO_ENTRY_16, 3))
    package = SimpleNamespace(mResId=0x7F030000)
    table = SimpleNamespace(flags=FLAG_OFFSET16, entryCount=2)

    entries = read_res_table_type_offsets(buff, table, package)

    assert entries == [(12, 0x7F030001)]


def test_read_res_table_type_offsets_sparse_wins_over_offset16() -> None:
    buff = io.BytesIO(pack("<HH", 5, 4))
    package = SimpleNamespace(mResId=0x7F040000)
    table = SimpleNamespace(flags=FLAG_SPARSE | FLAG_OFFSET16, entryCount=1)

    entries = read_res_table_type_offsets(buff, table, package)

    assert entries == [(16, 0x7F040005)]


def test_complex_parse_plan_skips_sentinel_and_resource_id_counts() -> None:
    assert _complex_parse_plan(0xFFFFFFFF, max_items=40) == (0, False)
    assert _complex_parse_plan(134217778, max_items=40) == (0, False)
    assert _complex_parse_plan(12, max_items=40) == (12, False)
    assert _complex_parse_plan(80, max_items=40) == (40, True)


def test_complex_entry_sentinel_count_does_not_print(capsys) -> None:
    apply_androguard_arsc_compat()
    payload = pack("<II", 0, 0xFFFFFFFF) + b"\x00" * 24
    buff = io.BytesIO(payload)

    parsed = axml.ARSCComplex(buff, expected_end_of_chunk=len(payload), parent=None)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert parsed.count == 0xFFFFFFFF
    assert parsed.items == []


def test_complex_entry_truncated_plausible_count_still_emits_legacy_line(capsys) -> None:
    apply_androguard_arsc_compat()
    payload = pack("<II", 0, 80)
    buff = io.BytesIO(payload)

    parsed = axml.ARSCComplex(buff, expected_end_of_chunk=len(payload), parent=None)

    captured = capsys.readouterr()
    assert "We are out of bound with this complex entry. Count: 80" in captured.out
    assert parsed.items == []


def test_compact_flag_takes_precedence_over_complex_flag() -> None:
    apply_androguard_arsc_compat()
    flags = axml.ARSCResTableEntry.FLAG_COMPLEX | axml.ARSCResTableEntry.FLAG_COMPACT
    payload = pack("<HHI", 42, flags, 99)

    entry = axml.ARSCResTableEntry(io.BytesIO(payload), 0, len(payload), 0x7F010001, None)

    assert entry.is_compact()
    assert entry.is_complex()
    assert entry.key == 42
    assert entry.data == 99
    assert not hasattr(entry, "item")


def test_nonzero_type_reserved_does_not_raise() -> None:
    apply_androguard_arsc_compat()
    consts = axml.ARSCResType.__init__.__code__.co_consts
    assert "Reserved must be zero! Meta is that you?" in consts
    assert "reserved must be zero!" not in consts
