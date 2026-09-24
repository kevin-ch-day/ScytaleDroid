"""Runtime compatibility patches for Androguard ARSC parsing.

Androguard 4.1.3 understands ``FLAG_OFFSET16`` but still walks ``FLAG_SPARSE``
type chunks as a dense offset array. Modern APKs (Signal, Play, Chrome, …)
encode those chunks as ``ResTable_sparseTypeEntry`` pairs, so the parser reads
resource IDs / ``0xFFFFFFFF`` as ``ResTable_map_entry.count`` and prints
``We are out of bound with this complex entry``.

This module:

* injects a sparse/offset16 type-entry walker
* prefers compact ``ResTable_entry`` layout over complex when both flags are set
* turns a non-zero ``ResTable_type.reserved`` into a warning instead of aborting
* clamps implausible complex-entry counts so leftover stdout does not leak
"""

from __future__ import annotations

import inspect
import textwrap
from collections.abc import Mapping
from struct import unpack
from typing import Any, BinaryIO

FLAG_SPARSE = 0x01
FLAG_OFFSET16 = 0x02
NO_ENTRY_16 = 0xFFFF
NO_ENTRY_32 = 0xFFFFFFFF

# ResTable_map: ResTable_ref (4) + Res_value (8).
_RES_TABLE_MAP_SIZE = 12
# Styleable maps with more than this many attrs are not plausible; larger
# values are almost always misaligned resource IDs or sentinels.
_PLAUSIBLE_COMPLEX_COUNT_MAX = 0x10000

_APPLIED = False
_STATUS: dict[str, str] = {
    "sparse_type_entries": "not_applied",
    "complex_entry_bounds": "not_applied",
    "compact_entry_precedence": "not_applied",
    "type_reserved_nonzero": "not_applied",
}

# Unique snippet from androguard 4.1.3 ARSCParser.__init__ (dense OFFSET16/32 walk).
_DENSE_TYPE_ENTRY_LOOP = """                        for i in range(0, a_res_type.entryCount):
                            current_package.mResId = (
                                current_package.mResId & 0xFFFF0000 | i
                            )
                            # Check if FLAG_OFFSET16 is set
                            if a_res_type.flags & FLAG_OFFSET16:
                                # Read as 16-bit offset
                                offset_16 = unpack('<H', self.buff.read(2))[0]
                                offset = offset_from16(offset_16)
                                if offset == NO_ENTRY_16:
                                    continue
                            else:
                                # Read as 32-bit offset
                                offset = unpack('<I', self.buff.read(4))[0]
                                if offset == NO_ENTRY_32:
                                    continue
                            entries.append((offset, current_package.mResId))
"""

_HELPER_TYPE_ENTRY_LOOP = """                        entries.extend(
                            _scytale_read_type_offsets(
                                self.buff,
                                a_res_type,
                                current_package,
                            )
                        )
"""

_COMPLEX_BEFORE_COMPACT = """        if self.is_complex():
            self.item = ARSCComplex(buff, expected_end_of_chunk, parent)
        elif self.is_compact():
            self.key = self.size
            self.data = self.index
            self.datatype = (self.flags >> 8) & 0xFF
"""

_COMPACT_BEFORE_COMPLEX = """        if self.is_compact():
            self.key = self.size
            self.data = self.index
            self.datatype = (self.flags >> 8) & 0xFF
        elif self.is_complex():
            self.item = ARSCComplex(buff, expected_end_of_chunk, parent)
"""

_RESERVED_RAISE = '            raise ResParserError("reserved must be zero!")\n'
_RESERVED_WARN = '            logger.warning("Reserved must be zero! Meta is that you?")\n'


def offset_from16(off16: int) -> int:
    """Decode a FLAG_OFFSET16 slot; ``0xFFFF`` is the 16-bit NO_ENTRY sentinel."""

    return NO_ENTRY_16 if off16 == NO_ENTRY_16 else off16 * 4


def read_res_table_type_offsets(
    buff: BinaryIO,
    a_res_type: Any,
    current_package: Any,
) -> list[tuple[int, int]]:
    """Read ``ResTable_type`` entry offsets, including ``FLAG_SPARSE`` tables.

    Returns ``(byte_offset, resource_id)`` pairs and updates
    ``current_package.mResId`` the same way Androguard's dense walker does.
    """

    entries: list[tuple[int, int]] = []
    flags = int(getattr(a_res_type, "flags", 0) or 0)
    entry_count = int(getattr(a_res_type, "entryCount", 0) or 0)
    for index in range(entry_count):
        if flags & FLAG_SPARSE:
            raw = buff.read(4)
            if len(raw) < 4:
                break
            entry_id, encoded_offset = unpack("<HH", raw)
            current_package.mResId = current_package.mResId & 0xFFFF0000 | entry_id
            offset = encoded_offset * 4
        else:
            current_package.mResId = current_package.mResId & 0xFFFF0000 | index
            if flags & FLAG_OFFSET16:
                raw = buff.read(2)
                if len(raw) < 2:
                    break
                offset = offset_from16(unpack("<H", raw)[0])
                if offset == NO_ENTRY_16:
                    continue
            else:
                raw = buff.read(4)
                if len(raw) < 4:
                    break
                offset = unpack("<I", raw)[0]
                if offset == NO_ENTRY_32:
                    continue
        entries.append((offset, current_package.mResId))
    return entries


def apply_androguard_arsc_compat() -> Mapping[str, str]:
    """Patch Androguard ARSC helpers once per process. Safe to call repeatedly."""

    global _APPLIED
    if _APPLIED:
        return dict(_STATUS)

    from androguard.core import axml

    _patch_sparse_type_entries(axml)
    _patch_compact_entry_precedence(axml)
    _patch_type_reserved_nonzero(axml)
    _patch_complex_entry_bounds(axml)
    _APPLIED = True
    return dict(_STATUS)


def compat_status() -> Mapping[str, str]:
    return dict(_STATUS)


def _rebuild_method(axml: Any, source: str, filename: str) -> Any | None:
    src = textwrap.dedent(source)
    try:
        code = compile(src, filename, "exec")
        namespace: dict[str, Any] = {}
        exec(code, axml.__dict__, namespace)  # noqa: S102 - targeted method rebuild
    except Exception:
        return None
    return namespace.get("__init__")


def _patch_sparse_type_entries(axml: Any) -> None:
    init = getattr(axml.ARSCParser, "__init__", None)
    if not callable(init):
        _STATUS["sparse_type_entries"] = "skipped_missing_init"
        return
    try:
        raw = inspect.getsource(init)
    except (OSError, TypeError):
        _STATUS["sparse_type_entries"] = "skipped_no_source"
        return
    if "if a_res_type.flags & FLAG_SPARSE" in raw or "_scytale_read_type_offsets" in raw:
        _STATUS["sparse_type_entries"] = "already_present"
        return
    if _DENSE_TYPE_ENTRY_LOOP not in raw:
        _STATUS["sparse_type_entries"] = "skipped_unrecognized"
        return
    axml.__dict__["_scytale_read_type_offsets"] = read_res_table_type_offsets
    patched = raw.replace(_DENSE_TYPE_ENTRY_LOOP, _HELPER_TYPE_ENTRY_LOOP, 1)
    rebuilt = _rebuild_method(axml, patched, "<scytaledroid:androguard_arsc_compat:parser>")
    if not callable(rebuilt):
        _STATUS["sparse_type_entries"] = "skipped_compile_error"
        return
    axml.ARSCParser.__init__ = rebuilt
    _STATUS["sparse_type_entries"] = "applied"


def _patch_compact_entry_precedence(axml: Any) -> None:
    init = getattr(axml.ARSCResTableEntry, "__init__", None)
    if not callable(init):
        _STATUS["compact_entry_precedence"] = "skipped_missing_init"
        return
    try:
        raw = inspect.getsource(init)
    except (OSError, TypeError):
        _STATUS["compact_entry_precedence"] = "skipped_no_source"
        return
    compact_idx = raw.find("if self.is_compact():")
    complex_idx = raw.find("if self.is_complex():")
    if compact_idx != -1 and (complex_idx == -1 or compact_idx < complex_idx):
        _STATUS["compact_entry_precedence"] = "already_present"
        return
    if _COMPLEX_BEFORE_COMPACT not in raw:
        _STATUS["compact_entry_precedence"] = "skipped_unrecognized"
        return
    patched = raw.replace(_COMPLEX_BEFORE_COMPACT, _COMPACT_BEFORE_COMPLEX, 1)
    rebuilt = _rebuild_method(axml, patched, "<scytaledroid:androguard_arsc_compat:entry>")
    if not callable(rebuilt):
        _STATUS["compact_entry_precedence"] = "skipped_compile_error"
        return
    axml.ARSCResTableEntry.__init__ = rebuilt
    _STATUS["compact_entry_precedence"] = "applied"


def _patch_type_reserved_nonzero(axml: Any) -> None:
    init = getattr(axml.ARSCResType, "__init__", None)
    if not callable(init):
        _STATUS["type_reserved_nonzero"] = "skipped_missing_init"
        return
    try:
        raw = inspect.getsource(init)
    except (OSError, TypeError):
        _STATUS["type_reserved_nonzero"] = "skipped_no_source"
        return
    if 'raise ResParserError("reserved must be zero!")' not in raw:
        _STATUS["type_reserved_nonzero"] = "already_present"
        return
    if _RESERVED_RAISE not in raw:
        _STATUS["type_reserved_nonzero"] = "skipped_unrecognized"
        return
    patched = raw.replace(_RESERVED_RAISE, _RESERVED_WARN, 1)
    rebuilt = _rebuild_method(axml, patched, "<scytaledroid:androguard_arsc_compat:type>")
    if not callable(rebuilt):
        _STATUS["type_reserved_nonzero"] = "skipped_compile_error"
        return
    axml.ARSCResType.__init__ = rebuilt
    _STATUS["type_reserved_nonzero"] = "applied"


def _patch_complex_entry_bounds(axml: Any) -> None:
    unpack_fn = axml.unpack
    string_pool_ref = axml.ARSCResStringPoolRef

    def _safe_complex_init(
        self: Any,
        buff: BinaryIO,
        expected_end_of_chunk: int,
        parent: Any | None = None,
    ) -> None:
        self.start = buff.tell()
        self.parent = parent
        header = buff.read(8)
        if len(header) < 8:
            self.id_parent = 0
            self.count = 0
            self.items = []
            return
        self.id_parent = unpack_fn("<I", header[:4])[0]
        self.count = unpack_fn("<I", header[4:])[0]
        self.items = []

        remaining = max(0, int(expected_end_of_chunk) - buff.tell())
        max_items = remaining // _RES_TABLE_MAP_SIZE
        parse_count, emit_legacy_warning = _complex_parse_plan(int(self.count), max_items)
        if emit_legacy_warning:
            # Kept for the existing stdout-capture / aapt2 fallback path.
            print(f"We are out of bound with this complex entry. Count: {self.count}")
        for _ in range(parse_count):
            if buff.tell() + 4 > expected_end_of_chunk:
                break
            name = buff.read(4)
            if len(name) < 4:
                break
            self.items.append((unpack_fn("<I", name)[0], string_pool_ref(buff, self.parent)))

    axml.ARSCComplex.__init__ = _safe_complex_init
    _STATUS["complex_entry_bounds"] = "applied"


def _complex_parse_plan(count: int, max_items: int) -> tuple[int, bool]:
    """Return ``(parse_count, emit_legacy_stdout_warning)`` for a complex entry."""

    if count <= 0:
        return 0, False
    if count <= max_items:
        return count, False
    if count <= _PLAUSIBLE_COMPLEX_COUNT_MAX:
        return max_items, True
    # Sentinel / resource-id / misaligned sparse payload: do not iterate or print.
    return 0, False


__all__ = [
    "FLAG_OFFSET16",
    "FLAG_SPARSE",
    "NO_ENTRY_16",
    "NO_ENTRY_32",
    "apply_androguard_arsc_compat",
    "compat_status",
    "offset_from16",
    "read_res_table_type_offsets",
]
