from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Literal, Mapping, Optional

from .loader import ONLINE_URL, load_permission_doc
from .normalize import PermissionMeta
from .parser import parse_manifest_permissions
from .protection import sanitise_tokens
from .summary_clean import purge_markers as _purge_markers, dedupe_sentences as _dedupe


def load_catalog(source: Literal["sdk", "online", "auto"] = "auto") -> list[PermissionMeta]:
    html, label = load_permission_doc(source)
    if not html:
        raise RuntimeError("Permission documentation could not be loaded (SDK/online unavailable)")
    return parse_manifest_permissions(html, base_url=ONLINE_URL)


def save_catalog_json(
    path: Path,
    items: list[PermissionMeta],
    *,
    source: str = "auto",
    base_url: str = ONLINE_URL,
    write_timestamped: bool = False,
) -> Path:
    """Persist catalog with a small metadata wrapper; returns the primary path.

    The JSON shape becomes {"meta": {...}, "items": [...]}. For backward
    compatibility, loading still supports list-shaped payloads.
    """
    import hashlib
    from datetime import datetime

    path.parent.mkdir(parents=True, exist_ok=True)
    serialisable = [asdict(item) for item in items]
    payload = {
        "meta": {
            "catalog_version": 1,
            "source": source,
            "base_url": base_url,
            "fetched_at": datetime.utcnow().isoformat() + "Z",
        },
        "items": serialisable,
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    sha = hashlib.sha256(blob).hexdigest()
    payload["meta"]["content_sha256"] = sha
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    if write_timestamped:
        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        ts_path = path.with_name(f"{path.stem}.{stamp}{path.suffix}")
        ts_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_catalog_json(path: Path) -> list[PermissionMeta]:
    data = json.loads(path.read_text(encoding="utf-8"))
    # Backwards compatible: support both list payloads and {meta, items}
    raw_items = data.get("items") if isinstance(data, dict) else data
    items: list[PermissionMeta] = []
    for row in raw_items:
        # Clean and normalise legacy payload quirks when present
        raw_tokens = row.get("protection_tokens") or ()
        clean_tokens = sanitise_tokens(raw_tokens)
        row["protection_tokens"] = tuple(clean_tokens)
        if clean_tokens:
            row["protection_raw"] = "|".join(clean_tokens)
        if row.get("summary"):
            row["summary"] = _purge_markers(_dedupe(str(row["summary"])))
        items.append(
            PermissionMeta(
                name=row.get("name", ""),
                short=row.get("short", ""),
                protection=row.get("protection"),
                protection_raw=row.get("protection_raw"),
                protection_tokens=tuple(row.get("protection_tokens") or ()),
                added_api=row.get("added_api"),
                added_version=row.get("added_version"),
                deprecated_api=row.get("deprecated_api"),
                deprecated_note=row.get("deprecated_note"),
                hard_restricted=bool(row.get("hard_restricted")),
                soft_restricted=bool(row.get("soft_restricted")),
                system_only=bool(row.get("system_only")),
                restricted_note=row.get("restricted_note"),
                system_only_note=row.get("system_only_note"),
                constant_value=row.get("constant_value"),
                summary=row.get("summary", ""),
                doc_url=row.get("doc_url", ""),
                api_references=tuple(row.get("api_references") or ()),
                group=row.get("group"),
            )
        )
    return items


def index_by_constant(items: Iterable[PermissionMeta]) -> dict[str, PermissionMeta]:
    return {entry.name: entry for entry in items}


def index_by_short(items: Iterable[PermissionMeta]) -> dict[str, PermissionMeta]:
    return {entry.short: entry for entry in items}
