"""Canonical prospective evidence inventory and independent verification."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import replace
from pathlib import Path

CONTRACT = "evidence_sealing_v2"
EXCLUDED = {
    "run_manifest.json": "self_reference; anchor manifest checksum externally",
    "notes/.scytaledroid_in_progress": "transient lifecycle marker removed after seal",
}


def hash_regular(path: Path) -> tuple[str, int]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not_regular_file")
        with os.fdopen(os.dup(fd), "rb") as f:
            h = hashlib.file_digest(f, "sha256").hexdigest()
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("changed_while_hashing")
        return h, after.st_size
    finally:
        os.close(fd)


def inventory_files(root: Path) -> dict[str, Path]:
    files = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in list(dirs):
            p = Path(directory) / name
            if p.is_symlink():
                files[str(p.relative_to(root))] = p
                dirs.remove(name)
        for name in names:
            p = Path(directory) / name
            if str(p.relative_to(root)) not in EXCLUDED:
                files[str(p.relative_to(root))] = p
    return files


def seal_inventory(root: Path, manifest) -> dict:
    root = Path(root).resolve()
    groups = [manifest.artifacts, manifest.outputs] + [o.artifacts for o in manifest.observers]
    declared = {r.relative_path: r for group in groups for r in group}
    files = inventory_files(root)
    rows = []
    by_path = {}
    for rel in sorted(set(files) | set(declared)):
        if rel in EXCLUDED:
            continue
        rec = declared.get(rel)
        row = {
            "relative_path": rel,
            "artifact_type": rec.type if rec else "retained_unregistered_file",
            "source": rec.produced_by if rec else "unregistered_producer",
            "origin": (rec.origin or "unknown") if rec else "unknown",
            "collection_status": (rec.pull_status or "retained_local_status_unspecified")
            if rec
            else "retained_unregistered",
            "sha256": None,
            "size_bytes": None,
            "status": "EXEMPT",
            "reason": None,
        }
        p = files.get(rel)
        try:
            if p is None:
                raise ValueError("declared_file_missing_or_outside_pack")
            if p.is_symlink():
                raise ValueError("symlink_not_canonical")
            row["sha256"], row["size_bytes"] = hash_regular(p)
            row["status"] = "HASHED"
        except (OSError, ValueError) as exc:
            row["reason"] = type(exc).__name__ + ":" + str(exc)
        rows.append(row)
        by_path[rel] = row
    for group in groups:
        for i, rec in enumerate(group):
            row = by_path.get(rec.relative_path)
            if row and row["status"] == "HASHED":
                group[i] = replace(rec, sha256=row["sha256"], size_bytes=row["size_bytes"])
    return {
        "contract": CONTRACT,
        "status": "COMPLETE" if all(r["status"] == "HASHED" for r in rows) else "INCOMPLETE",
        "files": rows,
        "scope_exclusions": EXCLUDED,
        "provenance_complete": all(
            r["origin"] != "unknown"
            and r["source"] != "unregistered_producer"
            and r["collection_status"]
            not in {"retained_unregistered", "retained_local_status_unspecified"}
            for r in rows
        ),
        "policy": "No post-seal canonical mutations; derived work goes to a separate sidecar. Hashes do not change research eligibility.",
    }


def verify_inventory(root: Path, integrity: dict) -> dict:
    """Recompute bytes and validate the inventory itself; malformed seals fail closed."""
    root = Path(root).resolve()
    issues = []
    if not isinstance(integrity, dict) or integrity.get("contract") != CONTRACT:
        return {"valid": False, "issues": ["unknown_integrity_contract"]}
    rows = integrity.get("files")
    if not isinstance(rows, list):
        return {"valid": False, "issues": ["malformed_inventory"]}
    listed = set()
    provenance_complete = True
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("relative_path"), str):
            issues.append("malformed_inventory_row")
            provenance_complete = False
            continue
        rel = row["relative_path"]
        if rel in listed:
            issues.append("duplicate_inventory_path:" + rel)
        listed.add(rel)
        if not all(
            isinstance(row.get(k), str) and row[k]
            for k in ("artifact_type", "source", "origin", "collection_status")
        ):
            issues.append("missing_inventory_metadata:" + rel)
            provenance_complete = False
        if (
            row.get("origin") in (None, "unknown")
            or row.get("source") in (None, "unregistered_producer")
            or row.get("collection_status")
            in (None, "retained_unregistered", "retained_local_status_unspecified")
        ):
            provenance_complete = False
        p = root / rel
        if (
            not rel
            or rel in EXCLUDED
            or Path(rel).is_absolute()
            or ".." in Path(rel).parts
            or p.is_symlink()
            or not p.resolve().is_relative_to(root)
        ):
            issues.append("unsafe_path:" + rel)
            continue
        if row.get("status") != "HASHED":
            issues.append("integrity_exemption:" + rel)
            continue
        try:
            h, size = hash_regular(p)
            if h != row.get("sha256") or size != row.get("size_bytes"):
                issues.append("hash_or_size_mismatch:" + rel)
        except (OSError, ValueError):
            issues.append("missing_or_unreadable:" + rel)
    for extra in sorted(set(inventory_files(root)) - listed):
        issues.append("unaccounted_file:" + extra)
    if integrity.get("status") != "COMPLETE":
        issues.append("seal_incomplete")
    if integrity.get("scope_exclusions") != EXCLUDED:
        issues.append("scope_exclusions_differ")
    return {
        "valid": not issues,
        "issues": issues,
        "accounted_files": len(listed),
        "provenance_complete": provenance_complete and integrity.get("provenance_complete") is True,
    }


def integrity_grade_reasons(root: Path, integrity: dict) -> list[dict]:
    result = verify_inventory(root, integrity)
    reasons = [{"code": "evidence_integrity_v2_failed", "detail": x} for x in result["issues"]]
    if not result.get("provenance_complete"):
        reasons.append({"code": "evidence_provenance_v2_incomplete"})
    return reasons
