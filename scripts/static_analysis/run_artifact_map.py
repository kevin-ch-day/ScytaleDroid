#!/usr/bin/env python3
"""Static run artifact audit (read-only): selection, archive, logs, mirrors, DB, diagnostics.

Implements the model in ``docs/maintenance/static_run_artifact_lifecycle.md``. Does not move or
delete any files.

Run from repo root::

  PYTHONPATH=. python scripts/static_analysis/run_artifact_map.py --session 20260510-all-full-145

``report.saved`` lines may repeat the same ``archive_path`` (e.g. re-save / multiple emit paths); the audit
uses **unique** ``archive_path`` counts for strict alignment with on-disk archive JSON, not raw JSONL line count.

  PYTHONPATH=. python scripts/static_analysis/run_artifact_map.py --session SESSION --json
  PYTHONPATH=. python scripts/static_analysis/run_artifact_map.py --session SESSION --write-report
  PYTHONPATH=. python scripts/static_analysis/run_artifact_map.py --session SESSION --include-harvest-linkage
  PYTHONPATH=. python scripts/static_analysis/run_artifact_map.py --session SESSION --include-harvest-receipt-linkage

Exit codes: 0 ok, 1 bad args / import failure, 2 --strict violations (complete-looking session failed checks).
Use ``--strict-log-duplicates`` with ``--strict`` to fail on duplicate ``report.saved`` lines (named violation ``duplicate_report_saved_events``).

Legacy ``--compare-log`` and ``--db`` are deprecated no-ops (full audit always runs; use ``--no-db`` to skip SQL).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

SCRIPT_PATH = Path(__file__).resolve()


def _safe_receipt_segment(value: str) -> str:
    """Delegate to ``artifact_store.safe_filesystem_slug`` (lazy import for ``--help`` without PYTHONPATH)."""

    from scytaledroid.DeviceAnalysis.services.artifact_store import safe_filesystem_slug

    return safe_filesystem_slug(value)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


def _count_files(root: Path, pattern: str) -> int:
    if not root.is_dir():
        return 0
    return sum(1 for _ in root.rglob(pattern))


def _rel_display(path: Path, repo: Path) -> str:
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.as_posix()


def _resolve_maybe_path(value: str | None, *, repo: Path) -> Path | None:
    if not value or value in {"None", ""}:
        return None
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = (repo / p).resolve()
    else:
        p = p.resolve()
    return p


# ---------------------------------------------------------------------------
# Selection manifest
# ---------------------------------------------------------------------------


def _harvest_apk_meta_sidecar_path(apk_path: Path) -> Path:
    """Path to the harvest metadata sidecar next to *apk_path*.

    Matches ``write_metadata_sidecar`` / ``_load_metadata`` in DeviceAnalysis + StaticAnalysis:
    ``<apk_filename>.apk.meta.json`` (e.g. ``foo__base.apk`` → ``foo__base.apk.meta.json``), not
    ``<stem>.meta.json``.
    """

    return apk_path.parent / f"{apk_path.name}.meta.json"


def _path_has_harvest_package_manifest_nearby(path: Path, *, max_up: int = 6) -> bool:
    """True when ``harvest_package_manifest.json`` exists beside *path* or a few parents up."""

    parent = path.parent
    if (parent / "harvest_package_manifest.json").is_file():
        return True
    walk = parent
    for _ in range(max_up):
        if (walk / "harvest_package_manifest.json").is_file():
            return True
        if walk.parent == walk:
            break
        walk = walk.parent
    return False


def _selection_path_is_canonical_apk_content_store(p: Path) -> bool:
    """True when *p* looks like ``.../store/.../apk/sha256/<hex>/<digest>.apk`` (content-addressed mirror).

    Receipt resolution prefers ``canonical_store_path`` over the ``device_apks`` pull path; harvest writes
    ``*.apk.meta.json`` beside the pull, not beside the sha256 store entry, so adjacent sidecar counts
    are often zero for selection strings even when pulls have metadata.
    """

    parts_lower = tuple(part.lower() for part in p.parts)
    for i in range(len(parts_lower) - 1):
        if parts_lower[i] == "apk" and parts_lower[i + 1] == "sha256":
            return True
    return False


def _load_selection(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _permission_audit_directory_audit(
    *,
    perm_audit_root: Path,
    repo: Path,
    db_permission_audit_apps_rows: int | None,
) -> dict[str, Any]:
    """Inventory ``data/audit/perm-audit_app_<session>/`` (read-only)."""

    apps_dir = perm_audit_root / "apps"
    app_json_count = 0
    if apps_dir.is_dir():
        app_json_count = sum(1 for p in apps_dir.glob("*.json") if p.is_file())
    snap = perm_audit_root / "snapshot.json"
    corr = perm_audit_root / "correlation.csv"
    out: dict[str, Any] = {
        "resolved_root": _rel_display(perm_audit_root.resolve(), repo),
        "root_exists": perm_audit_root.is_dir(),
        "snapshot_json": {
            "path": _rel_display(snap, repo),
            "present": snap.is_file(),
            "artifact_family": "evidence_required",
        },
        "apps_dir": {
            "path": _rel_display(apps_dir, repo),
            "json_file_count": app_json_count,
            "artifact_family": "evidence_required",
        },
        "correlation_csv": {
            "path": _rel_display(corr, repo),
            "present": corr.is_file(),
            "artifact_family": "diagnostics_required",
        },
        "db_permission_audit_apps_rows": db_permission_audit_apps_rows,
        "apps_json_count_vs_db_rows": None,
        "changed_parity_packages": [],
        "changed_parity_note": (
            "Post-run permission snapshot parity logs which apps used a fresh report vs reused_saved_report; "
            "that per-package list is not written to a standard session JSON artifact here—check run transcript."
        ),
    }
    if db_permission_audit_apps_rows is not None:
        out["apps_json_count_vs_db_rows"] = {
            "match": app_json_count == db_permission_audit_apps_rows,
            "delta_apps_json_minus_db": app_json_count - int(db_permission_audit_apps_rows),
        }
    return out


def _collect_permission_parity_generated_packages(
    *,
    session: str,
    jsonl_path: Path,
) -> list[dict[str, Any]]:
    """Return packages regenerated during permission snapshot parity."""

    if not jsonl_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    with jsonl_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if str(event.get("session_stamp") or "") != session:
                continue
            if event.get("event") != "run.phase":
                continue
            if event.get("phase") != "permission_snapshot_parity":
                continue
            if event.get("status") != "running":
                continue
            if event.get("report_source") != "generated":
                continue
            package = str(event.get("package_name") or "").strip()
            if not package or package in seen:
                continue
            seen.add(package)
            rows.append(
                {
                    "package_name": package,
                    "app_label": event.get("app_label"),
                    "app_index": event.get("app_index"),
                    "app_total": event.get("app_total"),
                    "ts": event.get("ts"),
                    "report_source": event.get("report_source"),
                }
            )
    return rows


def _iter_harvest_receipt_session_dirs(
    receipts_root: Path, selection: dict[str, Any]
) -> tuple[list[Path], str]:
    """Choose harvest receipt session directories; return (dirs, resolution_note).

    Resolution order (first hit wins for the *set* scanned, not first file):

    1. ``receipts_root / safe(selection.session_stamp)`` when that directory exists.
    2. Else any ``receipts_root / safe(capture_id)`` for capture ids listed on selection apps.
    3. Else **all** immediate subdirectories of ``receipts_root`` (widest; can be expensive).
    """

    if not receipts_root.is_dir():
        return [], "receipts_root_missing"
    stamp = str(selection.get("session_stamp") or "").strip()
    if stamp:
        direct = receipts_root / _safe_receipt_segment(stamp)
        if direct.is_dir():
            return [direct], "selection_session_stamp_directory"
    dirs: list[Path] = []
    apps = selection.get("apps")
    if isinstance(apps, list):
        for a in apps:
            if not isinstance(a, dict):
                continue
            cid = str(a.get("capture_id") or "").strip()
            if cid and cid != "unknown":
                d = receipts_root / _safe_receipt_segment(cid)
                if d.is_dir() and d not in dirs:
                    dirs.append(d)
    if dirs:
        return dirs, "capture_id_directories"
    return sorted(p for p in receipts_root.iterdir() if p.is_dir()), "all_session_subdirectories_fallback"


def _harvest_receipt_canonical_to_pull_map(
    selection: dict[str, Any],
    *,
    repo: Path,
    receipts_root: Path,
    device_apks_root: Path,
) -> tuple[dict[str, str], dict[str, int]]:
    """Index ``canonical_store_path`` → device_apks pull path from harvest receipts (read-only)."""

    stats: dict[str, Any] = {
        "receipt_sessions_scanned": 0,
        "receipt_json_files_opened": 0,
        "indexed_observed_rows": 0,
        "canonical_pull_path_collisions": 0,
    }
    out: dict[str, str] = {}
    apps = selection.get("apps")
    if not isinstance(apps, list):
        return out, stats

    packages = {str(a.get("package_name") or "").strip() for a in apps if isinstance(a, dict)}
    packages.discard("")
    if not packages:
        return out, stats

    session_dirs, resolution = _iter_harvest_receipt_session_dirs(receipts_root, selection)
    stats["receipt_sessions_scanned"] = len(session_dirs)
    stats["receipt_session_resolution"] = resolution
    stats["receipt_session_dir_names_sample"] = [d.name for d in session_dirs[:32]]
    pull_root = device_apks_root.resolve()

    for session_dir in session_dirs:
        for pkg in sorted(packages):
            rp = session_dir / f"{_safe_receipt_segment(pkg)}.json"
            if not rp.is_file():
                continue
            stats["receipt_json_files_opened"] += 1
            try:
                payload = json.loads(rp.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            ex = payload.get("execution")
            if not isinstance(ex, dict):
                continue
            observed = ex.get("observed_artifacts")
            if not isinstance(observed, list):
                continue
            for entry in observed:
                if not isinstance(entry, dict):
                    continue
                canon_s = str(entry.get("canonical_store_path") or "").strip()
                local_s = str(entry.get("local_artifact_path") or "").strip()
                if not canon_s or not local_s:
                    continue
                canon_p = _resolve_maybe_path(canon_s, repo=repo)
                if canon_p is None or canon_p.suffix.lower() != ".apk":
                    continue
                local_part = Path(local_s)
                if local_part.is_absolute():
                    pull_p = local_part.expanduser().resolve()
                else:
                    pull_p = (pull_root / local_s).resolve()
                key = str(canon_p.resolve())
                pull_norm = str(pull_p.resolve())
                prev = out.get(key)
                if prev is not None and prev != pull_norm:
                    stats["canonical_pull_path_collisions"] = int(stats.get("canonical_pull_path_collisions") or 0) + 1
                out[key] = pull_norm
                stats["indexed_observed_rows"] = int(stats.get("indexed_observed_rows") or 0) + 1

    stats["indexed_unique_canonical_paths"] = len(out)
    return out, stats


def _harvest_linkage_from_selection(
    selection: dict[str, Any] | None,
    *,
    repo: Path,
    receipt_pull_by_canonical: dict[str, str] | None = None,
    receipt_scan_stats: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Map selection manifest artifact paths to on-disk harvest evidence (read-only)."""

    empty: dict[str, Any] = {
        "skipped": True,
        "reason": "selection_manifest_missing",
        "manifest_only_harvest_note": (
            "Package directories that contain harvest_package_manifest.json but no pulled APK splits often "
            "reflect inventory-only capture (policy-blocked, non-root limits, or ineligible artifacts)—not "
            "usable as static analysis inputs until APK evidence exists."
        ),
    }
    if not selection:
        return empty

    apps = selection.get("apps")
    if not isinstance(apps, list):
        return {**empty, "reason": "selection_apps_missing"}

    selected_paths_total = 0
    artifact_path_found = 0
    apk_paths_in_manifest = 0
    apk_file_found = 0
    apk_meta_sidecar_found = 0
    apk_paths_canonical_content_store = 0
    missing_source_samples: list[str] = []
    harvest_run_labels: set[str] = set()
    package_rows: list[dict[str, Any]] = []

    apk_receipt_mapped = 0
    receipt_pull_apk_on_disk = 0
    receipt_pull_meta_found = 0
    receipt_pull_manifest_nearby = 0
    unmapped_content_store_path_samples: list[str] = []

    for app in apps:
        if not isinstance(app, dict):
            continue
        pkg = str(app.get("package_name") or "")
        cap = str(app.get("capture_id") or "")
        paths_raw = app.get("artifacts")
        if not isinstance(paths_raw, list):
            continue
        group_apks = 0
        group_apks_found = 0
        group_manifest = False
        path_entries_non_empty = 0
        for s in paths_raw:
            if not isinstance(s, str) or not s.strip():
                continue
            path_entries_non_empty += 1
            selected_paths_total += 1
            p = Path(s.strip()).expanduser()
            if not p.is_absolute():
                p = (repo / p).resolve()
            else:
                p = p.resolve()
            parts = p.parts
            try:
                idx = parts.index("device_apks")
                if len(parts) > idx + 4 and parts[idx + 2] == "runs":
                    harvest_run_labels.add(f"{parts[idx + 1]}/runs/{parts[idx + 3]}")
            except ValueError:
                pass

            if p.is_file():
                artifact_path_found += 1
            elif len(missing_source_samples) < 24:
                missing_source_samples.append(_rel_display(p, repo))

            if p.suffix.lower() == ".apk":
                apk_paths_in_manifest += 1
                if _selection_path_is_canonical_apk_content_store(p):
                    apk_paths_canonical_content_store += 1
                if p.is_file():
                    apk_file_found += 1
                    group_apks_found += 1
                group_apks += 1
                meta = _harvest_apk_meta_sidecar_path(p)
                if meta.is_file():
                    apk_meta_sidecar_found += 1

                if receipt_pull_by_canonical is not None:
                    pull_s = receipt_pull_by_canonical.get(str(p.resolve()))
                    if pull_s:
                        apk_receipt_mapped += 1
                        pull_p = Path(pull_s)
                        if pull_p.is_file():
                            receipt_pull_apk_on_disk += 1
                        if _harvest_apk_meta_sidecar_path(pull_p).is_file():
                            receipt_pull_meta_found += 1
                        if _path_has_harvest_package_manifest_nearby(pull_p):
                            receipt_pull_manifest_nearby += 1
                    elif _selection_path_is_canonical_apk_content_store(p) and len(
                        unmapped_content_store_path_samples
                    ) < 16:
                        unmapped_content_store_path_samples.append(_rel_display(p, repo))
            if _path_has_harvest_package_manifest_nearby(p):
                group_manifest = True

        # Manifest on disk but no pulled APK files for this group's paths → inventory / blocked pull, not static input.
        manifest_only = bool(group_manifest and group_apks_found == 0)
        package_rows.append(
            {
                "package_name": pkg,
                "capture_id": cap,
                "artifact_paths_in_manifest": path_entries_non_empty,
                "apk_paths_in_manifest": group_apks,
                "apk_files_present": group_apks_found,
                "harvest_manifest_seen": group_manifest,
                "manifest_only_harvest_folder": manifest_only,
            }
        )

    manifest_only_groups = sum(1 for r in package_rows if r.get("manifest_only_harvest_folder"))

    meta_note = ""
    if apk_paths_canonical_content_store:
        meta_note = (
            "Harvest writes *.apk.meta.json beside the device_apks pull path; selection paths from "
            "receipts usually resolve to canonical_store_path under …/apk/sha256/…, where no sidecar "
            "is written (hardlink/copy). Adjacent sidecar count can be 0 while device_apks trees still "
            "have metadata."
        )

    result: dict[str, Any] = {
        "skipped": False,
        "session_stamp": selection.get("session_stamp"),
        "capture_ids_in_manifest": sorted(
            {cid for cid in (str(a.get("capture_id") or "") for a in apps if isinstance(a, dict)) if cid}
        ),
        "harvest_run_path_labels": sorted(harvest_run_labels),
        "selected_artifact_paths_total": selected_paths_total,
        "artifact_paths_resolved_existing": artifact_path_found,
        "apk_paths_referenced_in_manifest": apk_paths_in_manifest,
        "apk_files_found_on_disk": apk_file_found,
        "apk_meta_sidecars_found": apk_meta_sidecar_found,
        "apk_paths_resolving_to_content_store": apk_paths_canonical_content_store,
        "harvest_meta_sidecar_note": meta_note,
        "missing_source_file_samples": missing_source_samples,
        "packages_with_harvest_package_manifest": sum(1 for r in package_rows if r.get("harvest_manifest_seen")),
        "package_groups_manifest_only_count": manifest_only_groups,
        "package_group_samples": package_rows[:40],
        "manifest_only_harvest_note": empty["manifest_only_harvest_note"],
    }

    if receipt_pull_by_canonical is not None:
        rs = receipt_scan_stats or {}
        dir_sample = rs.get("receipt_session_dir_names_sample")
        if not isinstance(dir_sample, list):
            dir_sample = []
        result["receipt_pull_enrichment"] = {
            "receipt_sessions_scanned": int(rs.get("receipt_sessions_scanned") or 0),
            "receipt_json_files_opened": int(rs.get("receipt_json_files_opened") or 0),
            "indexed_canonical_to_pull_rows": int(rs.get("indexed_observed_rows") or 0),
            "indexed_unique_canonical_paths": int(rs.get("indexed_unique_canonical_paths") or 0),
            "canonical_pull_path_collisions": int(rs.get("canonical_pull_path_collisions") or 0),
            "receipt_session_resolution": str(rs.get("receipt_session_resolution") or ""),
            "receipt_session_dir_names_sample": dir_sample,
            "apk_paths_with_receipt_pull_mapping": apk_receipt_mapped,
            "receipt_pull_apk_files_on_disk": receipt_pull_apk_on_disk,
            "receipt_pull_meta_sidecars_found": receipt_pull_meta_found,
            "receipt_pull_harvest_manifest_nearby": receipt_pull_manifest_nearby,
            "unmapped_content_store_path_samples": unmapped_content_store_path_samples,
        }

    return result


# ---------------------------------------------------------------------------
# Log parsing: report.saved
# ---------------------------------------------------------------------------


def _parse_text_log_suffix(line: str) -> dict[str, str]:
    if " | " not in line:
        return {}
    suffix = line.split(" | ", 1)[1].strip()
    out: dict[str, str] = {}
    for part in suffix.split(", "):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        k = key.strip()
        if k:
            out[k] = value.strip()
    return out


def _collect_report_saved_events(
    session: str,
    *,
    jsonl_path: Path,
    log_path: Path,
) -> tuple[list[dict[str, Any]], str]:
    """Return (events, source_name) for event report.saved and this session_stamp."""

    events: list[dict[str, Any]] = []

    if jsonl_path.is_file():
        try:
            with jsonl_path.open(encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(obj, Mapping):
                        continue
                    if str(obj.get("event") or "") != "report.saved":
                        continue
                    if str(obj.get("session_stamp") or "") != session:
                        continue
                    events.append(dict(obj))
        except OSError:
            pass

    if events:
        return events, "static_analysis.jsonl"

    if not log_path.is_file():
        return [], "none"

    try:
        with log_path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                suffix = _parse_text_log_suffix(line)
                # Must match session_stamp exactly (avoid ``20260510-all-full`` matching ``…-full-145``).
                if suffix.get("session_stamp") != session:
                    continue
                if suffix.get("event") != "report.saved":
                    continue
                row: dict[str, Any] = dict(suffix)
                row["_source"] = "text_log"
                events.append(row)
    except OSError:
        return [], "none"

    return events, "static_analysis.log" if events else "none"


def _event_archive_path(ev: Mapping[str, Any], *, repo: Path) -> Path | None:
    raw = ev.get("archive_path")
    if raw is None or str(raw).strip() in {"", "None"}:
        return None
    return _resolve_maybe_path(str(raw), repo=repo)


def _event_html_path(ev: Mapping[str, Any], *, repo: Path) -> Path | None:
    raw = ev.get("html_path")
    if raw is None or str(raw).strip() in {"", "None"}:
        return None
    return _resolve_maybe_path(str(raw), repo=repo)


def _event_package(ev: Mapping[str, Any]) -> str:
    for key in ("package_name", "normalized_package_name", "manifest_package_name"):
        v = ev.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    return ""


def _rollup_report_saved_archive_paths(
    log_events: list[dict[str, Any]],
    *,
    repo: Path,
) -> dict[str, Any]:
    """Summarize ``report.saved`` lines: raw count vs distinct ``archive_path`` keys.

    Duplicate ``report.saved`` events for the same resolved ``archive_path`` can happen from
    legitimate re-save / re-emit paths (e.g. retries, secondary writers). They inflate the raw
    JSONL count but do not imply missing session archive files when unique paths match disk.
    """

    path_counts: Counter[str] = Counter()
    path_packages: dict[str, set[str]] = {}
    missing_archive_path_events = 0
    for ev in log_events:
        raw = ev.get("archive_path")
        raw_s = str(raw).strip() if raw is not None else ""
        if raw_s in {"", "None"}:
            missing_archive_path_events += 1
            continue
        ap = _event_archive_path(ev, repo=repo)
        key = str(ap.resolve()) if ap is not None else f"unresolved:{raw_s}"
        path_counts[key] += 1
        pkg = _event_package(ev)
        if pkg:
            path_packages.setdefault(key, set()).add(pkg)

    raw_n = len(log_events)
    unique_n = len(path_counts)
    events_with_path = raw_n - missing_archive_path_events
    duplicate_archive_event_extra_count = max(0, events_with_path - unique_n)
    duplicate_archive_path_count = sum(1 for c in path_counts.values() if c > 1)

    dup_samples: list[dict[str, Any]] = []
    for pth, cnt in sorted(path_counts.items(), key=lambda x: (-x[1], x[0])):
        if cnt <= 1:
            break
        sample: dict[str, Any] = {"event_count": cnt, "log_key": pth}
        if pth.startswith("unresolved:"):
            sample["archive_path_raw"] = pth[len("unresolved:") :]
            sample["path_resolution"] = "unresolved"
        else:
            sample["archive_path_resolved"] = pth
            try:
                sample["archive_path_repo_relative"] = _rel_display(Path(pth), repo)
            except ValueError:
                pass
        pkgs = sorted(path_packages.get(pth) or [])
        if pkgs:
            sample["package_names"] = pkgs
        dup_samples.append(sample)
        if len(dup_samples) >= 12:
            break

    core = {
        "raw_report_saved_event_count": raw_n,
        "unique_archive_path_count": unique_n,
        "duplicate_archive_path_count": duplicate_archive_path_count,
        "duplicate_archive_event_extra_count": duplicate_archive_event_extra_count,
        "duplicate_archive_path_samples": dup_samples,
        "report_saved_events_missing_archive_path": missing_archive_path_events,
        "interpretation_note": (
            "Evidence invariant: selection artifact_count == archived_json_count == unique_archive_path_count. "
            "Raw JSONL lines may exceed unique paths when the same archive_path is logged more than once "
            "(re-save/retry); that is log duplication, not missing session archive JSON."
        ),
    }
    # Legacy aliases (older consumers / strict tests)
    core["report_saved_raw_event_count"] = raw_n
    core["report_saved_unique_archive_path_count"] = unique_n
    core["duplicate_report_saved_events"] = duplicate_archive_event_extra_count
    return core


# ---------------------------------------------------------------------------
# Archive JSON validation
# ---------------------------------------------------------------------------


def _audit_archive_json_files(archive_dir: Path) -> tuple[list[Path], int, list[str]]:
    """Return (paths, bad_json_count, sample_bad_names)."""

    if not archive_dir.is_dir():
        return [], 0, []

    paths = sorted(p for p in archive_dir.iterdir() if p.is_file() and p.suffix.lower() == ".json")
    bad = 0
    bad_samples: list[str] = []
    for p in paths:
        try:
            json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            bad += 1
            if len(bad_samples) < 12:
                bad_samples.append(p.name)
    return paths, bad, bad_samples


# ---------------------------------------------------------------------------
# DB audit (join apps via app_versions)
# ---------------------------------------------------------------------------


def _db_audit(session: str) -> dict[str, Any]:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        return {"available": False, "error": f"import_failed: {exc}"}

    run_sql = core_q.run_sql
    out: dict[str, Any] = {"available": True}

    def _fetch_all(sql: str, params: tuple[object, ...] = ()) -> list[Any]:
        try:
            rows = run_sql(sql, params, fetch="all")
        except Exception as exc:
            return [{"_error": str(exc)}]
        return list(rows or [])

    def _scalar(sql: str, params: tuple[object, ...]) -> int | None:
        try:
            row = run_sql(sql, params, fetch="one")
        except Exception as exc:
            out.setdefault("query_errors", []).append({"sql": sql[:80], "error": str(exc)})
            return None
        if not row:
            return 0
        val = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(val or 0)
        except (TypeError, ValueError):
            return None

    # Runs by status
    rows = _fetch_all(
        """
        SELECT UPPER(COALESCE(sar.status, '')) AS run_status, COUNT(*) AS c
        FROM static_analysis_runs sar
        WHERE sar.session_stamp = %s
        GROUP BY UPPER(COALESCE(sar.status, ''))
        ORDER BY c DESC
        """,
        (session,),
    )
    status_counts: dict[str, int] = {}
    status_err: str | None = None
    for row in rows:
        if isinstance(row, dict) and row.get("_error"):
            status_err = str(row.get("_error"))
            break
        if isinstance(row, dict):
            st = str(row.get("run_status") or row.get("RUN_STATUS") or "")
            c = row.get("c")
        elif isinstance(row, (list, tuple)) and len(row) >= 2:
            st, c = str(row[0] or ""), row[1]
        else:
            continue
        try:
            status_counts[st] = int(c or 0)
        except (TypeError, ValueError):
            continue
    if status_err:
        out["static_analysis_runs_by_status_error"] = status_err
    else:
        out["static_analysis_runs_by_status"] = status_counts

    out["static_analysis_findings_total"] = _scalar(
        """
        SELECT COUNT(*) FROM static_analysis_findings f
        INNER JOIN static_analysis_runs r ON r.id = f.run_id
        WHERE r.session_stamp = %s
        """,
        (session,),
    )

    out["static_permission_matrix_rows"] = _scalar(
        """
        SELECT COUNT(*) FROM static_permission_matrix m
        WHERE m.run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )

    out["static_permission_risk_vnext_rows"] = _scalar(
        """
        SELECT COUNT(*) FROM static_permission_risk_vnext p
        WHERE p.run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )

    out["static_string_summary_rows"] = _scalar(
        "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp=%s",
        (session,),
    )

    out["permission_audit_apps_rows"] = _scalar(
        """
        SELECT COUNT(*) FROM permission_audit_apps a
        WHERE a.static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )

    # Matrix / risk skew: one side has rows, the other does not (same static_run_id)
    skew_sql = """
        SELECT COUNT(*) FROM static_analysis_runs sar
        WHERE sar.session_stamp = %s
          AND (
            (
              (SELECT COUNT(*) FROM static_permission_matrix m WHERE m.run_id = sar.id) > 0
              AND (SELECT COUNT(*) FROM static_permission_risk_vnext r WHERE r.run_id = sar.id) = 0
            )
            OR (
              (SELECT COUNT(*) FROM static_permission_matrix m WHERE m.run_id = sar.id) = 0
              AND (SELECT COUNT(*) FROM static_permission_risk_vnext r WHERE r.run_id = sar.id) > 0
            )
          )
    """
    out["matrix_risk_mismatch_run_count"] = _scalar(skew_sql, (session,))

    # Per-run detail for operator (package via join)
    detail_rows = _fetch_all(
        """
        SELECT
          sar.id AS static_run_id,
          UPPER(COALESCE(sar.status, '')) AS status,
          a.package_name AS package_name,
          (SELECT COUNT(*) FROM static_permission_matrix m WHERE m.run_id = sar.id) AS matrix_rows,
          (SELECT COUNT(*) FROM static_permission_risk_vnext r WHERE r.run_id = sar.id) AS risk_rows,
          (SELECT COUNT(*) FROM static_analysis_findings f WHERE f.run_id = sar.id) AS findings_rows
        FROM static_analysis_runs sar
        INNER JOIN app_versions av ON av.id = sar.app_version_id
        INNER JOIN apps a ON a.id = av.app_id
        WHERE sar.session_stamp = %s
        ORDER BY a.package_name, sar.id
        """,
        (session,),
    )
    packages: list[dict[str, Any]] = []
    for row in detail_rows:
        if isinstance(row, dict) and row.get("_error"):
            out["per_run_detail_error"] = row["_error"]
            packages = []
            break
        if isinstance(row, dict):
            packages.append(
                {
                    "static_run_id": int(row["static_run_id"]) if row.get("static_run_id") is not None else None,
                    "status": row.get("status"),
                    "package_name": row.get("package_name"),
                    "matrix_rows": int(row.get("matrix_rows") or 0),
                    "risk_rows": int(row.get("risk_rows") or 0),
                    "findings_rows": int(row.get("findings_rows") or 0),
                }
            )
        elif isinstance(row, (tuple, list)) and len(row) >= 6:
            packages.append(
                {
                    "static_run_id": int(row[0]) if row[0] is not None else None,
                    "status": str(row[1] or ""),
                    "package_name": str(row[2] or ""),
                    "matrix_rows": int(row[3] or 0),
                    "risk_rows": int(row[4] or 0),
                    "findings_rows": int(row[5] or 0),
                }
            )
    out["per_run_packages"] = packages

    return out


# ---------------------------------------------------------------------------
# Persistence audit (post-run JSON)
# ---------------------------------------------------------------------------


def _load_persistence_audit(session: str, output_dir: Path) -> dict[str, Any]:
    base = output_dir / "audit" / "persistence"
    for suffix in ("persistence_audit", "missing_run_ids"):
        path = base / f"{session}_{suffix}.json"
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {"present": True, "path": str(path), "parse_error": True}
            if isinstance(payload, dict):
                return {"present": True, "path": str(path), "payload": payload}
    return {"present": False, "path": None}


def _summarize_persistence_failures(audit: dict[str, Any]) -> dict[str, Any]:
    payload = audit.get("payload")
    if not isinstance(payload, dict):
        return {
            "failure_row_count": None,
            "missing_static_run_id_count": None,
            "outcome_persistence_failed": None,
        }

    missing = int(payload.get("missing_static_run_id_count") or 0)
    outcome = payload.get("outcome")
    outcome_pf = None
    if isinstance(outcome, dict):
        outcome_pf = bool(outcome.get("persistence_failed"))

    rows = payload.get("rows")
    failure_rows = 0
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("missing_static_run_id"):
                failure_rows += 1
                continue
            cls = str(row.get("classification") or "").lower()
            stage = str(row.get("stage") or "").lower()
            if cls and cls not in {"ok", "completed"}:
                failure_rows += 1
            elif stage and stage not in {"completed", "ok", ""}:
                failure_rows += 1
    return {
        "missing_static_run_id_count": missing,
        "failure_row_count": failure_rows,
        "artifact_kind": payload.get("artifact_kind"),
        "outcome_persistence_failed": outcome_pf,
    }


# ---------------------------------------------------------------------------
# Run health discovery
# ---------------------------------------------------------------------------


def _find_run_health_files(session: str, *, output_dir: Path, analysis_apk_root: Path) -> list[str]:
    try:
        from scytaledroid.StaticAnalysis.cli.execution.run_health.cli_output import (
            sanitize_session_stamp_for_filename,
        )

        stamp = sanitize_session_stamp_for_filename(session)
    except ImportError:
        stamp = re.sub(r"[^A-Za-z0-9._-]+", "_", session.strip())[:120]

    name = f"{stamp}_run_health.json"
    found: list[Path] = []
    for root in (output_dir, analysis_apk_root):
        if root.is_dir():
            for p in root.rglob(name):
                if p.is_file():
                    found.append(p.resolve())
    # de-dupe
    seen: set[str] = set()
    out: list[str] = []
    for p in sorted(found):
        s = str(p)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# ---------------------------------------------------------------------------
# Artifact family classification (model snapshot)
# ---------------------------------------------------------------------------


def _artifact_family_map(
    *,
    session: str,
    paths: dict[str, Path],
) -> list[dict[str, str]]:
    """Static classification table for key paths (executable spec from lifecycle doc)."""

    sel = paths["selection_json"]
    arch = paths["archive_dir"]
    pers = paths["persistence_json"]
    miss = paths["missing_run_ids"]
    perm = paths["perm_snapshot"]
    latest_j = paths["latest_json_dir"]
    latest_h = paths["html_latest"]
    dyn = paths["dynamic_audit_dir"]
    perm_audit_dir = paths.get("perm_audit_dir")
    static_log = paths["static_log"]
    db_log = paths["db_log"]
    lock = paths["lock_path"]
    report_out = paths.get("default_report_path")

    rows: list[dict[str, str]] = []

    def add(path: Path, family: str, note: str) -> None:
        rows.append({"path": str(path), "family": family, "note": note})

    add(sel, "evidence_required", "Selection contract / scope manifest for this session.")
    add(arch, "evidence_required", "Session-scoped report JSON archive (content-addressed stems).")
    add(perm, "evidence_required", "Permission audit snapshot.json (when workflow ran).")
    if perm_audit_dir is not None:
        add(
            perm_audit_dir,
            "evidence_required",
            "Permission audit session dir: snapshot.json + apps/*.json are session evidence; correlation.csv is diagnostics export.",
        )
    add(pers, "diagnostics_required", "Persistence audit JSON (post-run).")
    add(miss, "diagnostics_required", "Missing static_run_id audit variant.")
    add(latest_j, "latest_mirror", "Global JSON by report hash; not session-scoped; not sole evidence.")
    add(latest_h, "latest_mirror", "HTML overwritten per package/artifact slug.")
    add(
        dyn,
        "separate_workflow",
        "NOT static session evidence: dynamic/paper-readiness audits under output/audit/dynamic — "
        "do not treat as static scanner proof (kept beside static audit folders for operator convenience only).",
    )
    add(static_log, "diagnostics_optional", "Static category log (append); filter by session in messages.")
    add(db_log, "diagnostics_optional", "Database logger channel; distinct from static log stream.")
    add(lock, "operator_state", "Coordination lock file when present.")
    if report_path := report_out:
        add(report_path, "diagnostics_required", "Written by this script when --write-report is used.")

    # Repo-relative evidence tree (cwd-dependent)
    add(
        Path("evidence") / "static_runs",
        "evidence_required",
        "Handoff/manifest evidence per static_run_id (path is cwd-relative when CLI runs).",
    )

    return rows


# ---------------------------------------------------------------------------
# Audit envelope: metadata, evidence/static_runs, verdict, strict checks
# ---------------------------------------------------------------------------


def _try_git_commit_short(repo: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    line = (proc.stdout or "").strip()
    return line or None


def _as_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _discover_evidence_static_runs(repo: Path, static_run_ids: list[int | None]) -> dict[str, Any]:
    root = (repo / "evidence" / "static_runs").resolve()
    out: dict[str, Any] = {
        "resolved_root": str(root),
        "root_exists": root.is_dir(),
        "cwd_note": "Paths are resolved from repo cwd at audit time (matches CLI cwd-relative evidence model).",
        "per_static_run_id": [],
        "unscoped_child_dir_count": None,
        "unscoped_child_dir_sample": [],
    }
    seen: set[int] = set()
    for rid in static_run_ids:
        if rid is None:
            continue
        try:
            ir = int(rid)
        except (TypeError, ValueError):
            continue
        if ir in seen:
            continue
        seen.add(ir)
        d = (root / str(ir)).resolve()
        out["per_static_run_id"].append(
            {
                "static_run_id": ir,
                "path": str(d),
                "present": d.is_dir(),
            }
        )
    if root.is_dir():
        try:
            child_dirs = sorted(p.name for p in root.iterdir() if p.is_dir())
            out["unscoped_child_dir_count"] = len(child_dirs)
            out["unscoped_child_dir_sample"] = child_dirs[:24]
        except OSError:
            out["unscoped_child_dir_count"] = None
    return out


def _strict_violations(report: dict[str, Any]) -> list[str]:
    """Violations when the session looks fully scanned on disk (archive == selection == unique log paths)."""

    violations: list[str] = []
    sc = report.get("selection_contract") or {}
    ev = report.get("per_artifact_scanner_evidence") or {}
    db = report.get("per_app_db_projection") or {}
    pr = (report.get("post_run_diagnostics") or {}).get("persistence_audit") or {}
    audit_opts = report.get("audit_options") if isinstance(report.get("audit_options"), dict) else {}

    sel_n = _as_int(sc.get("artifact_count"))
    arch = _as_int(ev.get("archived_json_count")) or 0
    unique_paths = _as_int(ev.get("unique_archive_path_count"))
    if unique_paths is None:
        unique_paths = _as_int(ev.get("report_saved_unique_archive_path_count"))
    if unique_paths is None:
        unique_paths = _as_int(ev.get("report_saved_event_count"))
    if unique_paths is None:
        unique_paths = 0
    missing_path_ev = _as_int(ev.get("report_saved_events_missing_archive_path")) or 0
    dup_extra = (
        _as_int(ev.get("duplicate_archive_event_extra_count"))
        or _as_int(ev.get("duplicate_report_saved_events"))
        or 0
    )

    if sel_n is not None and sel_n > 0 and arch == sel_n == unique_paths:
        if not pr.get("present"):
            violations.append("persistence_audit_missing_when_scan_counts_full")
        gc = _as_int(sc.get("group_count"))
        if db.get("available") and gc is not None:
            by_status = db.get("static_analysis_runs_by_status") or {}
            runs_total = sum(int(v or 0) for v in by_status.values())
            if runs_total != gc:
                violations.append(f"db_run_total_{runs_total}_neq_group_count_{gc}")
            completed = int(by_status.get("COMPLETED") or 0)
            skew = int(db.get("matrix_risk_mismatch_run_count") or 0)
            if completed > 0 and skew > 0:
                violations.append("matrix_risk_skew_on_completed_runs")
        if missing_path_ev > 0:
            violations.append("report_saved_events_missing_archive_path_field")

    if arch != unique_paths and max(arch, unique_paths) > 0:
        violations.append("archived_json_count_ne_unique_archive_path_in_log")

    db_completed = 0
    if db.get("available"):
        db_completed = int((db.get("static_analysis_runs_by_status") or {}).get("COMPLETED") or 0)
    if db_completed > 0 and not sc.get("present"):
        violations.append("selection_manifest_missing_but_db_has_completed_runs")

    if audit_opts.get("strict_log_duplicates") and dup_extra > 0:
        violations.append("duplicate_report_saved_events")

    return violations


def _build_evidence_invariant_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Compact counts + OK/WARN for human output and JSON consumers."""

    sc = report.get("selection_contract") or {}
    ev = report.get("per_artifact_scanner_evidence") or {}
    sel = sc.get("artifact_count")
    arch = ev.get("archived_json_count")
    uniq = ev.get("unique_archive_path_count")
    raw = ev.get("raw_report_saved_event_count")
    dup_ex_i = _as_int(ev.get("duplicate_archive_event_extra_count")) or 0
    miss_disk = len(ev.get("archive_paths_in_log_missing_on_disk") or [])
    miss_log = len(ev.get("archive_paths_on_disk_not_in_log_events") or [])
    bad = _as_int(ev.get("bad_json_count")) or 0
    miss_path_ev = _as_int(ev.get("report_saved_events_missing_archive_path")) or 0

    try:
        sel_n = int(sel) if sel is not None else None
    except (TypeError, ValueError):
        sel_n = None
    try:
        arch_n = int(arch) if arch is not None else None
    except (TypeError, ValueError):
        arch_n = None
    try:
        uniq_n = int(uniq) if uniq is not None else None
    except (TypeError, ValueError):
        uniq_n = None

    invariant_holds = bool(sel_n is not None and arch_n == sel_n == uniq_n and uniq_n > 0)

    if bad > 0 or miss_disk > 0:
        evidence_result = "ERROR"
    elif miss_log > 0 or not invariant_holds:
        evidence_result = "WARN"
    else:
        evidence_result = "OK"

    if dup_ex_i > 0 or miss_path_ev > 0:
        log_result = "WARN"
    else:
        log_result = "OK"

    return {
        "selection_artifact_count": sel,
        "archived_json_count": arch,
        "unique_archive_path_count": uniq,
        "raw_report_saved_event_count": raw,
        "duplicate_archive_event_extra_count": dup_ex_i,
        "evidence_result": evidence_result,
        "log_result": log_result,
        "evidence_invariant_holds": invariant_holds,
    }


def _explain_report_saved_duplicates(
    report: Mapping[str, Any],
    *,
    evidence_invariant: bool,
) -> dict[str, Any]:
    """Classify duplicate ``report.saved`` rows when evidence files still align."""

    ev = report.get("per_artifact_scanner_evidence") or {}
    dup_ev = _as_int(ev.get("duplicate_archive_event_extra_count")) or 0
    samples = ev.get("duplicate_archive_path_samples") or []
    sample_rows = [row for row in samples if isinstance(row, Mapping)]

    parity = (report.get("permission_audit_directory") or {}).get("changed_parity_packages") or []
    parity_packages = {
        str(row.get("package_name") or "").strip().lower()
        for row in parity
        if isinstance(row, Mapping)
    }
    parity_packages.discard("")

    duplicate_packages: set[str] = set()
    samples_without_package = 0
    for row in sample_rows:
        names = row.get("package_names")
        if isinstance(names, list):
            row_pkgs = {str(name).strip().lower() for name in names if str(name).strip()}
            duplicate_packages.update(row_pkgs)
            if not row_pkgs:
                samples_without_package += 1
        else:
            samples_without_package += 1

    unexplained = sorted(duplicate_packages - parity_packages)
    explained = bool(
        evidence_invariant
        and dup_ev > 0
        and duplicate_packages
        and not samples_without_package
        and not unexplained
        and parity_packages
    )
    status = "none"
    reason = "no_duplicate_report_saved_events"
    if dup_ev > 0:
        if explained:
            status = "explained"
            reason = "permission_snapshot_parity_regenerated_reports"
        else:
            status = "needs_review"
            reason = "unmatched_or_unattributed_duplicate_report_saved_events"

    return {
        "status": status,
        "reason": reason,
        "duplicate_archive_event_extra_count": dup_ev,
        "duplicate_archive_path_sample_count": len(sample_rows),
        "duplicate_packages": sorted(duplicate_packages),
        "parity_regenerated_packages": sorted(parity_packages),
        "unexplained_duplicate_packages": unexplained,
        "samples_without_package": samples_without_package,
        "evidence_invariant_holds": evidence_invariant,
    }


def _harvest_receipt_linkage_incomplete_audit(
    audit_opts: Mapping[str, Any],
    harvest_linkage: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Return (incomplete, warning lines) when receipt linkage was requested but could not fully map store paths."""

    if not audit_opts.get("include_harvest_receipt_linkage") or harvest_linkage.get("skipped"):
        return False, []
    rpe = harvest_linkage.get("receipt_pull_enrichment")
    rpe = rpe if isinstance(rpe, dict) else {}
    store_apk_n = int(harvest_linkage.get("apk_paths_resolving_to_content_store") or 0)
    mapped_apk_n = int(rpe.get("apk_paths_with_receipt_pull_mapping") or 0)
    receipts_read_n = int(rpe.get("receipt_json_files_opened") or 0)
    if store_apk_n <= 0:
        return False, []
    if receipts_read_n == 0:
        return True, [
            "Harvest receipt linkage enabled but no harvest receipt JSON files were read — "
            "check data/receipts/harvest session directory names vs selection session_stamp/capture_id, "
            "or receipt layout."
        ]
    if mapped_apk_n < store_apk_n:
        return True, [
            f"Harvest receipt linkage incomplete: mapped {mapped_apk_n}/{store_apk_n} content-store APK paths "
            "to pull paths — missing or stale observed_artifacts rows, or receipt session filter too narrow."
        ]
    return False, []


def _finalize_artifact_envelope(
    report: dict[str, Any],
    *,
    repo: Path,
    no_db: bool,
    data_dir: Path,
    output_dir: Path,
    logs_dir: Path,
    analysis_apk_root: Path,
    app_version: str | None,
) -> None:
    report["evidence_invariant_summary"] = _build_evidence_invariant_summary(report)

    sc = report.get("selection_contract") or {}
    ev = report.get("per_artifact_scanner_evidence") or {}
    db = report.get("per_app_db_projection") or {}
    pr = (report.get("post_run_diagnostics") or {}).get("persistence_audit") or {}
    lm = report.get("latest_mirrors") or {}

    sel_present = bool(sc.get("present"))
    gc = _as_int(sc.get("group_count"))
    sel_art = _as_int(sc.get("artifact_count"))
    archived = int(ev.get("archived_json_count") or 0)
    raw_log = int(
        ev.get("raw_report_saved_event_count")
        or ev.get("report_saved_raw_event_count")
        or ev.get("report_saved_event_count")
        or 0
    )
    unique_n = int(ev.get("unique_archive_path_count") or ev.get("report_saved_unique_archive_path_count") or 0)
    dup_ev = int(ev.get("duplicate_archive_event_extra_count") or ev.get("duplicate_report_saved_events") or 0)
    dup_path_n = int(ev.get("duplicate_archive_path_count") or 0)
    miss_path_ev = int(ev.get("report_saved_events_missing_archive_path") or 0)
    evidence_invariant = (
        sel_art is not None
        and archived == sel_art == unique_n
        and unique_n > 0
    )
    duplicate_explanation = _explain_report_saved_duplicates(
        report,
        evidence_invariant=evidence_invariant,
    )
    bad_json = int(ev.get("bad_json_count") or 0)
    miss_disk = len(ev.get("archive_paths_in_log_missing_on_disk") or [])
    miss_log = len(ev.get("archive_paths_on_disk_not_in_log_events") or [])
    dup_html = int(lm.get("duplicate_html_path_count_from_logs") or 0)

    db_available = bool(db.get("available"))
    db_skipped = bool(db.get("skipped"))
    by_status: dict[str, int] = dict(db.get("static_analysis_runs_by_status") or {})
    runs_total = sum(int(v or 0) for v in by_status.values()) if by_status else 0
    completed = int(by_status.get("COMPLETED") or 0)
    started = int(by_status.get("STARTED") or 0)
    skew = int(db.get("matrix_risk_mismatch_run_count") or 0)

    pf = db.get("persistence_failures") or {}
    pers_failed = bool(pf.get("outcome_persistence_failed"))

    static_run_ids: list[int | None] = []
    for row in db.get("per_run_packages") or []:
        if isinstance(row, dict):
            static_run_ids.append(row.get("static_run_id"))

    evidence_root = _discover_evidence_static_runs(repo, static_run_ids)

    warnings: list[str] = []
    if not sel_present and archived == 0 and db_available and completed > 0:
        warnings.append("Selection manifest missing and archive empty, but DB shows COMPLETED runs — check session_stamp vs cohort that produced DB rows.")
    if not sel_present and archived > 0:
        warnings.append("Selection manifest missing — session stamp may be wrong or manifest was never written for this string.")
    if sel_art is not None and archived < sel_art:
        warnings.append("Archive count below selection artifact_count — scan likely still in progress.")
    if sel_art is not None and archived == sel_art == unique_n and unique_n > 0 and not pr.get("present"):
        warnings.append("Per-artifact counts match selection but persistence audit not present yet — post-run finalization may still be running.")
    if dup_ev > 0:
        if duplicate_explanation.get("status") == "explained":
            pass
        elif evidence_invariant:
            warnings.append(
                "Raw report.saved log events include duplicate archive_path entries; "
                "on-disk session archive count still matches selection (unique paths aligned)."
            )
        else:
            warnings.append(
                f"Log duplication: {dup_ev} extra report.saved line(s) for repeated archive_path "
                f"(raw={raw_log}, unique={unique_n}). Investigate if archive/selection counts disagree."
            )
    if miss_path_ev > 0:
        warnings.append(
            f"{miss_path_ev} report.saved event(s) omit archive_path — inspect JSONL/log field shape."
        )
    if unique_n > 0 and archived != unique_n:
        warnings.append(
            f"Evidence alignment: archived_json_count ({archived}) != unique archive_path in log ({unique_n})."
        )
    if miss_disk:
        warnings.append(f"{miss_disk} archive path(s) referenced in logs are missing on disk under the session archive dir.")
    if miss_log:
        warnings.append(f"{miss_log} on-disk archive JSON file(s) have no matching report.saved path in the log stream (stale or alternate logger).")
    if bad_json:
        warnings.append(f"{bad_json} archive JSON file(s) failed parse — evidence integrity issue.")
    if dup_html and not (
        duplicate_explanation.get("status") == "explained"
        and dup_html == dup_ev
    ):
        warnings.append(f"Log stream lists duplicate html_path values ({dup_html}) — expected for some workflows but worth spot-checking.")
    if db_available and gc is not None and runs_total > 0 and runs_total != gc:
        warnings.append(f"DB static_analysis_runs row count ({runs_total}) != selection group_count ({gc}).")
    if db_available and completed > 0 and skew > 0:
        warnings.append(f"{skew} run(s) show matrix vs permission_risk_vnext skew — suspicious for COMPLETED rows.")
    if pers_failed:
        warnings.append("Persistence audit payload indicates outcome.persistence_failed — inspect persistence JSON.")

    audit_opts = report.get("audit_options") if isinstance(report.get("audit_options"), dict) else {}
    hl_fin = report.get("harvest_linkage") or {}
    harvest_receipt_linkage_incomplete, receipt_warns = _harvest_receipt_linkage_incomplete_audit(
        audit_opts, hl_fin if isinstance(hl_fin, dict) else {}
    )
    warnings.extend(receipt_warns)
    rpe_coll = hl_fin.get("receipt_pull_enrichment") if isinstance(hl_fin.get("receipt_pull_enrichment"), dict) else {}
    coll_n = int(rpe_coll.get("canonical_pull_path_collisions") or 0)
    if audit_opts.get("include_harvest_receipt_linkage") and coll_n > 0:
        warnings.append(
            f"Harvest receipt linkage: {coll_n} canonical_store_path key(s) pointed at different pull paths "
            "across receipt rows — last indexed row wins; investigate duplicate harvest sessions or retagged pulls."
        )

    # Evidence / DB severity. Raw duplicate report.saved lines are log-stream
    # telemetry; when disk, selection, and unique archive paths align they should
    # not downgrade evidence integrity.
    if bad_json > 0 or miss_disk > 0:
        evidence_status = "ERROR"
    elif (
        miss_log > 0
        or miss_path_ev > 0
        or (unique_n > 0 and archived != unique_n)
        or harvest_receipt_linkage_incomplete
    ):
        evidence_status = "WARN"
    else:
        evidence_status = "OK"

    if no_db or db_skipped:
        db_status = "SKIPPED"
    elif not db_available:
        db_status = "WARN"
    elif started > 0 and completed == 0:
        db_status = "NOT_FINALIZED"
    elif sel_art is not None and archived == sel_art == unique_n and unique_n > 0 and gc is not None and runs_total < gc:
        db_status = "NOT_FINALIZED"
    elif gc is not None and runs_total != gc and runs_total > 0:
        db_status = "WARN"
    elif completed > 0 and skew > 0:
        db_status = "WARN"
    else:
        db_status = "OK"

    severity_order = {"OK": 0, "WARN": 1, "ERROR": 2, "SKIPPED": 0, "NOT_FINALIZED": 1}
    sev_ev = severity_order.get(evidence_status, 0)
    sev_db = severity_order.get(db_status, 0)
    if db_status == "SKIPPED":
        sev_db = 0
    severity_max_rank = max(sev_ev, sev_db)
    severity_max = {0: "OK", 1: "WARN", 2: "ERROR"}[severity_max_rank]

    # Session state (operator-facing)
    session_state = "UNKNOWN"
    action = "inspect_mismatches"
    if bad_json > 0 or pers_failed:
        session_state = "FAILED_OR_DIRTY"
        action = "inspect_errors_and_logs"
    elif sel_present and sel_art is not None and archived < sel_art:
        session_state = "IN_PROGRESS"
        action = "wait_for_scan_completion"
    elif (
        sel_present
        and sel_art is not None
        and archived == sel_art == unique_n
        and unique_n > 0
        and not pr.get("present")
    ):
        session_state = "SCAN_COMPLETE_PERSISTENCE_PENDING"
        action = "wait_for_post_run_persistence"
    elif pr.get("present") and sel_present and sel_art is not None and archived == sel_art == unique_n and unique_n > 0:
        has_log_dup = dup_ev > 0 or (raw_log > unique_n and unique_n > 0)
        log_dup_explained = has_log_dup and duplicate_explanation.get("status") == "explained"
        if no_db:
            if log_dup_explained:
                session_state = "COMPLETE_WITH_EXPLAINED_LOG_DUPLICATES"
                action = "none"
            elif has_log_dup:
                session_state = "COMPLETE_WITH_LOG_WARNINGS"
                action = "review_log_duplication"
            else:
                session_state = "COMPLETE"
                action = "none"
        elif gc is not None and completed == gc and started == 0:
            if skew > 0:
                session_state = "COMPLETE_WITH_WARNINGS"
                action = "review_matrix_risk_skew"
            elif log_dup_explained:
                session_state = "COMPLETE_WITH_EXPLAINED_LOG_DUPLICATES"
                action = "none"
            elif has_log_dup:
                session_state = "COMPLETE_WITH_LOG_WARNINGS"
                action = "review_log_duplication"
            else:
                session_state = "COMPLETE"
                action = "none"
        else:
            session_state = "COMPLETE_WITH_WARNINGS"
            action = "inspect_db_vs_selection"
    elif not sel_present and db_available and completed > 0 and archived == 0:
        session_state = "STAMP_OR_ARTIFACT_MISMATCH"
        action = "verify_session_stamp_and_paths"
    elif db_available and completed > 0 and skew > 0:
        session_state = "COMPLETE_WITH_WARNINGS" if pr.get("present") else "UNKNOWN"
        action = "review_matrix_risk_skew"

    verdict = {
        "session_state": session_state,
        "evidence_status": evidence_status,
        "db_projection_status": db_status,
        "latest_mirrors_note": "Latest JSON / latest HTML are present as mirrors — not authoritative run-scoped evidence.",
        "action_needed": action,
        "severity_max": severity_max,
        "log_stream": {
            "raw_report_saved_event_count": raw_log,
            "unique_archive_path_count": unique_n,
            "duplicate_archive_path_count": dup_path_n,
            "duplicate_archive_event_extra_count": dup_ev,
            "evidence_invariant_selection_archive_unique": evidence_invariant,
            "log_duplication_without_evidence_gap": bool(evidence_invariant and dup_ev > 0),
            "duplicate_explanation": duplicate_explanation,
        },
        "harvest_receipt_linkage_incomplete": harvest_receipt_linkage_incomplete,
    }

    git_short = _try_git_commit_short(repo)
    report["audit_metadata"] = {
        "script_path": str(SCRIPT_PATH),
        "generated_at_utc": report.get("generated_at_utc"),
        "scytale_app_version": app_version,
        "git_commit_short": git_short,
        "db_enabled": not no_db,
        "resolved_paths": {
            "DATA_DIR": str(data_dir.resolve()),
            "OUTPUT_DIR": str(output_dir.resolve()),
            "LOGS_DIR": str(logs_dir.resolve()),
            "analysis_apk_root": str(analysis_apk_root.resolve()),
            "evidence_static_runs_root": str((repo / "evidence" / "static_runs").resolve()),
            "repo_cwd": str(repo.resolve()),
        },
        "selection_manifest_sha256": sc.get("artifact_manifest_sha256"),
    }
    report["evidence_static_runs_resolution"] = evidence_root
    report["artifact_audit_verdict"] = verdict
    report["warnings"] = warnings
    report["strict_violations"] = _strict_violations(report)


# ---------------------------------------------------------------------------
# Build full report
# ---------------------------------------------------------------------------


def build_artifact_map_report(
    session: str,
    *,
    repo: Path | None = None,
    no_db: bool = False,
    include_harvest_linkage: bool = False,
    include_harvest_receipt_linkage: bool = False,
    strict_log_duplicates: bool = False,
) -> dict[str, Any]:
    repo = repo or Path.cwd()

    from scytaledroid.Config import app_config
    from scytaledroid.DeviceAnalysis.services import artifact_store
    from scytaledroid.StaticAnalysis.cli.execution.run_health.cli_output import sanitize_session_stamp_for_filename
    from scytaledroid.Utils.evidence_store import filesystem_safe_slug

    data_dir = Path(app_config.DATA_DIR)
    output_dir = Path(app_config.OUTPUT_DIR)
    logs_dir = Path(app_config.LOGS_DIR)
    analysis_apk_root = artifact_store.analysis_apk_root().resolve()

    archive_dir = data_dir / "static_analysis" / "reports" / "archive" / session
    latest_json_dir = data_dir / "static_analysis" / "reports" / "latest"
    html_latest = output_dir / "reports" / "static" / "latest"
    selection_json = output_dir / "audit" / "selection" / f"{session}_selected_artifacts.json"
    persistence_json = output_dir / "audit" / "persistence" / f"{session}_persistence_audit.json"
    missing_run_ids = output_dir / "audit" / "persistence" / f"{session}_missing_run_ids.json"
    perm_audit_root = data_dir / "audit" / filesystem_safe_slug(f"perm-audit:app:{session}")
    perm_snapshot = perm_audit_root / "snapshot.json"
    lock_path = data_dir / "locks" / "static_analysis.lock"
    static_log = logs_dir / "static_analysis.log"
    static_jsonl = logs_dir / "static_analysis.jsonl"
    db_log = logs_dir / "db.log"
    dynamic_audit_dir = output_dir / "audit" / "dynamic"

    safe = sanitize_session_stamp_for_filename(session)
    default_report_path = output_dir / "audit" / "run_artifacts" / f"{safe}_artifact_map.json"

    selection = _load_selection(selection_json)
    archive_paths, bad_json_count, bad_json_samples = _audit_archive_json_files(archive_dir)
    archived_count = len(archive_paths)
    archive_stems = {p.stem for p in archive_paths}

    log_events, log_source = _collect_report_saved_events(session, jsonl_path=static_jsonl, log_path=static_log)
    log_n = len(log_events)
    log_path_rollup = _rollup_report_saved_archive_paths(log_events, repo=repo)

    logged_archive_resolved: set[str] = set()
    html_paths_nonempty: list[str] = []
    for ev in log_events:
        ap = _event_archive_path(ev, repo=repo)
        if ap is not None:
            logged_archive_resolved.add(str(ap.resolve()))
        hp = _event_html_path(ev, repo=repo)
        if hp is not None:
            html_paths_nonempty.append(str(hp.resolve()))

    disk_archive_resolved = {str(p.resolve()) for p in archive_paths}

    missing_on_disk_from_logs = sorted(logged_archive_resolved - disk_archive_resolved)
    # "Missing from logs" — archive files not referenced by any log event path
    missing_in_logs_from_disk = sorted(disk_archive_resolved - logged_archive_resolved)

    pkg_counter: Counter[str] = Counter()
    for ev in log_events:
        pkg = _event_package(ev)
        if pkg:
            pkg_counter[pkg] += 1

    top_packages = [{"package_name": p, "report_saved_count": c} for p, c in pkg_counter.most_common(15)]

    selection_artifact_count: int | None = None
    split_heavy: list[dict[str, Any]] = []
    if selection:
        try:
            selection_artifact_count = int(selection.get("artifact_count") or 0)
        except (TypeError, ValueError):
            selection_artifact_count = None
        apps = selection.get("apps")
        if isinstance(apps, list):
            for row in apps:
                if not isinstance(row, dict):
                    continue
                try:
                    ac = int(row.get("artifact_count") or 0)
                except (TypeError, ValueError):
                    ac = 0
                if ac >= 2:
                    split_heavy.append(
                        {
                            "package_name": row.get("package_name"),
                            "artifact_count": ac,
                            "group_key": row.get("group_key"),
                        }
                    )
            split_heavy.sort(key=lambda x: (-int(x.get("artifact_count") or 0), str(x.get("package_name") or "")))

    delta_archive_vs_selection: int | None = None
    if selection_artifact_count is not None:
        delta_archive_vs_selection = archived_count - selection_artifact_count

    latest_json_total = _count_files(latest_json_dir, "*.json")
    overlap = sum(1 for stem in archive_stems if (latest_json_dir / f"{stem}.json").is_file())
    latest_html_total = _count_files(html_latest, "*.html")

    uniq_html = sorted(set(html_paths_nonempty))
    dup_html_count = max(0, len(html_paths_nonempty) - len(uniq_html))

    db_projection: dict[str, Any] = {"skipped": True, "reason": "no_db_flag"}
    if not no_db:
        db_projection = _db_audit(session)

    persistence_audit = _load_persistence_audit(session, output_dir)
    persistence_summary = _summarize_persistence_failures(persistence_audit)
    if isinstance(db_projection, dict):
        db_projection["persistence_failures"] = persistence_summary

    db_perm_rows: int | None = None
    if isinstance(db_projection, dict) and db_projection.get("available"):
        prn = db_projection.get("permission_audit_apps_rows")
        if isinstance(prn, int):
            db_perm_rows = prn
        elif prn is not None:
            try:
                db_perm_rows = int(prn)
            except (TypeError, ValueError):
                db_perm_rows = None

    permission_audit_directory = _permission_audit_directory_audit(
        perm_audit_root=perm_audit_root,
        repo=repo,
        db_permission_audit_apps_rows=db_perm_rows,
    )
    permission_audit_directory["changed_parity_packages"] = (
        _collect_permission_parity_generated_packages(
            session=session,
            jsonl_path=static_jsonl,
        )
    )
    if permission_audit_directory["changed_parity_packages"]:
        permission_audit_directory["changed_parity_note"] = (
            "Packages listed here were regenerated during permission snapshot parity; "
            "matching duplicate report.saved paths are expected secondary saves."
        )

    harvest_linkage: dict[str, Any]
    if include_harvest_linkage or include_harvest_receipt_linkage:
        receipt_map: dict[str, str] | None = None
        receipt_stats: dict[str, int] | None = None
        if include_harvest_receipt_linkage and selection:
            receipt_map, receipt_stats = _harvest_receipt_canonical_to_pull_map(
                selection,
                repo=repo,
                receipts_root=artifact_store.harvest_receipts_root().resolve(),
                device_apks_root=artifact_store.device_apks_root().resolve(),
            )
        harvest_linkage = _harvest_linkage_from_selection(
            selection,
            repo=repo,
            receipt_pull_by_canonical=receipt_map if include_harvest_receipt_linkage and selection else None,
            receipt_scan_stats=receipt_stats if include_harvest_receipt_linkage and selection else None,
        )
    else:
        harvest_linkage = {"skipped": True, "reason": "omit --include-harvest-linkage"}

    run_health_paths = _find_run_health_files(session, output_dir=output_dir, analysis_apk_root=analysis_apk_root)

    path_bundle = {
        "selection_json": selection_json,
        "archive_dir": archive_dir,
        "persistence_json": persistence_json,
        "missing_run_ids": missing_run_ids,
        "perm_snapshot": perm_snapshot,
        "perm_audit_dir": perm_audit_root,
        "latest_json_dir": latest_json_dir,
        "html_latest": html_latest,
        "dynamic_audit_dir": dynamic_audit_dir,
        "static_log": static_log,
        "db_log": db_log,
        "lock_path": lock_path,
        "default_report_path": default_report_path,
    }

    report: dict[str, Any] = {
        "session_stamp": session,
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "repo_cwd": str(repo.resolve()),
        "selection_contract": {
            "path": str(selection_json),
            "present": selection_json.is_file(),
            "session_stamp": selection.get("session_stamp") if selection else None,
            "execution_id": selection.get("execution_id") if selection else None,
            "group_count": selection.get("group_count") if selection else None,
            "artifact_count": selection.get("artifact_count") if selection else None,
            "artifact_manifest_sha256": selection.get("artifact_manifest_sha256") if selection else None,
            "scope": selection.get("scope") if selection else None,
            "scope_label": selection.get("scope_label") if selection else None,
        },
        "per_artifact_scanner_evidence": {
            "archive_dir": str(archive_dir),
            "archive_json_paths": [_rel_display(p, repo) for p in archive_paths],
            "archive_json_paths_sample": [_rel_display(p, repo) for p in archive_paths[:8]],
            "archived_json_count": archived_count,
            "bad_json_count": bad_json_count,
            "bad_json_samples": bad_json_samples,
            "delta_archived_minus_selection_artifact_count": delta_archive_vs_selection,
            "raw_report_saved_event_count": log_path_rollup["raw_report_saved_event_count"],
            "unique_archive_path_count": log_path_rollup["unique_archive_path_count"],
            "duplicate_archive_path_count": log_path_rollup["duplicate_archive_path_count"],
            "duplicate_archive_event_extra_count": log_path_rollup["duplicate_archive_event_extra_count"],
            "duplicate_archive_path_samples": log_path_rollup["duplicate_archive_path_samples"],
            "report_saved_events_missing_archive_path": log_path_rollup["report_saved_events_missing_archive_path"],
            "report_saved_event_count": log_path_rollup["raw_report_saved_event_count"],
            "report_saved_raw_event_count": log_path_rollup["report_saved_raw_event_count"],
            "report_saved_unique_archive_path_count": log_path_rollup["unique_archive_path_count"],
            "duplicate_report_saved_events": log_path_rollup["duplicate_archive_event_extra_count"],
            "log_source": log_source,
            "archive_paths_in_log_missing_on_disk": [_rel_display(Path(p), repo) for p in missing_on_disk_from_logs[:50]],
            "archive_paths_on_disk_not_in_log_events": [_rel_display(Path(p), repo) for p in missing_in_logs_from_disk[:50]],
            "top_packages_by_report_saved_count": top_packages,
            "split_heavy_packages": split_heavy[:40],
        },
        "evidence_vs_log_stream": {
            "evidence_path_alignment": {
                "summary": (
                    "Disk session archive vs unique archive_path values seen on report.saved lines. "
                    "Non-zero missing/unreferenced counts indicate evidence mismatch (not log duplication)."
                ),
                "counts": {
                    "log_missing_on_disk": len(missing_on_disk_from_logs),
                    "disk_unreferenced_in_log": len(missing_in_logs_from_disk),
                },
                "archive_paths_in_log_missing_on_disk": [
                    _rel_display(Path(p), repo) for p in missing_on_disk_from_logs[:50]
                ],
                "archive_paths_on_disk_not_in_log_events": [
                    _rel_display(Path(p), repo) for p in missing_in_logs_from_disk[:50]
                ],
            },
            "report_saved_log_stream": {
                **log_path_rollup,
                "log_source": log_source,
                "evidence_mismatch_vs_log_duplication": {
                    "evidence_mismatch": (
                        "Non-zero log→disk missing or disk→log unreferenced counts, or archived_json_count ≠ "
                        "unique_archive_path_count."
                    ),
                    "log_duplication": (
                        "raw_report_saved_event_count > unique_archive_path_count with duplicate_archive_event_extra_count>0 "
                        "when the invariant selection==archive==unique still holds."
                    ),
                },
                "summary": (
                    "Evidence invariant: selection artifact_count == archived_json_count == unique_archive_path_count. "
                    "Extra raw JSONL lines are log duplication, not missing archive files, when that invariant holds."
                ),
            },
        },
        "permission_audit_directory": permission_audit_directory,
        "harvest_linkage": harvest_linkage,
        "duplicate_report_saved_investigation": {
            "emitter_module": "scytaledroid.StaticAnalysis.persistence.reports",
            "emitter_function": "save_report",
            "code_note": (
                "Only save_report() emits event report.saved (log.info with extra event=REPORT_SAVED). "
                "There is no second logger in that path."
            ),
            "callers": [
                "scan_report.generate_report → save_report (main per-artifact scan via scan_flow).",
                "permission_flow.execute_permission_scan → generate_report → save_report when a full report is "
                "built because reuse_saved_reports could not load a saved on-disk report (parity 'changed' path).",
            ],
            "typical_explanation": (
                "Extra lines with the same archive_path usually mean save_report ran twice for that hash/session: "
                "once during the main scan and again when post-run permission snapshot parity regenerated a report. "
                "The archive file is overwritten; JSONL appends a second telemetry row."
            ),
            "parity_correlation_hint": (
                "When CLI showed permission parity changed=N and reused_saved_report=M, N often matches "
                "duplicate_archive_path_count / duplicate_archive_event_extra_count for unchanged hashes."
            ),
            "one_line_summary": (
                "Duplicates are almost always a second save_report (often permission parity regenerate), not split naming."
            ),
        },
        "latest_mirrors": {
            "latest_json_dir": str(latest_json_dir),
            "latest_json_total_files": latest_json_total,
            "latest_json_session_overlap_count": overlap,
            "note_session_hashes_also_in_latest_dir": (
                "Counts archive stems from this session that also exist as latest/<stem>.json."
            ),
            "html_latest_dir": str(html_latest),
            "latest_html_total_files": latest_html_total,
            "unique_html_path_count_from_logs": len(uniq_html),
            "duplicate_html_path_count_from_logs": dup_html_count,
            "warning": (
                "Latest mirrors (data/.../reports/latest and output/.../static/latest) are not authoritative "
                "evidence: they overwrite or dedupe by hash/package and are not a session-sealed record."
            ),
        },
        "per_app_db_projection": db_projection,
        "post_run_diagnostics": {
            "persistence_audit": {
                "present": bool(persistence_audit.get("present")),
                "path": persistence_audit.get("path"),
                "summary": persistence_summary,
            },
            "permission_audit_snapshot": {
                "present": perm_snapshot.is_file(),
                "path": str(perm_snapshot),
            },
            "run_health_json": {
                "paths": run_health_paths,
                "searched_roots": [str(output_dir.resolve()), str(analysis_apk_root)],
            },
            "db_verification_digest": {
                "note": (
                    "DB verification is emitted to stdout by the static results footer / db_verification module "
                    "during CLI runs; it is not persisted as a standard JSON artifact unless captured manually."
                ),
            },
        },
        "artifact_families": _artifact_family_map(session=session, paths=path_bundle),
        "artifact_family_taxonomy": {
            "evidence_required": [
                "Session archive JSON under data/static_analysis/reports/archive/<session>/",
                "Selection manifest output/audit/selection/<session>_selected_artifacts.json",
                "Permission audit data/audit/perm-audit_app_<session>/snapshot.json and apps/*.json when workflow ran",
                "evidence/static_runs/<id>/ handoff artifacts (cwd-relative)",
            ],
            "diagnostics_required": [
                "Persistence audit output/audit/persistence/<session>_*.json",
                "Permission audit correlation.csv (tabular export) under perm-audit_app_<session>/",
                "Run health *_run_health.json next to analysis_apk_root or under output/",
                "This script's --write-report JSON",
            ],
            "diagnostics_optional": ["logs/static_analysis.log", "logs/static_analysis.jsonl", "logs/db.log"],
            "latest_mirror": [
                "data/static_analysis/reports/latest/<sha>.json",
                "output/reports/static/latest/<package>/*.html",
            ],
            "separate_workflow": [
                "output/audit/dynamic/* (dynamic/paper-readiness — not static scanner session evidence)",
                "output/evidence/dynamic/…",
            ],
            "operator_state": ["data/locks/static_analysis.lock", "DB session rollups / linkage rows"],
            "stale_or_orphaned": [
                "latest/*.json hashes not referenced by any retained session archive",
                "HTML/latest files overwritten without session archive",
            ],
            "unknown_needs_review": [
                "Any path not matching the above; deltas between selection, disk, and logs",
            ],
        },
    }

    report["audit_options"] = {
        "include_harvest_linkage": include_harvest_linkage,
        "include_harvest_receipt_linkage": include_harvest_receipt_linkage,
        "strict_log_duplicates": strict_log_duplicates,
    }

    _finalize_artifact_envelope(
        report,
        repo=repo,
        no_db=no_db,
        data_dir=data_dir,
        output_dir=output_dir,
        logs_dir=logs_dir,
        analysis_apk_root=analysis_apk_root,
        app_version=getattr(app_config, "APP_VERSION", None),
    )

    return report


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------


def _print_evidence_invariant_block(report: dict[str, Any]) -> None:
    s = report.get("evidence_invariant_summary") or _build_evidence_invariant_summary(report)
    print("Evidence invariant")
    print("-" * 44)
    print(f"  Selection artifacts : {s.get('selection_artifact_count')}")
    print(f"  Archived JSON       : {s.get('archived_json_count')}")
    print(f"  Unique log archives : {s.get('unique_archive_path_count')}")
    print(f"  Raw log events      : {s.get('raw_report_saved_event_count')}")
    print(f"  Duplicate log extra : {s.get('duplicate_archive_event_extra_count')}")
    print(f"  Evidence result     : {s.get('evidence_result')}")
    print(f"  Log result          : {s.get('log_result')}")
    inv = report.get("duplicate_report_saved_investigation")
    if isinstance(inv, dict) and inv.get("one_line_summary"):
        print(f"  Telemetry note      : {inv.get('one_line_summary')}")
    print()


def _print_human(report: dict[str, Any], *, repo: Path) -> None:
    session = str(report.get("session_stamp") or "?")
    print()
    print(f"Static run artifact audit — session_stamp={session}")
    print("=" * min(88, max(40, len(session) + 28)))
    print()

    _print_evidence_invariant_block(report)

    meta = report.get("audit_metadata") or {}
    verdict = report.get("artifact_audit_verdict") or {}
    print(f"Inferred session state : {verdict.get('session_state')}")
    print(f"Severity (max)         : {verdict.get('severity_max')}")
    warns = report.get("warnings") or []
    if warns:
        print("Warnings:")
        for w in warns[:12]:
            print(f"  - {w}")
        if len(warns) > 12:
            print(f"  … ({len(warns) - 12} more)")
    print()

    rp = (meta.get("resolved_paths") or {}) if isinstance(meta.get("resolved_paths"), dict) else {}
    if rp:
        print("0) Resolved roots (absolute)")
        print("-" * 44)
        for key in ("DATA_DIR", "OUTPUT_DIR", "LOGS_DIR", "analysis_apk_root", "evidence_static_runs_root"):
            if key in rp:
                print(f"  {key:26s} : {rp[key]}")
        ver = meta.get("scytale_app_version")
        git = meta.get("git_commit_short")
        print(f"  {'app_version':26s} : {ver}")
        print(f"  {'git_commit_short':26s} : {git}")
        print(f"  {'db_enabled':26s} : {meta.get('db_enabled')}")
        print()

    esr = report.get("evidence_static_runs_resolution") or {}
    if esr:
        print("0b) evidence/static_runs (resolved)")
        print("-" * 44)
        print(f"  root                     : {esr.get('resolved_root')} [{'ok' if esr.get('root_exists') else 'missing'}]")
        print(f"  child dirs (unscoped)    : {esr.get('unscoped_child_dir_count')}")
        sample = esr.get("unscoped_child_dir_sample") or []
        if sample:
            print(f"  sample                   : {', '.join(sample[:12])}")
        pr_ids = esr.get("per_static_run_id") or []
        for row in pr_ids[:10]:
            mark = "ok" if row.get("present") else "missing"
            print(f"  run {row.get('static_run_id')} [{mark}] {row.get('path')}")
        if len(pr_ids) > 10:
            print(f"  … ({len(pr_ids) - 10} more run id dir(s))")
        print()

    sc = report.get("selection_contract") or {}
    print("1) Selection contract")
    print("-" * 44)
    sel_path = sc.get("path")
    sel_disp = _rel_display(Path(sel_path), repo) if sel_path else "(unknown)"
    print(f"  path                     : {sel_disp}  [{'ok' if sc.get('present') else 'missing'}]")
    print(f"  session_stamp            : {sc.get('session_stamp')}")
    print(f"  execution_id             : {sc.get('execution_id')}")
    print(f"  apps/group_count         : {sc.get('group_count')}")
    print(f"  artifact_count           : {sc.get('artifact_count')}")
    print(f"  artifact_manifest_sha256 : {sc.get('artifact_manifest_sha256')}")
    print()

    ev = report.get("per_artifact_scanner_evidence") or {}
    print("2) Per-artifact scanner evidence")
    print("-" * 44)
    print(f"  archive_dir              : {ev.get('archive_dir')}")
    print(f"  archived_json_count      : {ev.get('archived_json_count')}")
    print(f"  bad_json_count           : {ev.get('bad_json_count')}")
    if ev.get("bad_json_samples"):
        print(f"  bad_json_samples         : {', '.join(ev['bad_json_samples'])}")
    d = ev.get("delta_archived_minus_selection_artifact_count")
    print(f"  Δ archive − selection    : {d}")
    print("  top packages (log, raw event counts):")
    for row in ev.get("top_packages_by_report_saved_count") or []:
        print(f"      {row.get('package_name')}: {row.get('report_saved_count')}")
    print("  split-heavy (selection)  :")
    for row in (ev.get("split_heavy_packages") or [])[:12]:
        print(f"      {row.get('package_name')}: artifacts={row.get('artifact_count')}")
    print()

    evls = report.get("evidence_vs_log_stream") or {}
    align = evls.get("evidence_path_alignment") or {}
    rsls = evls.get("report_saved_log_stream") or {}
    ac = align.get("counts") or {}
    print("2a) Evidence path alignment (disk ↔ unique log paths)")
    print("-" * 44)
    print(f"  log→disk missing files   : {ac.get('log_missing_on_disk', len(ev.get('archive_paths_in_log_missing_on_disk') or []))}")
    for line in (ev.get("archive_paths_in_log_missing_on_disk") or [])[:8]:
        print(f"      - {line}")
    print(f"  disk→log unreferenced    : {ac.get('disk_unreferenced_in_log', len(ev.get('archive_paths_on_disk_not_in_log_events') or []))}")
    for line in (ev.get("archive_paths_on_disk_not_in_log_events") or [])[:8]:
        print(f"      - {line}")
    print()

    print("2b) report.saved log stream (JSONL / text log)")
    print("-" * 44)
    print(f"  log_source               : {rsls.get('log_source') or ev.get('log_source')}")
    print(f"  raw_report_saved_event_count        : {rsls.get('raw_report_saved_event_count', ev.get('raw_report_saved_event_count'))}")
    print(f"  unique_archive_path_count           : {rsls.get('unique_archive_path_count', ev.get('unique_archive_path_count'))}")
    print(f"  duplicate_archive_path_count        : {rsls.get('duplicate_archive_path_count', ev.get('duplicate_archive_path_count'))}")
    print(f"  duplicate_archive_event_extra_count : {rsls.get('duplicate_archive_event_extra_count', ev.get('duplicate_archive_event_extra_count'))}")
    print(f"  events missing archive_path         : {rsls.get('report_saved_events_missing_archive_path')}")
    samples = rsls.get("duplicate_archive_path_samples") or []
    if samples:
        print("  duplicate_archive_path_samples      :")
        for row in samples[:8]:
            cnt = row.get("event_count") or row.get("report_saved_event_count")
            rel = row.get("archive_path_repo_relative") or row.get("archive_path_resolved") or row.get("log_key")
            print(f"      ×{cnt}  {rel}")
    print()

    lm = report.get("latest_mirrors") or {}
    print("3) Latest mirrors")
    print("-" * 44)
    print(f"  latest JSON total files  : {lm.get('latest_json_total_files')}")
    print(f"  session overlap in latest: {lm.get('latest_json_session_overlap_count')}")
    print(f"  latest HTML total files  : {lm.get('latest_html_total_files')}")
    print(f"  unique html_path (logs)  : {lm.get('unique_html_path_count_from_logs')}")
    print(f"  duplicate html_path      : {lm.get('duplicate_html_path_count_from_logs')}")
    print(f"  WARNING                  : {lm.get('warning')}")
    print()

    db = report.get("per_app_db_projection") or {}
    print("4) Per-app DB projection")
    print("-" * 44)
    if not db.get("available"):
        print(f"  (DB unavailable: {db.get('error') or db.get('reason')})")
    else:
        print(f"  runs_by_status           : {db.get('static_analysis_runs_by_status')}")
        print(f"  findings (canonical)       : {db.get('static_analysis_findings_total')}")
        print(f"  static_permission_matrix   : {db.get('static_permission_matrix_rows')}")
        print(f"  permission_risk_vnext      : {db.get('static_permission_risk_vnext_rows')}")
        print(f"  static_string_summary      : {db.get('static_string_summary_rows')}")
        print(f"  permission_audit_apps      : {db.get('permission_audit_apps_rows')}")
        print(f"  matrix/risk mismatch runs: {db.get('matrix_risk_mismatch_run_count')}")
        print("  per-run sample (first 8) :")
        for row in (db.get("per_run_packages") or [])[:8]:
            print(
                f"      {row.get('package_name')} id={row.get('static_run_id')} "
                f"st={row.get('status')} m={row.get('matrix_rows')} r={row.get('risk_rows')} "
                f"f={row.get('findings_rows')}"
            )
    pf = db.get("persistence_failures") or {}
    print(
        f"  persistence failures     : outcome_failed={pf.get('outcome_persistence_failed')} "
        f"missing_run_ids={pf.get('missing_static_run_id_count')} "
        f"flagged_rows≈{pf.get('failure_row_count')}"
    )
    print()

    pr = report.get("post_run_diagnostics") or {}
    print("5) Post-run diagnostics")
    print("-" * 44)
    pa = pr.get("persistence_audit") or {}
    print(f"  persistence audit        : [{'ok' if pa.get('present') else 'missing'}] {pa.get('path')}")
    ps = pr.get("permission_audit_snapshot") or {}
    print(f"  permission snapshot      : [{'ok' if ps.get('present') else 'missing'}] {ps.get('path')}")
    rh = pr.get("run_health_json") or {}
    print(f"  run_health.json          : {len(rh.get('paths') or [])} file(s)")
    for p in (rh.get("paths") or [])[:6]:
        print(f"      - {p}")
    dvd = pr.get("db_verification_digest") or {}
    print(f"  db_verification_digest   : {dvd.get('note')}")
    print()

    pad = report.get("permission_audit_directory") or {}
    if pad and not pad.get("skipped"):
        print("5a) Permission audit directory (data/audit/perm-audit_app_…)")
        print("-" * 44)
        print(f"  root                     : {pad.get('resolved_root')} [{'ok' if pad.get('root_exists') else 'missing'}]")
        sj = pad.get("snapshot_json") or {}
        print(f"  snapshot.json            : [{'ok' if sj.get('present') else 'missing'}] {sj.get('artifact_family')}")
        ad = pad.get("apps_dir") or {}
        print(f"  apps/*.json count        : {ad.get('json_file_count')} ({ad.get('artifact_family')})")
        cc = pad.get("correlation_csv") or {}
        print(f"  correlation.csv          : [{'ok' if cc.get('present') else 'missing'}] ({cc.get('artifact_family')})")
        vsdb = pad.get("apps_json_count_vs_db_rows")
        if vsdb:
            print(f"  apps json vs DB rows     : match={vsdb.get('match')} Δ={vsdb.get('delta_apps_json_minus_db')}")
        if pad.get("changed_parity_note"):
            print(f"  parity detail            : {pad.get('changed_parity_note')}")
        print()

    hl = report.get("harvest_linkage") or {}
    if hl and not hl.get("skipped"):
        print("5b) Harvest linkage (from selection manifest paths)")
        print("-" * 44)
        print(f"  harvest_run_path_labels  : {', '.join(hl.get('harvest_run_path_labels') or []) or '(none parsed)'}")
        print(f"  capture_ids              : {hl.get('capture_ids_in_manifest')}")
        print(f"  selected paths (manifest): {hl.get('selected_artifact_paths_total')}")
        print(f"  source files found       : {hl.get('artifact_paths_resolved_existing')}")
        print(f"  APK paths in manifest    : {hl.get('apk_paths_referenced_in_manifest')}")
        print(f"  APK files on disk        : {hl.get('apk_files_found_on_disk')}")
        print(f"  APK *.apk.meta.json      : {hl.get('apk_meta_sidecars_found')}")
        cs = int(hl.get("apk_paths_resolving_to_content_store") or 0)
        if cs:
            print(f"  APK paths (sha256 store) : {cs}")
            print(
                "  sidecar expectation      : "
                "Sidecars live beside device_apks pull paths, not content-store (sha256) paths."
            )
        elif hl.get("harvest_meta_sidecar_note"):
            # Unusual: note set without content-store paths; still surface for auditors.
            print(f"  sidecar note             : {hl.get('harvest_meta_sidecar_note')}")
        rpe = hl.get("receipt_pull_enrichment")
        if isinstance(rpe, dict):
            res = str(rpe.get("receipt_session_resolution") or "")
            if res:
                print(f"  receipt session pick     : {res}")
            sample = rpe.get("receipt_session_dir_names_sample") or []
            if isinstance(sample, list) and sample:
                preview = ", ".join(str(x) for x in sample[:6])
                more = f" (+{len(sample) - 6} more)" if len(sample) > 6 else ""
                print(f"  receipt dirs sample      : {preview}{more}")
            print(
                "  receipt → pull index     : "
                f"sessions={rpe.get('receipt_sessions_scanned')} "
                f"receipts_read={rpe.get('receipt_json_files_opened')} "
                f"observed_rows={rpe.get('indexed_canonical_to_pull_rows')} "
                f"unique_keys={rpe.get('indexed_unique_canonical_paths')}"
            )
            coll = int(rpe.get("canonical_pull_path_collisions") or 0)
            if coll:
                print(f"  receipt key collisions   : {coll} (last pull path wins)")
            print(
                "  receipt pull checks      : "
                f"mapped_apks={rpe.get('apk_paths_with_receipt_pull_mapping')} "
                f"apk_on_disk={rpe.get('receipt_pull_apk_files_on_disk')} "
                f"*.apk.meta.json={rpe.get('receipt_pull_meta_sidecars_found')} "
                f"harvest_manifest={rpe.get('receipt_pull_harvest_manifest_nearby')}"
            )
            unmapped = rpe.get("unmapped_content_store_path_samples") or []
            if isinstance(unmapped, list) and unmapped:
                print("  unmapped store paths     : (no receipt row for canonical key)")
                for line in unmapped[:8]:
                    print(f"      - {line}")
        print(f"  manifest-only groups     : {hl.get('package_groups_manifest_only_count')}")
        miss = hl.get("missing_source_file_samples") or []
        if miss:
            print("  missing source samples   :")
            for line in miss[:8]:
                print(f"      - {line}")
        print(f"  note                     : {hl.get('manifest_only_harvest_note')}")
        print()

    sep_rows = [r for r in (report.get("artifact_families") or []) if r.get("family") == "separate_workflow"]
    if sep_rows:
        print("5c) Separate workflows (not static session evidence)")
        print("-" * 44)
        for row in sep_rows:
            print(f"  {row.get('path')}")
            print(f"       {row.get('note')}")
        print()

    print("6) Artifact families (key paths)")
    print("-" * 44)
    for row in report.get("artifact_families") or []:
        print(f"  [{row.get('family')}] {row.get('path')}")
        print(f"           {row.get('note')}")
    tax = report.get("artifact_family_taxonomy") or {}
    if tax:
        print("  Taxonomy (lifecycle model)")
        for fam, items in tax.items():
            print(f"    {fam}: {len(items)} bullet(s)")
    print()

    print("7) Artifact audit verdict")
    print("-" * 44)
    print(f"  Session state       : {verdict.get('session_state')}")
    print(f"  Evidence status     : {verdict.get('evidence_status')}")
    print(f"  DB projection       : {verdict.get('db_projection_status')}")
    print(f"  Latest mirrors      : {verdict.get('latest_mirrors_note')}")
    print(f"  Action needed       : {verdict.get('action_needed')}")
    if verdict.get("harvest_receipt_linkage_incomplete"):
        print("  Harvest receipt link  : incomplete (see Warnings)")
    ls = verdict.get("log_stream") if isinstance(verdict.get("log_stream"), dict) else {}
    if ls:
        print("  Log stream rollup   :")
        print(f"      raw={ls.get('raw_report_saved_event_count')} unique={ls.get('unique_archive_path_count')} "
              f"dup_paths={ls.get('duplicate_archive_path_count')} dup_extra_events={ls.get('duplicate_archive_event_extra_count')}")
        print(f"      invariant(selection=archive=unique)={ls.get('evidence_invariant_selection_archive_unique')} "
              f"log_dup_without_evidence_gap={ls.get('log_duplication_without_evidence_gap')}")
    sv = report.get("strict_violations") or []
    if sv:
        print("  Strict violations   :")
        for line in sv:
            print(f"      - {line}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit static session artifacts (selection, archive, logs, mirrors, DB). Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Deprecated (no-op): --compare-log, --db — the audit always includes log/DB analysis; "
            "use --no-db to skip SQL.\n"
            "Exit codes: 0 success, 1 usage/import error, 2 --strict and strict_violations non-empty.\n"
            "--strict-log-duplicates adds duplicate_report_saved_events when raw JSONL lines repeat archive_path."
        ),
    )
    parser.add_argument("--session", required=True, help="session_stamp (e.g. 20260510-all-full-145)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit full audit JSON on stdout (suppresses human sections).",
    )
    parser.add_argument(
        "--write-report",
        nargs="?",
        const="default",
        default=None,
        metavar="PATH",
        help=(
            "Write full audit JSON; default: output/audit/run_artifacts/<session>_artifact_map.json "
            "(under OUTPUT_DIR)."
        ),
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Skip DB queries (offline / no DSN).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 2 when strict_violations is non-empty (full disk counts or DB/selection mismatches).",
    )
    parser.add_argument(
        "--strict-log-duplicates",
        action="store_true",
        help="With --strict, fail if duplicate_archive_event_extra_count>0 (violation duplicate_report_saved_events).",
    )
    parser.add_argument(
        "--include-harvest-linkage",
        action="store_true",
        help="Resolve selection paths under device_apks (APK/meta/manifest counts; manifest-only harvest hints).",
    )
    parser.add_argument(
        "--include-harvest-receipt-linkage",
        action="store_true",
        help=(
            "Enables harvest linkage and indexes harvest receipts to map canonical_store_path → device_apks pull; "
            "reports *.apk.meta.json and harvest_package_manifest.json relative to pull paths for store-selected APKs."
        ),
    )
    # Legacy flags (no-op for compatibility)
    parser.add_argument("--compare-log", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--db", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()
    session = str(args.session).strip()
    if not session:
        sys.stderr.write("Empty --session.\n")
        return 1

    repo = Path.cwd()

    try:
        report = build_artifact_map_report(
            session,
            repo=repo,
            no_db=bool(args.no_db),
            include_harvest_linkage=bool(args.include_harvest_linkage),
            include_harvest_receipt_linkage=bool(args.include_harvest_receipt_linkage),
            strict_log_duplicates=bool(args.strict_log_duplicates),
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (use repo root and PYTHONPATH=.): {exc}\n")
        return 1

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False, ensure_ascii=False))
    else:
        _print_human(report, repo=repo)

    if args.write_report is not None:
        from scytaledroid.Config import app_config
        from scytaledroid.StaticAnalysis.cli.execution.run_health.cli_output import sanitize_session_stamp_for_filename

        out_path: Path
        if args.write_report == "default":
            safe = sanitize_session_stamp_for_filename(session)
            out_path = Path(app_config.OUTPUT_DIR) / "audit" / "run_artifacts" / f"{safe}_artifact_map.json"
        else:
            out_path = Path(args.write_report).expanduser()
            if not out_path.is_absolute():
                out_path = (repo / out_path).resolve()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        if not args.json:
            print("Written report:")
            print(f"  {_rel_display(out_path, repo)}")
            print()

    if getattr(args, "strict", False) and report.get("strict_violations"):
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
