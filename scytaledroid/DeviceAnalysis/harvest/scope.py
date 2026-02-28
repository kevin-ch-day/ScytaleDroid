"""Scope selection helpers for APK harvesting."""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from . import rules
from .models import InventoryRow, ScopeSelection
from .scope_context import (
    EXCLUSION_LABELS,
    apply_default_scope,
    build_inventory_rows,
    build_scope_context,
    collect_exclusion_samples,
    estimated_files,
    filter_updated_only,
    sample_names,
)
from .watchlists import Watchlist

_LAST_SCOPE: ScopeSelection | None = None


def _load_latest_scoped_inventory_packages(*, device_serial: str, scope_id: str) -> list[dict[str, object]] | None:
    """Best-effort: load latest scoped inventory snapshot packages for *scope_id*.

    This allows paper-grade cohorts (v2/v3) to use fresh version_code/version_name and
    APK paths without requiring a full-device inventory sync.
    """

    # Scoped snapshots are persisted under:
    # data/state/<serial>/inventory/scoped/latest_scoped_<scope_id>.json
    p = Path("data") / "state" / device_serial / "inventory" / "scoped" / f"latest_scoped_{scope_id}.json"
    if not p.exists():
        return None
    try:
        import json

        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if str(payload.get("scope_id") or "").strip() != str(scope_id).strip():
        return None
    pkgs = payload.get("packages")
    return pkgs if isinstance(pkgs, list) else None


def _append_non_root_note(label: str) -> str:
    return label

def _maybe_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

def _merge_rows_prefer_scoped(
    *,
    rows: Sequence[InventoryRow],
    scoped_rows: Sequence[InventoryRow],
) -> list[InventoryRow]:
    """Merge *scoped_rows* into *rows*, replacing any existing packages.

    Paper-grade scoped inventory snapshots should win for version_code/version_name
    and APK paths. Appending would create duplicate package entries, and downstream
    planning may pick the wrong one depending on iteration order.
    """

    by_pkg: dict[str, InventoryRow] = {}
    for row in rows:
        pkg = (row.package_name or "").strip().lower()
        if not pkg:
            continue
        # Keep the first-seen row for non-scoped inventory; scoped_rows will overwrite.
        by_pkg.setdefault(pkg, row)
    for row in scoped_rows:
        pkg = (row.package_name or "").strip().lower()
        if not pkg:
            continue
        by_pkg[pkg] = row
    return list(by_pkg.values())

def _hydrate_missing_rows_from_adb(
    *,
    device_serial: str,
    missing_packages: set[str],
) -> list[InventoryRow]:
    """Best-effort: build InventoryRow entries for a small missing set via ADB.

    This is used only for paper/dataset cohorts to avoid forcing a full inventory
    sync when the canonical snapshot is slightly stale but the operator has just
    installed a small number of missing apps (e.g., Drive/Sheets).

    If hydration fails for a package, it remains missing and the paper precheck
    will fail-closed.
    """

    if not missing_packages:
        return []
    # Local import to avoid adding hard adb deps at module import time.
    from scytaledroid.DeviceAnalysis.adb import packages as adb_packages  # type: ignore
    from scytaledroid.DeviceAnalysis.runtime_flags import allow_inventory_fallbacks

    allow_fallbacks = allow_inventory_fallbacks()
    # Best-effort: fetch versionCode/versionName in one call so hydrated rows get correct
    # filename identities (avoids *_unknown__base.apk for newly installed apps).
    version_map: dict[str, tuple[str | None, str | None]] = {}
    try:
        for pkg, vcode, vname in adb_packages.list_packages_with_versions(
            device_serial,
            allow_fallbacks=allow_fallbacks,
        ):
            key = str(pkg or "").strip().lower()
            if not key:
                continue
            version_map[key] = (vcode, vname)
    except Exception:
        version_map = {}

    hydrated: list[InventoryRow] = []
    for pkg in sorted({p.strip().lower() for p in missing_packages if str(p).strip()}):
        try:
            apk_paths = adb_packages.get_package_paths(device_serial, pkg, allow_fallbacks=allow_fallbacks)
            meta = adb_packages.get_package_metadata(device_serial, pkg, refresh=True)
        except Exception:
            continue
        vcode, vname = version_map.get(pkg, (None, None))
        raw = {
            "package_name": pkg,
            "apk_paths": apk_paths,
            "split_count": len(apk_paths),
            "primary_path": (apk_paths[0] if apk_paths else None),
            "app_label": meta.get("app_label") or meta.get("label") or None,
            "version_name": meta.get("version_name") or vname or None,
            "version_code": meta.get("version_code") or vcode or None,
            "installer": meta.get("installer") or None,
        }
        hydrated.append(
            InventoryRow(
                raw=raw,
                package_name=pkg,
                app_label=_maybe_str(raw.get("app_label")),
                installer=_maybe_str(raw.get("installer")),
                category=None,
                primary_path=_maybe_str(raw.get("primary_path")),
                profile_key=None,
                profile=None,
                version_name=_maybe_str(raw.get("version_name")),
                version_code=_maybe_str(raw.get("version_code")),
                apk_paths=[str(p).strip() for p in apk_paths if str(p).strip()],
                split_count=int(raw.get("split_count") or 0),
            )
        )
    return hydrated


def _precheck_paper_dataset(
    *,
    title: str,
    expected_packages: set[str],
    inventory_rows: Sequence[InventoryRow],
    is_rooted: bool,
    # Optional label map (package -> human name) for nicer operator output.
    package_labels: dict[str, str] | None = None,
    expected_catalog_size: int | None = None,
    actual_catalog_size: int | None = None,
) -> tuple[bool, str]:
    """Return (ok_to_proceed, failure_reason) after printing a precheck summary."""

    # Operator UX:
    # - On PASS, printing the full "present on device" list is noisy and hard to copy/paste.
    # - On FAIL, we always print missing/blocked lists.
    # Set SCYTALEDROID_PRECHECK_VERBOSE=1 to always print the full present list.
    verbose = os.environ.get("SCYTALEDROID_PRECHECK_VERBOSE", "").strip().lower() in {"1", "true", "yes", "y"}

    pkg_labels = package_labels or {}
    inv_by_pkg = {row.package_name.strip().lower(): row for row in inventory_rows if row.package_name}
    inv_pkgs = set(inv_by_pkg.keys())
    exp = {p.strip().lower() for p in expected_packages if p.strip()}

    present = sorted(exp.intersection(inv_pkgs))
    missing = sorted(exp.difference(inv_pkgs))

    # Policy eligibility is "readable user path" under non-root.
    eligible = []
    blocked = []
    for pkg in present:
        row = inv_by_pkg.get(pkg)
        if not row:
            continue
        if is_rooted or any(rules.is_user_path(path) for path in row.apk_paths):
            eligible.append(pkg)
        else:
            blocked.append(pkg)

    print()
    menu_utils.print_header(f"{title} · Precheck")
    if expected_catalog_size is not None and actual_catalog_size is not None:
        frozen = expected_catalog_size == actual_catalog_size
        level = "success" if frozen else "warn"
        status = "PASS" if frozen else "FAIL"
        print(
            status_messages.status(
                f"Catalog frozen : {status} (catalog={actual_catalog_size} expected={expected_catalog_size})",
                level=level,
            )
        )
        if not frozen:
            missing_n = max(int(expected_catalog_size) - int(actual_catalog_size), 0)
            print(
                status_messages.status(
                    f"Paper-grade harvest is blocked until the catalog is frozen (missing {missing_n} catalog entr{'y' if missing_n == 1 else 'ies'}).",
                    level="warn",
                )
            )
    print(f"Required packages : {len(exp)}")
    print(f"Present on device : {len(present)}")
    print(f"Policy eligible   : {len(eligible)} (blocked {len(blocked)})")

    # Copy/paste friendly one-liner for tickets/PM updates.
    frozen_ok = True
    if expected_catalog_size is not None and actual_catalog_size is not None:
        frozen_ok = expected_catalog_size == actual_catalog_size
    print(
        status_messages.status(
            f"[COPY] precheck title={title!r} catalog_frozen={'PASS' if frozen_ok else 'FAIL'} "
            f"required={len(exp)} present={len(present)} eligible={len(eligible)} blocked={len(blocked)} missing={len(missing)}",
            level="info",
        )
    )
    if missing:
        print()
        print(status_messages.status("Missing on device:", level="warn"))
        for pkg in missing:
            label = pkg_labels.get(pkg, "")
            suffix = f" ({label})" if label else ""
            print(f"- {pkg}{suffix}")
    if blocked:
        print()
        print(status_messages.status("Present but blocked by policy (non-root paths):", level="warn"))
        for pkg in blocked:
            label = pkg_labels.get(pkg, "")
            suffix = f" ({label})" if label else ""
            print(f"- {pkg}{suffix}")

    # Print the present list only when it helps: on FAIL, or when explicitly requested.
    if present and (verbose or missing or blocked):
        print()
        print(status_messages.status("Present on device:", level="info"))
        if verbose or len(present) <= 30:
            for pkg in present:
                label = pkg_labels.get(pkg, "")
                suffix = f" ({label})" if label else ""
                print(f"- {pkg}{suffix}")
        else:
            for pkg in present[:20]:
                label = pkg_labels.get(pkg, "")
                suffix = f" ({label})" if label else ""
                print(f"- {pkg}{suffix}")
            print(f"... ({len(present) - 20} more)")
    if not missing and not blocked and not (
        expected_catalog_size is not None and actual_catalog_size is not None and expected_catalog_size != actual_catalog_size
    ):
        print(status_messages.status("Precheck PASS (all required packages present + eligible).", level="success"))
        return True, ""

    if expected_catalog_size is not None and actual_catalog_size is not None and expected_catalog_size != actual_catalog_size:
        reason = "catalog_not_frozen"
    else:
        reason = "missing_on_device" if missing else "blocked_by_policy"
    print()
    print(status_messages.status("Precheck FAIL.", level="error"))
    return False, reason


@dataclass(frozen=True)
class _WatchlistEntry:
    watchlist: Watchlist
    filtered: list[InventoryRow]
    excluded: dict[str, int]
    counts: dict[str, int]
    preview: str


def select_package_scope(
    rows: Sequence[InventoryRow],
    *,
    device_serial: str,
    is_rooted: bool,
    google_allowlist: Iterable[str | None] = None,
) -> ScopeSelection | None:
    """Prompt the analyst to choose a harvesting scope and return the filtered list."""

    if not rows:
        print(status_messages.status("No inventory data available for harvest.", level="warn"))
        return None

    allow = set(google_allowlist or rules.GOOGLE_ALLOWLIST)
    context = build_scope_context(rows, allow)
    profile_counts = context["profile_counts"]  # type: ignore[assignment]
    # Note: profile groups / watchlists are rendered inside build_scope_context() output.

    default_rows, _ = apply_default_scope(rows, allow)
    updated_rows, updated_meta = filter_updated_only(rows)
    if not is_rooted:
        readable_updated = [
            row for row in updated_rows if any(rules.is_user_path(path) for path in row.apk_paths)
        ]
        if len(readable_updated) != len(updated_rows):
            updated_meta = dict(updated_meta)
            updated_meta["filtered_non_user"] = len(updated_rows) - len(readable_updated)
        updated_rows = readable_updated

    while True:
        _render_scope_table(rows, device_serial, is_rooted, context, default_rows)

        option_handlers: dict[str, Callable[[], ScopeSelection | None]] = {}
        entries: list[dict[str, object]] = []

        def _add_entry(
            key: str,
            label: str,
            *,
            packages: int | None = None,
            files: int | None = None,
            note: str | None = None,
            handler: Callable[[], ScopeSelection | None] | None = None,
            entries: list[dict[str, object]] = entries,
            option_handlers: dict[str, Callable[[], ScopeSelection | None]] = option_handlers,
        ) -> None:
            # Keep the menu readable on narrow terminals: truncate long notes (profiles lists,
            # blocked explanations, etc.).
            note_text = str(note or "").strip()
            if note_text and len(note_text) > 64:
                note_text = note_text[:61].rstrip() + "..."
            entries.append(
                {
                    "key": key,
                    "label": label,
                    "packages": packages,
                    "files": files,
                    "note": note_text,
                }
            )
            if handler:
                option_handlers[key] = handler

        if _LAST_SCOPE is not None:
            _add_entry(
                "R",
                _format_rerun_label(_LAST_SCOPE),
                note="re-run last scope",
                handler=lambda: _LAST_SCOPE,
            )

        # Primary: research dataset collection.
        try:
            from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages

            dataset_pkgs = {p.lower() for p in load_profile_packages("RESEARCH_DATASET_ALPHA")}
        except Exception:
            dataset_pkgs = set()
        # Prefer a scoped snapshot for paper cohorts when available (faster and fresher than full inventory).
        scoped_alpha = _load_latest_scoped_inventory_packages(device_serial=device_serial, scope_id="paper2_alpha")
        if scoped_alpha:
            scoped_rows = build_inventory_rows(scoped_alpha)
            # Keep only the cohort packages; ignore other entries.
            scoped_rows = [row for row in scoped_rows if row.package_name.lower() in dataset_pkgs]
            if scoped_rows:
                rows = _merge_rows_prefer_scoped(rows=rows, scoped_rows=scoped_rows)
        # If the operator just installed a missing dataset app but hasn't re-synced the full
        # inventory snapshot yet, try to hydrate those missing rows directly from ADB so the
        # paper cohort precheck and harvest selection are accurate.
        existing_pkgs = {row.package_name.strip().lower() for row in rows if row.package_name}
        missing_dataset = {p for p in dataset_pkgs if p and p not in existing_pkgs}
        if missing_dataset:
            rows = list(rows) + _hydrate_missing_rows_from_adb(device_serial=device_serial, missing_packages=missing_dataset)
            existing_pkgs = {row.package_name.strip().lower() for row in rows if row.package_name}
        dataset_rows = [row for row in rows if row.package_name.lower() in dataset_pkgs] if dataset_pkgs else []
        _add_entry(
            "1",
            "Paper #2 Dataset",
            packages=len(dataset_rows),
            files=estimated_files(dataset_rows),
            note="Research Dataset Alpha",
            handler=lambda rows=dataset_rows, expected=dataset_pkgs: ScopeSelection(
                label="Research Dataset Alpha",
                packages=list(rows),
                kind="research_dataset",
                metadata={
                    "estimated_files": estimated_files(rows),
                    "candidate_count": len(rows),
                    "selected_count": len(rows),
                    "profile_key": "RESEARCH_DATASET_ALPHA",
                    "paper_dataset": True,
                    "expected_packages": sorted(list(expected)),
                    # Always pull the full dataset set; do not delta-filter these runs.
                    "disable_delta_filter": True,
                    "policy": "non_root_paths" if not is_rooted else "none",
                },
            ),
        )

        # Profile v3 structural cohort (catalog-driven, paper-grade defaults).
        try:
            from scytaledroid.Publication.profile_v3_metrics import load_profile_v3_catalog

            catalog = load_profile_v3_catalog(Path("profiles") / "profile_v3_app_catalog.json")
            v3_pkgs = {p.lower() for p in catalog.keys()}
            v3_catalog_n = int(len(catalog))
            v3_labels = {str(pkg).strip().lower(): str((meta or {}).get("app") or "").strip() for pkg, meta in catalog.items()}
        except Exception:
            v3_pkgs = set()
            v3_catalog_n = 0
            v3_labels = {}
        # Prefer latest scoped v3 snapshot when available (paper-grade speed + freshness).
        scoped_v3 = _load_latest_scoped_inventory_packages(device_serial=device_serial, scope_id="paper3_beta")
        if scoped_v3:
            scoped_rows = build_inventory_rows(scoped_v3)
            scoped_rows = [row for row in scoped_rows if row.package_name.lower() in v3_pkgs]
            if scoped_rows:
                rows = _merge_rows_prefer_scoped(rows=rows, scoped_rows=scoped_rows)
                existing_pkgs = {row.package_name.strip().lower() for row in rows if row.package_name}
        missing_v3 = {p for p in v3_pkgs if p and p not in existing_pkgs}
        if missing_v3:
            rows = list(rows) + _hydrate_missing_rows_from_adb(device_serial=device_serial, missing_packages=missing_v3)
            existing_pkgs = {row.package_name.strip().lower() for row in rows if row.package_name}
        v3_rows = [row for row in rows if row.package_name.lower() in v3_pkgs] if v3_pkgs else []
        expected_v3_n = 21
        v3_note = "Research Dataset Beta"
        v3_handler = lambda rows=v3_rows, expected=v3_pkgs, labels=v3_labels, n=v3_catalog_n, exp_n=expected_v3_n: ScopeSelection(
            label="Profile v3 Structural Cohort",
            packages=list(rows),
            kind="profile_v3",
            metadata={
                "estimated_files": estimated_files(rows),
                "candidate_count": len(rows),
                "selected_count": len(rows),
                "profile_key": "PROFILE_V3_STRUCTURAL",
                "paper_dataset": True,
                "expected_packages": sorted(list(expected)),
                "package_labels": labels,
                "catalog_size": int(n),
                "expected_catalog_size": int(exp_n),
                # Paper-grade: never delta-filter; always refresh the full cohort.
                "disable_delta_filter": True,
                "harvest_mode": "full_refresh",
                "policy": "non_root_paths" if not is_rooted else "none",
            },
        )
        _add_entry(
            "2",
            "Paper #3 Dataset",
            packages=len(v3_rows),
            files=estimated_files(v3_rows),
            note=v3_note,
            handler=v3_handler,
        )

        _add_entry(
            "3",
            "Play & user apps",
            packages=context["default_counts"].get("packages"),
            files=context["default_counts"].get("files"),
            note="default",
            handler=lambda: _scope_default(rows, allow),
        )
        # Primary: profiled apps. This is the research dataset adjacent view, without being a hard-coded list.
        _add_entry(
            "4",
            "Target app profiles",
            packages=context["profile_summary"].get("packages"),
            files=context["profile_summary"].get("files"),
            note="",
            handler=lambda: _scope_profiles(rows, profile_counts, allow),
        )

        _add_entry(
            "5",
            "Google allow-list",
            packages=context["google_exceptions"].get("packages"),
            files=context["google_exceptions"].get("files"),
            note="allow-list",
            handler=lambda: _scope_google_allowlist(rows, allow),
        )
        _add_entry(
            "6",
            "Everything",
            packages=context["everything"].get("packages"),
            files=context["everything"].get("files"),
            note="policy-filtered" if not is_rooted else None,
            handler=lambda: ScopeSelection(
                label="Everything",
                packages=list(rows),
                kind="everything",
                metadata={
                    "estimated_files": context["everything"].get("files", 0),
                    "candidate_count": len(rows),
                    "selected_count": len(rows),
                    # Default to delta-filter for huge scopes unless the operator overrides it.
                    # The workflow will prompt for delta-vs-full-refresh when a delta summary exists.
                    "policy": "non_root_paths" if not is_rooted else "none",
                },
            ),
        )

        headers = ["#", "Scope", "Packages", "Est.Files", "Notes"]
        table_rows = []
        for entry in entries:
            key = str(entry["key"])
            label = entry["label"]
            packages = entry.get("packages")
            files = entry.get("files")
            note = entry.get("note") or ""
            pkg_cell = packages if isinstance(packages, int) else ""
            files_cell = f"~{files}" if isinstance(files, int) and files else ""
            table_rows.append([key, label, pkg_cell, files_cell, note])

        table_utils.render_table(headers, table_rows, compact=True)
        print("0 back")

        choice = prompt_utils.get_choice(
            [str(entry["key"]) for entry in entries] + ["0"],
            default="1",
            casefold=True,
            prompt="Select scope #: ",
        )
        if choice == "0":
            return None

        handler = option_handlers.get(choice.upper()) or option_handlers.get(choice)
        if handler is None:
            print(status_messages.status("Selection not available.", level="warn"))
            continue

        selection = handler()
        if selection is None:
            continue

        # Paper dataset precheck is run after selection so the table stays compact.
        if bool(selection.metadata.get("paper_dataset")) and selection.metadata.get("expected_packages"):
            expected = {str(p).strip() for p in (selection.metadata.get("expected_packages") or []) if str(p).strip()}
            labels = selection.metadata.get("package_labels")
            pkg_labels = labels if isinstance(labels, dict) else None

            # Special v3 lock: do not allow harvest until catalog is frozen at expected size.
            if selection.kind == "profile_v3":
                cat_n = selection.metadata.get("catalog_size")
                exp_n = selection.metadata.get("expected_catalog_size")
                expected_size = int(exp_n) if isinstance(exp_n, int) else None
                actual_size = int(cat_n) if isinstance(cat_n, int) else None

            ok, reason = _precheck_paper_dataset(
                title="Paper #2 Dataset" if selection.kind == "research_dataset" else "Paper #3 Dataset",
                expected_packages=expected,
                inventory_rows=rows,
                is_rooted=is_rooted,
                package_labels=pkg_labels,
                expected_catalog_size=expected_size if selection.kind == "profile_v3" else None,
                actual_catalog_size=actual_size if selection.kind == "profile_v3" else None,
            )
            if not ok:
                # Paper-grade v3 harvesting is always blocked until the cohort catalog is frozen.
                if selection.kind == "profile_v3" and reason == "catalog_not_frozen":
                    continue
                proceed = prompt_utils.prompt_yes_no("Proceed anyway?", default=False)
                if not proceed:
                    continue

        _print_selection_diagnostics(selection)
        _store_last_scope(selection)
        return selection


def select_package_scope_auto(
    rows: Sequence[InventoryRow],
    *,
    device_serial: str,
    is_rooted: bool,
    google_allowlist: Iterable[str | None] = None,
) -> ScopeSelection | None:
    """Select a smart default scope without prompting (updated-only when possible)."""
    if not rows:
        print(status_messages.status("No inventory data available for harvest.", level="warn"))
        return None

    allow = set(google_allowlist or rules.GOOGLE_ALLOWLIST)
    updated_rows, updated_meta = filter_updated_only(rows)
    if not is_rooted:
        readable_updated = [
            row for row in updated_rows if any(rules.is_user_path(path) for path in row.apk_paths)
        ]
        if len(readable_updated) != len(updated_rows):
            updated_meta = dict(updated_meta)
            updated_meta["filtered_non_user"] = len(updated_rows) - len(readable_updated)
        updated_rows = readable_updated

    if updated_rows:
        selection = _scope_updated_only(rows, updated_rows, updated_meta)
        selection.metadata["auto_scope_reason"] = "updated_only"
        return selection

    if _LAST_SCOPE is not None:
        selection = ScopeSelection(
            label=_LAST_SCOPE.label,
            packages=list(_LAST_SCOPE.packages),
            kind=_LAST_SCOPE.kind,
            metadata=dict(_LAST_SCOPE.metadata),
        )
        selection.metadata["auto_scope_reason"] = "last_scope"
        return selection

    selection = _scope_default(rows, allow)
    selection.metadata["auto_scope_reason"] = "default_scope"
    return selection


def _render_scope_table(
    rows: Sequence[InventoryRow],
    device_serial: str,
    is_rooted: bool,
    context: dict[str, object],
    default_rows: Sequence[InventoryRow],
) -> None:
    mode_label = "root" if is_rooted else "non-root"
    print()
    print("----------------------------")
    print("Pull APKs -- Status")
    print("----------------------------")
    candidates = len(rows)
    eligible = candidates if is_rooted else sum(
        1 for row in rows if any(rules.is_user_path(path) for path in row.apk_paths)
    )
    blocked = max(candidates - eligible, 0)
    policy = "none" if is_rooted else "non_root_paths"
    print(f"App candidates : {candidates}")
    print(f"Policy eligible: {eligible} (blocked {blocked})")
    print(f"Policy         : {policy}")
    print("-" * 86)


def _format_rerun_label(selection: ScopeSelection) -> str:
    pkg_count = len(selection.packages)
    return f"Re-run last scope ({selection.label} – {pkg_count} pkg(s))"


def _format_menu_count(stats: dict[str, int]) -> str:
    packages = stats.get("packages", 0)
    files = stats.get("files", 0)
    return f"{packages} pkg(s) · ~{files} file(s)"


def _format_watchlist_hint(entry: _WatchlistEntry) -> str | None:
    if not entry.preview:
        return None
    if len(entry.filtered) > 3:
        return f"Preview: {entry.preview}, …"
    return f"Preview: {entry.preview}"


def _scope_default(rows: Sequence[InventoryRow], allow: set[str]) -> ScopeSelection:
    selected, excluded = apply_default_scope(rows, allow)
    excluded_samples = collect_exclusion_samples(rows, selected, allow)
    metadata = {
        "estimated_files": estimated_files(selected),
        "allowlist_size": len(allow),
        "excluded_counts": excluded,
        "sample_names": sample_names(selected),
        "excluded_samples": excluded_samples,
        "candidate_count": len(rows),
        "selected_count": len(selected),
    }
    return ScopeSelection("Play Store & user-installed", selected, "default", metadata)


def _scope_updated_only(
    rows: Sequence[InventoryRow],
    updated_rows: Sequence[InventoryRow],
    meta: dict[str, int],
) -> ScopeSelection:
    metadata = {
        "estimated_files": estimated_files(updated_rows),
        "candidate_count": len(rows),
        "selected_count": len(updated_rows),
        "updated_only": True,
        "updated_missing_repo": meta.get("missing_repo", 0),
        "updated_version_mismatch": meta.get("version_mismatch", 0),
        "updated_version_match": meta.get("version_match", 0),
    }
    # Inventory-only deltas are metadata-based under non-root constraints, not build-identity claims.
    return ScopeSelection("Changed apps only", list(updated_rows), "updated_only", metadata)


def _scope_profiles(
    rows: Sequence[InventoryRow],
    profile_counts: Counter[str],
    allow: set[str],
) -> ScopeSelection | None:
    if not profile_counts:
        print(status_messages.status("No profiled packages available.", level="warn"))
        return None

    print()
    menu_utils.print_header("Choose profile(s)")
    target_profiles = {"SOCIAL", "MESSAGING", "MEDIA", "BROWSER", "PRODUCTIVITY", "SHOPPING", "NEWS"}
    sorted_profiles = sorted(
        [(name, count) for name, count in profile_counts.items() if name in target_profiles],
        key=lambda item: (-item[1], item[0].lower()),
    )
    profile_menu: dict[str, str] = {}
    for index, (profile, count) in enumerate(sorted_profiles, start=1):
        profile_menu[str(index)] = f"{profile} ({count})"
    profile_menu["A"] = "All profiles"

    menu_utils.print_menu(profile_menu, is_main=False)
    while True:
        raw = prompt_utils.prompt_text(
            "Selection (e.g., 1,3 or A)",
            default="",
            required=False,
        ).strip()
        if not raw:
            print(status_messages.status("Profile selection cancelled.", level="warn"))
            return None

        if raw.upper() == "A":
            selected = {name for name, _ in sorted_profiles}
            break

        tokens = [token.strip() for token in re.split(r"[,\s]+", raw) if token.strip()]
        if not tokens:
            print(status_messages.status("No profiles selected.", level="warn"))
            continue
        if not all(token.isdigit() for token in tokens):
            print(status_messages.status("Use numeric selections or A for all.", level="warn"))
            continue

        indices = {int(token) for token in tokens}
        if any(idx < 1 or idx > len(sorted_profiles) for idx in indices):
            print(status_messages.status("Selection out of range. Try again.", level="warn"))
            continue

        selected = {sorted_profiles[idx - 1][0] for idx in indices}
        break

    if not selected:
        print(status_messages.status("No valid profiles selected.", level="warn"))
        return None

    profile_rows = [
        row
        for row in rows
        if (row.profile_key or "").upper() in selected
    ]
    if not profile_rows:
        print(status_messages.status("No packages matched the selected profiles.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(profile_rows, allow)
    excluded_samples = collect_exclusion_samples(profile_rows, filtered, allow)
    if not filtered:
        print(
            status_messages.status(
                "Selected profiles matched only packages filtered by scope rules.",
                level="warn",
            )
        )
        return None

    metadata = {
        "profiles": sorted(selected),
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "excluded_samples": excluded_samples,
        "candidate_count": len(profile_rows),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"Profiles: {', '.join(sorted(selected))}",
        packages=filtered,
        kind="profiles",
        metadata=metadata,
    )


def _scope_google_user_apps(
    rows: Sequence[InventoryRow], allow: set[str]
) -> ScopeSelection | None:
    candidates = [row for row in rows if rules.is_google_user_app(row.package_name)]
    if not candidates:
        print(status_messages.status("No Google user apps present on device.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(candidates, allow)
    if not filtered:
        print(
            status_messages.status(
                "Google user apps present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "candidate_count": len(candidates),
        "selected_count": len(filtered),
    }
    return ScopeSelection("Google user apps", filtered, "google_user", metadata)


def _scope_profile_subset(
    rows: Sequence[InventoryRow],
    allow: set[str],
    profiles: set[str],
    *,
    label: str,
) -> ScopeSelection | None:
    normalized = {profile.lower() for profile in profiles}
    subset = [row for row in rows if row.profile and row.profile.lower() in normalized]
    if not subset:
        print(status_messages.status(f"No packages tagged as {label}.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(subset, allow)
    if not filtered:
        print(
            status_messages.status(
                f"{label} packages present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "profiles": sorted({row.profile for row in subset if row.profile}),
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "candidate_count": len(subset),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"{label} apps",
        packages=filtered,
        kind="profile_subset",
        metadata=metadata,
    )


def _scope_profile_key_subset(
    rows: Sequence[InventoryRow],
    allow: set[str],
    profiles: set[str],
    *,
    label: str,
) -> ScopeSelection | None:
    normalized = {profile.upper() for profile in profiles}
    subset = [row for row in rows if (row.profile_key or "").upper() in normalized]
    if not subset:
        print(status_messages.status(f"No packages tagged as {label}.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(subset, allow)
    if not filtered:
        print(
            status_messages.status(
                f"{label} packages present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "profiles": sorted({(row.profile_key or "").upper() for row in subset if row.profile_key}),
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "candidate_count": len(subset),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"{label} apps",
        packages=filtered,
        kind="profile_key_subset",
        metadata=metadata,
    )


def _scope_category_subset(
    category_groups: dict[str, list[InventoryRow]],
    allow: set[str],
    categories: set[str],
    *,
    label: str | None = None,
) -> ScopeSelection | None:
    combined: list[InventoryRow] = []
    for category in categories:
        combined.extend(category_groups.get(category, []))
    if not combined:
        print(status_messages.status(f"No packages tagged as {', '.join(categories)}.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(combined, allow)
    if not filtered:
        print(
            status_messages.status(
                f"{', '.join(categories)} packages present but filtered by scope policy.",
                level="warn",
            )
        )
        return None

    scope_label = label or " & ".join(sorted(categories))
    metadata = {
        "categories": sorted(categories),
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        # Capture how many candidates existed vs how many survive policy filters.
        "candidate_count": len(combined),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"{scope_label} apps",
        packages=filtered,
        kind="category_subset",
        metadata=metadata,
    )


def _group_by_profile_key(rows: Sequence[InventoryRow]) -> dict[str, list[InventoryRow]]:
    grouped: dict[str, list[InventoryRow]] = {}
    for row in rows:
        key = (row.profile_key or "").strip().upper()
        if not key:
            continue
        grouped.setdefault(key, []).append(row)
    return grouped


def _scope_watchlist(entry: _WatchlistEntry) -> ScopeSelection | None:
    if not entry.filtered:
        print(status_messages.status("Watchlist contains no packages in scope.", level="warn"))
        return None
    metadata = {
        "watchlist": entry.watchlist.name,
        "watchlist_path": str(entry.watchlist.path),
        "estimated_files": entry.counts.get("files", 0),
        "excluded_counts": entry.excluded,
        "sample_names": sample_names(entry.filtered),
        "candidate_count": entry.counts.get("packages", 0) + sum(entry.excluded.values()),
        "selected_count": len(entry.filtered),
    }
    return ScopeSelection(
        label=f"Watchlist: {entry.watchlist.name}",
        packages=list(entry.filtered),
        kind="watchlist",
        metadata=metadata,
    )


def _scope_google_allowlist(
    rows: Sequence[InventoryRow], allow: set[str]
) -> ScopeSelection | None:
    candidates = [row for row in rows if row.package_name in allow]
    if not candidates:
        print(status_messages.status("No Google allow-list packages found in inventory.", level="warn"))
        return None
    filtered, excluded = apply_default_scope(candidates, allow)
    if not filtered:
        message = (
            "Google allow-list packages present but filtered by scope policy."
            if excluded
            else "No Google allow-list packages matched the current scope."
        )
        print(status_messages.status(message, level="warn"))
        return None
    excluded_samples = collect_exclusion_samples(candidates, filtered, allow)
    metadata = {
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "excluded_samples": excluded_samples,
        "candidate_count": len(candidates),
        "selected_count": len(filtered),
    }
    return ScopeSelection("Google exceptions", filtered, "google_allow", metadata)


def _scope_families(rows: Sequence[InventoryRow]) -> ScopeSelection | None:
    filtered = [row for row in rows if rules.family(row.package_name) in {"android", "google", "motorola"}]
    if not filtered:
        print(status_messages.status("No Android/Google/Motorola packages found.", level="warn"))
        return None
    excluded_samples: dict[str, list[str]] = {}
    metadata = {
        "estimated_files": estimated_files(filtered),
        "sample_names": sample_names(filtered),
        "candidate_count": len(filtered),
        "selected_count": len(filtered),
        "excluded_counts": {},
        "excluded_samples": excluded_samples,
    }
    return ScopeSelection("System families", filtered, "families", metadata)


def _scope_custom(rows: Sequence[InventoryRow], allow: set[str]) -> ScopeSelection | None:
    print()
    print(
        status_messages.status(
            "Enter package names (comma separated, prefix * wildcards supported). Leave blank to cancel.",
            level="info",
        )
    )
    raw = prompt_utils.prompt_text("Packages", default="", required=False).strip()
    if not raw:
        print(status_messages.status("Custom selection cancelled.", level="warn"))
        return None

    patterns = [token.strip().lower() for token in re.split(r"[\s,]+", raw) if token.strip()]
    if not patterns:
        print(status_messages.status("No valid package identifiers provided.", level="warn"))
        return None

    matches: list[InventoryRow] = []
    for row in rows:
        name = row.package_name.lower()
        if any(_pattern_matches(pattern, name) for pattern in patterns):
            matches.append(row)

    if not matches:
        print(status_messages.status("No packages matched the provided patterns.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(matches, allow)
    if not filtered:
        print(
            status_messages.status(
                "Custom patterns matched packages filtered by scope policy.",
                level="warn",
            )
        )
        return None

    metadata = {
        "patterns": patterns,
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "excluded_samples": collect_exclusion_samples(matches, filtered, allow),
        "candidate_count": len(matches),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"Custom ({', '.join(patterns)})",
        packages=filtered,
        kind="custom",
        metadata=metadata,
    )


def _store_last_scope(selection: ScopeSelection) -> None:
    global _LAST_SCOPE
    _LAST_SCOPE = selection


def _format_count(stats: object, key: str, *, prefix: str = "") -> str:
    if isinstance(stats, dict):
        value = int(stats.get(key, 0))
    else:
        value = 0
    unit = "pkg(s)" if key == "packages" else "file(s)"
    return f"{prefix}{value} {unit}"


def _format_count_summary(rows: Sequence[InventoryRow | None]) -> str:
    if not rows:
        return "0 pkg(s)"
    return f"{len(rows)} pkg(s)"


def _print_selection_diagnostics(selection: ScopeSelection) -> None:
    """
    Explain how a chosen scope shrank from all candidates to the kept set, with reasons.
    Always-on so operators see why a category collapsed.
    """
    meta = selection.metadata or {}
    if not meta.get("show_details"):
        return
    excluded_counts = meta.get("excluded_counts") or {}
    selected = int(meta.get("selected_count") or len(selection.packages) or 0)
    candidates = int(meta.get("candidate_count") or 0)
    if not candidates:
        candidates = selected + sum(int(v) for v in excluded_counts.values())
    if not candidates:
        return
    filtered = max(candidates - selected, 0)
    breakdown = []
    for reason, count in sorted(excluded_counts.items()):
        if not count:
            continue
        label = EXCLUSION_LABELS.get(reason, reason)
        breakdown.append(f"{label}={count}")
    detail = f"{selection.label}: candidates={candidates} • kept={selected} • filtered={filtered}"
    if breakdown:
        detail = f"{detail} ({'; '.join(breakdown)})"
    print(status_messages.status(detail, level="info"))


def _scope_option_label(
    title: str,
    *,
    packages: int | None = None,
    files: int | None = None,
    note: str | None = None,
) -> str:
    parts: list[str] = [title]
    metrics: list[str] = []
    if packages is not None:
        metrics.append(f"{packages} pkg(s)")
    if files is not None:
        metrics.append(f"~{files} file(s)")
    if metrics:
        parts.append("· " + " · ".join(metrics))
    if note:
        parts.append(f"— {note}")
    return " ".join(parts)


def _pattern_matches(pattern: str, value: str) -> bool:
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
        return re.match(regex, value) is not None
    if "." not in pattern:
        return pattern in value
    return pattern == value


def _print_scope_overview(
    rows: Sequence[InventoryRow],
    device_serial: str,
    is_rooted: bool,
    context: dict[str, object],
) -> None:
    print()
    menu_utils.print_header(
        "Package Scope Overview",
        subtitle=f"{device_serial} · {'root' if is_rooted else 'non-root'}",
    )
    headers = ("Subset", "Packages", "Artifacts", "Notes")
    rows_summary: list[tuple[str, str, str, str]] = [
        (
            "Play & user",
            _format_count(context["default_counts"], "packages"),
            _format_count(context["default_counts"], "files", prefix="~"),
            "Default scope",
        ),
    ]

    rows_summary.append(
        (
            "Google user",
            _format_count(context["google_user"], "packages"),
            _format_count(context["google_user"], "files", prefix="~"),
            "YouTube/Maps/Photos/etc.",
        )
    )

    profile_summary = context.get("profile_summary", {"packages": 0})
    if profile_summary.get("packages", 0):
        rows_summary.append(
            (
                "Profiled apps",
                _format_count(profile_summary, "packages"),
                _format_count(profile_summary, "files", prefix="~"),
                "Social/Messaging/Shopping",
            )
        )

    watchlist_totals = context.get("watchlist_totals", {"packages": 0, "files": 0})
    watchlist_lists = context.get("watchlists", [])
    if watchlist_totals.get("packages", 0):
        note = f"{len(watchlist_lists)} list(s)"
        rows_summary.append(
            (
                "Watchlists",
                _format_count(watchlist_totals, "packages"),
                _format_count(watchlist_totals, "files", prefix="~"),
                note,
            )
        )

    rows_summary.extend(
        [
            (
                "Google exceptions",
                _format_count(context["google_exceptions"], "packages"),
                _format_count(context["google_exceptions"], "files", prefix="~"),
                "Allow-list scope",
            ),
            (
                "System families",
                _format_count(context["families"], "packages"),
                _format_count(context["families"], "files", prefix="~"),
                "Android/Google/Motorola",
            ),
            (
                "Everything",
                str(len(rows)),
                _format_count(context["everything"], "files", prefix="~"),
                "Full inventory",
            ),
        ]
    )

    menu_utils.print_table(headers, rows_summary)

    default_stats = context["default_counts"]
    menu_utils.print_hint(
        f"Default scope · {default_stats.get('packages', 0)} pkg(s) / ~{default_stats.get('files', 0)} file(s)"
    )
    default_excluded = context.get("default_excluded") or {}
    if default_excluded:
        filtered_bits = []
        for reason, count in sorted(default_excluded.items()):
            label = EXCLUSION_LABELS.get(reason, reason)
            filtered_bits.append(f"{label}={count}")
        if filtered_bits:
            print(status_messages.status("Default scope filters:", level="info"))
            for bit in filtered_bits:
                print(status_messages.status(f"  • {bit}", level="info"))
    if not is_rooted:
        menu_utils.print_hint(
            "System/vendor partitions require root; they are filtered automatically.",
            icon="⚠",
        )


def reset_last_scope() -> None:
    """Reset cached scope state (mainly used in tests)."""

    global _LAST_SCOPE
    _LAST_SCOPE = None


__all__ = [
    "build_inventory_rows",
    "reset_last_scope",
    "select_package_scope",
]
