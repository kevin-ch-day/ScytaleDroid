"""Scope selection helpers for APK harvesting."""

from __future__ import annotations

import os
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

    This allows profile-scoped harvesting to use fresh version_code/version_name and
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

    Profile-scoped inventory snapshots should win for version_code/version_name
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

    This is used for profile-scoped harvesting to avoid forcing a full inventory
    sync when the canonical snapshot is slightly stale but the operator has just
    installed a small number of missing apps (e.g., Drive/Sheets).

    If hydration fails for a package, it remains missing from the scoped selection.
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


def _precheck_required_packages(
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
                    f"Harvest is blocked until the scoped catalog is complete (missing {missing_n} catalog entr{'y' if missing_n == 1 else 'ies'}).",
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


def _load_active_profile_scopes(
    rows: Sequence[InventoryRow],
    *,
    device_serial: str,
) -> list[dict[str, object]]:
    from scytaledroid.DynamicAnalysis.profile_loader import load_db_profiles, load_profile_packages

    scopes: list[dict[str, object]] = []
    for profile in load_db_profiles():
        profile_key = str(profile.get("profile_key") or "").strip().upper()
        if not profile_key:
            continue
        display_name = str(profile.get("display_name") or profile_key).strip() or profile_key
        scope_id = f"profile::{profile_key.lower()}"
        expected = {
            str(package).strip().lower()
            for package in load_profile_packages(profile_key)
            if str(package).strip()
        }
        if not expected:
            continue

        working_rows = list(rows)
        scoped_packages = _load_latest_scoped_inventory_packages(device_serial=device_serial, scope_id=scope_id)
        if scoped_packages:
            scoped_rows = build_inventory_rows(scoped_packages)
            scoped_rows = [row for row in scoped_rows if row.package_name.lower() in expected]
            if scoped_rows:
                working_rows = _merge_rows_prefer_scoped(rows=working_rows, scoped_rows=scoped_rows)

        existing_pkgs = {row.package_name.strip().lower() for row in working_rows if row.package_name}
        missing_packages = {pkg for pkg in expected if pkg and pkg not in existing_pkgs}
        if missing_packages:
            working_rows.extend(
                _hydrate_missing_rows_from_adb(
                    device_serial=device_serial,
                    missing_packages=missing_packages,
                )
            )

        profile_rows = [row for row in working_rows if row.package_name.lower() in expected]
        scopes.append(
            {
                "profile_key": profile_key,
                "display_name": display_name,
                "scope_id": scope_id,
                "expected_packages": expected,
                "rows": profile_rows,
            }
        )

    scopes.sort(key=lambda item: str(item["display_name"]).casefold())
    return scopes


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

        profile_scopes = _load_active_profile_scopes(rows, device_serial=device_serial)
        profile_scope_count = len(profile_scopes)
        profile_scope_packages = sum(len(scope["rows"]) for scope in profile_scopes)
        _add_entry(
            "1",
            "App profile",
            packages=profile_scope_packages if profile_scope_packages else None,
            note=f"{profile_scope_count} active" if profile_scope_count else "none available",
            handler=lambda: _scope_profiles(rows, allow, device_serial=device_serial, is_rooted=is_rooted),
        )

        _add_entry(
            "2",
            "Play & user apps",
            packages=context["default_counts"].get("packages"),
            files=context["default_counts"].get("files"),
            note="default",
            handler=lambda: _scope_default(rows, allow),
        )
        _add_entry(
            "3",
            "Google allow-list",
            packages=context["google_exceptions"].get("packages"),
            files=context["google_exceptions"].get("files"),
            note="allow-list",
            handler=lambda: _scope_google_allowlist(rows, allow),
        )
        _add_entry(
            "4",
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
            default="2",
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

        # Scoped profile selections can still benefit from an explicit inventory precheck.
        if bool(selection.metadata.get("profile_scope")) and selection.metadata.get("expected_packages"):
            expected = {str(p).strip() for p in (selection.metadata.get("expected_packages") or []) if str(p).strip()}
            labels = selection.metadata.get("package_labels")
            pkg_labels = labels if isinstance(labels, dict) else None

            ok, _reason = _precheck_required_packages(
                title=str(selection.label),
                expected_packages=expected,
                inventory_rows=rows,
                is_rooted=is_rooted,
                package_labels=pkg_labels,
            )
            if not ok:
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
    allow: set[str],
    *,
    device_serial: str,
    is_rooted: bool,
) -> ScopeSelection | None:
    profile_scopes = _load_active_profile_scopes(rows, device_serial=device_serial)
    if not profile_scopes:
        print(status_messages.status("No active app profiles are available.", level="warn"))
        return None

    if len(profile_scopes) == 1:
        selected_profile = profile_scopes[0]
        print(
            status_messages.status(
                f"Only one active profile is available; selecting {selected_profile['display_name']}.",
                level="info",
            )
        )
    else:
        print()
        menu_utils.print_header("Harvest Scope · Profile")
        rows_data = [
            [
                str(idx),
                str(profile["display_name"]),
                str(len(profile["rows"])),
                str(estimated_files(profile["rows"])),
            ]
            for idx, profile in enumerate(profile_scopes, start=1)
        ]
        table_utils.render_table(["#", "Profile", "Packages", "Est.Files"], rows_data, compact=True)
        print(status_messages.status(f"Status: profiles={len(profile_scopes)}", level="info"))
        choice = prompt_utils.get_choice(
            [str(index) for index in range(1, len(profile_scopes) + 1)] + ["0"],
            default="1",
            prompt="Select profile # [1] ",
        )
        if choice == "0":
            return None
        selected_profile = profile_scopes[int(choice) - 1]

    profile_rows = list(selected_profile["rows"])
    if not profile_rows:
        print(status_messages.status("No packages matched the selected profile.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(profile_rows, allow)
    excluded_samples = collect_exclusion_samples(profile_rows, filtered, allow)
    if not filtered:
        print(
            status_messages.status(
                "Selected profile matched only packages filtered by scope rules.",
                level="warn",
            )
        )
        return None

    package_labels = {
        row.package_name: row.display_name()
        for row in profile_rows
        if row.package_name
    }
    metadata = {
        "profile_scope": True,
        "profile_key": str(selected_profile["profile_key"]),
        "scope_id": str(selected_profile["scope_id"]),
        "profiles": [str(selected_profile["profile_key"])],
        "expected_packages": sorted(str(pkg) for pkg in set(selected_profile["expected_packages"])),
        "package_labels": package_labels,
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "excluded_samples": excluded_samples,
        "candidate_count": len(profile_rows),
        "selected_count": len(filtered),
        "disable_delta_filter": True,
        "policy": "non_root_paths" if not is_rooted else "none",
    }
    return ScopeSelection(
        label=str(selected_profile["display_name"]),
        packages=filtered,
        kind="profile_scope",
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
