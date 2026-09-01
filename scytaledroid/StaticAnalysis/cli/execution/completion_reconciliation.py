"""Derived frozen-selection completion reconciliation for static sessions.

This is deliberately derived from the selection held by the running session and
its in-memory terminal outcomes.  It is not another ledger: the JSON receipt is
a small, rebuildable explanation of whether the frozen work was accounted for.
Nothing reads this receipt as authority over the selection, outcomes, or DB rows.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from scytaledroid.Utils.IO.atomic_write import atomic_write_text

from ..core.models import RunOutcome
from .scan_identity_helpers import select_group_artifacts


def _path(value: object) -> str:
    return str(value or "").strip()


def _canonical_path(value: object) -> str:
    text = _path(value)
    if not text:
        return ""
    try:
        return str(Path(text).resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return text


def _selected_artifact_path(artifact: object) -> str:
    return _canonical_path(
        getattr(artifact, "path", None) or getattr(artifact, "display_path", None)
    )


def _artifact_path(artifact: object) -> str:
    report = getattr(artifact, "report", None)
    return _canonical_path(getattr(report, "file_path", None))


def _selected_artifact_sha256(artifact: object) -> str:
    sha256 = _path(getattr(artifact, "sha256", None)).lower()
    metadata = getattr(artifact, "metadata", None)
    if not sha256 and isinstance(metadata, Mapping):
        sha256 = _path(metadata.get("sha256")).lower()
    return sha256


def _terminal_artifact_sha256(artifact: object) -> str:
    report = getattr(artifact, "report", None)
    hashes = getattr(report, "hashes", None)
    if not isinstance(hashes, Mapping):
        return ""
    return _path(hashes.get("sha256")).lower()


def _selection_digest_entry(package: str, artifact: object) -> str:
    """Stable frozen-selection identity using existing package/hash/split fields."""

    sha256 = _path(getattr(artifact, "sha256", None)).lower()
    path = _selected_artifact_path(artifact)
    metadata = getattr(artifact, "metadata", None)
    if not sha256 and isinstance(metadata, Mapping):
        sha256 = _path(metadata.get("sha256")).lower()
    split = _path(getattr(artifact, "artifact_label", None))
    if not split and isinstance(metadata, Mapping):
        split = _path(metadata.get("split_name") or metadata.get("artifact_label"))
    return "\x1f".join((package, sha256 or f"path:{path}", split))


def build_static_completion_reconciliation(
    outcome: RunOutcome,
    *,
    scan_splits: bool,
    require_canonical_persistence: bool = True,
) -> dict[str, object]:
    """Reconcile terminal outcomes against the session's frozen ``outcome.scope``.

    The caller must invoke this after persistence.  A terminal report is a
    successful artifact outcome; missing, duplicate, or foreign report paths
    are never silently counted as completion.
    """

    expected: list[tuple[str, str]] = []
    expected_hashes: dict[tuple[str, str], str] = {}
    digest_entries: list[str] = []
    for group in getattr(outcome.scope, "groups", ()) or ():
        package = _path(getattr(group, "package_name", None))
        for artifact in select_group_artifacts(group, scan_splits=scan_splits):
            path = _selected_artifact_path(artifact)
            expected.append((package, path))
            expected_hashes[(package, path)] = _selected_artifact_sha256(artifact)
            digest_entries.append(_selection_digest_entry(package, artifact))

    terminal: list[tuple[str, str]] = []
    terminal_hashes: dict[tuple[str, str], str] = {}
    for app in outcome.results:
        package = _path(getattr(app, "package_name", None))
        for artifact in getattr(app, "artifacts", ()) or ():
            identity = (package, _artifact_path(artifact))
            terminal.append(identity)
            terminal_hashes[identity] = _terminal_artifact_sha256(artifact)

    expected_counts = Counter(expected)
    expected_set = set(expected)
    terminal_counts = Counter(terminal)
    terminal_set = set(terminal)
    duplicate_selected = sorted(
        f"{package}:{path}" for (package, path), count in expected_counts.items() if count > 1
    )
    duplicate_terminal = sorted(f"{package}:{path}" for (package, path), count in terminal_counts.items() if count > 1)
    foreign = sorted(f"{package}:{path}" for package, path in terminal_set - expected_set)
    missing = sorted(f"{package}:{path}" for package, path in expected_set - terminal_set)
    shared_identities = expected_set & terminal_set
    missing_terminal_hashes = sorted(
        f"{package}:{path}"
        for package, path in shared_identities
        if expected_hashes.get((package, path))
        and not terminal_hashes.get((package, path))
    )
    content_hash_mismatches = sorted(
        (
            f"{package}:{path}:expected={expected_hashes[(package, path)]}:"
            f"actual={terminal_hashes[(package, path)]}"
        )
        for package, path in shared_identities
        if expected_hashes.get((package, path))
        and terminal_hashes.get((package, path))
        and expected_hashes[(package, path)] != terminal_hashes[(package, path)]
    )
    content_verified_artifacts = sum(
        1
        for identity in shared_identities
        if expected_hashes.get(identity)
        and terminal_hashes.get(identity) == expected_hashes.get(identity)
    )
    expected_packages = {_path(getattr(group, "package_name", None)) for group in getattr(outcome.scope, "groups", ()) or ()}
    outcome_packages = {_path(getattr(app, "package_name", None)) for app in outcome.results}
    foreign_packages = sorted(outcome_packages - expected_packages)
    missing_packages = sorted(expected_packages - outcome_packages)
    missing_canonical_rows = sorted(
        _path(getattr(app, "package_name", None))
        for app in outcome.results
        if require_canonical_persistence
        and _path(getattr(app, "package_name", None)) in expected_packages
        and not getattr(app, "static_run_id", None)
    )
    uncommitted_canonical_rows = sorted(
        _path(getattr(app, "package_name", None))
        for app in outcome.results
        if require_canonical_persistence
        and _path(getattr(app, "package_name", None)) in expected_packages
        and getattr(app, "static_run_id", None)
        and str(getattr(app, "persistence_transaction_state", "") or "").lower()
        != "committed"
    )
    nonterminal_packages = sorted(
        _path(getattr(app, "package_name", None))
        for app in outcome.results
        if str(getattr(app, "final_status", "")).lower() not in {"complete", "partial", "failed", "skipped"}
    )
    failed_artifacts = sum(int(getattr(app, "failed_artifacts", 0) or 0) for app in outcome.results)
    persistence_failed = bool(
        require_canonical_persistence and getattr(outcome, "persistence_failed", False)
    )
    canonical_failed = bool(
        require_canonical_persistence and getattr(outcome, "canonical_failed", False)
    )
    selection_digest = hashlib.sha256("\n".join(sorted(digest_entries)).encode("utf-8")).hexdigest()

    inconsistent = bool(
        duplicate_selected
        or duplicate_terminal
        or foreign
        or foreign_packages
        or content_hash_mismatches
    )
    incomplete = bool(
        not expected
        or missing
        or missing_packages
        or nonterminal_packages
        or missing_canonical_rows
        or uncommitted_canonical_rows
        or persistence_failed
        or canonical_failed
        or missing_terminal_hashes
        or failed_artifacts
    )
    if inconsistent:
        state = "INCONSISTENT"
    elif incomplete:
        state = "INCOMPLETE"
    else:
        state = "COMPLETE_RECONCILED"
    return {
        "schema_version": 1,
        "selection_source": "frozen_outcome_scope",
        "selection_artifact_manifest_sha256": selection_digest,
        "selected_artifacts": len(expected),
        "successful_terminal_artifacts": len(terminal),
        "explicit_failed_artifacts": failed_artifacts,
        "accounted_artifacts": len(expected_set & terminal_set),
        "unexplained_artifacts": len(missing),
        "empty_selection": not expected,
        "duplicate_selected_artifact_identities": duplicate_selected,
        "duplicate_terminal_artifact_identities": duplicate_terminal,
        "foreign_terminal_artifact_identities": foreign,
        "unexplained_artifact_identities": missing,
        "content_verified_artifacts": content_verified_artifacts,
        "missing_terminal_content_hashes": missing_terminal_hashes,
        "content_hash_mismatches": content_hash_mismatches,
        "selected_packages": len(expected_packages),
        "terminal_packages": len(outcome_packages & expected_packages),
        "missing_package_outcomes": missing_packages,
        "foreign_package_outcomes": foreign_packages,
        "nonterminal_package_outcomes": nonterminal_packages,
        "missing_canonical_package_rows": missing_canonical_rows,
        "uncommitted_canonical_package_rows": uncommitted_canonical_rows,
        "canonical_persistence_required": require_canonical_persistence,
        "canonical_persistence_failed": persistence_failed,
        "canonical_finalization_failed": canonical_failed,
        "status": state,
    }


def write_static_completion_reconciliation(path: Path, receipt: Mapping[str, object]) -> Path:
    atomic_write_text(path, json.dumps(dict(receipt), indent=2, sort_keys=True) + "\n")
    return path


__all__ = ["build_static_completion_reconciliation", "write_static_completion_reconciliation"]
