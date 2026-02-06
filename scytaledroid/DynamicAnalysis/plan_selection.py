"""Dynamic plan selection helpers for the CLI."""

from __future__ import annotations

import json
import zoneinfo
from datetime import datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.plans.loader import (
    SUPPORTED_SIGNATURE_VERSIONS,
    extract_plan_identity,
)
from scytaledroid.StaticAnalysis.core.repository import group_artifacts, load_display_name_map
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.evidence_store import filesystem_safe_slug
from scytaledroid.Utils.System.world_clock.display import format_display_time


def resolve_plan_selection(package_name: str) -> dict[str, object] | None:
    candidates, note = _load_plan_candidates(package_name)
    if not candidates:
        return _prompt_missing_baseline(package_name, note)

    grouped: dict[str, list[dict[str, object]]] = {}
    for candidate in candidates:
        key = candidate["identity_key"]
        grouped.setdefault(key, []).append(candidate)

    if len(grouped) == 1:
        only_key = next(iter(grouped))
        selection = _pick_newest_candidate(grouped[only_key])
        return _build_selection(selection)

    return _prompt_baseline_selection(package_name, candidates)


def load_plan_candidates(package_name: str) -> tuple[list[dict[str, object]], str | None]:
    """Load plan candidates without prompting.

    This is used by dataset-mode flows that must be deterministic and non-interactive.
    """

    return _load_plan_candidates(package_name)


def resolve_plan_selection_noninteractive(package_name: str) -> dict[str, object] | None:
    """Deterministically pick the newest valid plan candidate without prompting.

    If multiple identities exist, we still pick the newest generated plan overall.
    Dataset-mode runs must not prompt (operator variance).
    """

    candidates, _note = _load_plan_candidates(package_name)
    if not candidates:
        return None
    selection = _pick_newest_candidate(candidates)
    return _build_selection(selection)


def print_plan_selection_banner(selection: dict[str, object]) -> None:
    package_name = selection.get("package_name") or "unknown"
    display_name = _resolve_display_name(str(package_name))
    app_label = (
        f"{display_name} ({package_name})"
        if display_name and display_name.lower() != str(package_name).lower()
        else package_name
    )
    version = _format_version(selection.get("version_name"), selection.get("version_code"))
    run_sig = selection.get("run_signature") or "unknown"
    artifact_hash = selection.get("artifact_set_hash") or "unknown"
    static_run_id = selection.get("static_run_id") or "unknown"
    generated_at = _format_generated_at(selection.get("generated_at"))

    print()
    lines = [
        ("App", app_label),
        ("Version", version),
        ("Artifact", f"SHA256 {_prefix(selection.get('base_apk_sha256'))} | Bundle {_prefix(artifact_hash)}"),
        ("Signature", f"{selection.get('run_signature_version') or 'v?'} / {_prefix(run_sig)}"),
        ("Generated", generated_at),
        ("Static run", str(static_run_id)),
    ]
    status_messages.print_strip("Baseline selected", lines, width=70)


def _load_plan_candidates(package_name: str) -> tuple[list[dict[str, object]], str | None]:
    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "dynamic_plan"
    if not base_dir.exists():
        return [], "No dynamic plan directory found."

    slug = filesystem_safe_slug(package_name)
    paths = sorted(base_dir.glob(f"{slug}-*.json"))
    if not paths:
        return [], "No dynamic plans found for package."

    candidates: list[dict[str, object]] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        identity = extract_plan_identity(payload)
        if str(identity.get("package") or "") != package_name:
            continue
        if identity.get("run_signature_version") not in SUPPORTED_SIGNATURE_VERSIONS:
            continue
        if not identity.get("run_signature") or not identity.get("artifact_set_hash"):
            continue
        generated_at = _parse_generated_at(payload.get("generated_at"))
        identity_key = _identity_key(identity)
        candidates.append(
            {
                "path": path,
                "identity": identity,
                "generated_at": generated_at,
                "identity_key": identity_key,
                "version_name": payload.get("version_name"),
                "version_code": payload.get("version_code"),
                "package_name": payload.get("package_name") or package_name,
                "run_signature_version": identity.get("run_signature_version"),
            }
        )
    if not candidates:
        return [], "No valid dynamic plan candidates found; regenerate plan."
    return candidates, None


def _pick_newest_candidate(candidates: list[dict[str, object]]) -> dict[str, object]:
    return sorted(
        candidates,
        key=lambda row: row.get("generated_at") or "",
        reverse=True,
    )[0]


def _build_selection(candidate: dict[str, object]) -> dict[str, object]:
    identity = candidate["identity"]
    return {
        "plan_path": str(candidate["path"]),
        "static_run_id": identity.get("static_run_id"),
        "package_name": identity.get("package"),
        "version_name": candidate.get("version_name"),
        "version_code": candidate.get("version_code"),
        "base_apk_sha256": identity.get("base_apk_sha256"),
        "artifact_set_hash": identity.get("artifact_set_hash"),
        "run_signature": identity.get("run_signature"),
        "run_signature_version": identity.get("run_signature_version"),
        "generated_at": candidate.get("generated_at"),
    }


def _prompt_baseline_selection(package_name: str, candidates: list[dict[str, object]]) -> dict[str, object] | None:
    print()
    menu_utils.print_header("Baseline selection required")
    print(
        status_messages.status(
            "Multiple baseline artifacts found for this app. Choose a baseline or run static analysis.",
            level="warn",
        )
    )
    rows = []
    sorted_candidates = sorted(candidates, key=lambda row: row.get("generated_at") or "", reverse=True)
    for idx, candidate in enumerate(sorted_candidates, start=1):
        rows.append(_format_candidate_row(idx, candidate))
    table_utils.render_table(
        ["#", "Version", "SHA256", "Bundle", "Generated"],
        rows,
        compact=True,
    )
    print()
    print("Options: [number] Select baseline  |  S Run static analysis  |  0 Cancel")
    choice = prompt_utils.prompt_text("Select baseline", required=False).strip().lower()
    if choice == "s":
        from scytaledroid.StaticAnalysis.cli import static_analysis_menu

        static_analysis_menu()
        return None
    if choice == "0" or not choice:
        print(status_messages.status("Baseline selection cancelled.", level="warn"))
        return None
    try:
        index = int(choice) - 1
    except ValueError:
        print(status_messages.status("Invalid selection.", level="warn"))
        return None
    if index < 0 or index >= len(sorted_candidates):
        print(status_messages.status("Selection out of range.", level="warn"))
        return None
    return _build_selection(sorted_candidates[index])


def _prompt_missing_baseline(package_name: str, note: str | None) -> dict[str, object] | None:
    print(status_messages.status(note or "No dynamic plan found for package.", level="warn"))
    print()
    print("Options: S Run static analysis  |  0 Cancel")
    choice = prompt_utils.prompt_text("Selection", required=False).strip().lower()
    if choice == "s":
        from scytaledroid.StaticAnalysis.cli import static_analysis_menu

        static_analysis_menu()
        return None
    print(status_messages.status("Baseline selection cancelled.", level="warn"))
    return None


def _format_candidate_row(index: int, candidate: dict[str, object]) -> list[str]:
    identity = candidate["identity"]
    version = _format_version(candidate.get("version_name"), candidate.get("version_code"))
    sha_prefix = _prefix(identity.get("base_apk_sha256"))
    bundle_prefix = _prefix(identity.get("artifact_set_hash"))
    generated = candidate.get("generated_at") or "unknown"
    return [str(index), version, sha_prefix, bundle_prefix, str(generated)]


def _format_version(version_name: object, version_code: object) -> str:
    if version_name and version_code:
        return f"{version_name} ({version_code})"
    if version_name:
        return str(version_name)
    if version_code:
        return f"(build {version_code})"
    return "unknown"


def _prefix(value: object, *, length: int = 4) -> str:
    if not value:
        return "unknown"
    value_str = str(value)
    return value_str[:length] + "…" + value_str[-length:]


def _parse_generated_at(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value)).isoformat()
    return None


def _format_generated_at(value: object) -> str:
    raw = _parse_generated_at(value)
    if not raw:
        return "unknown"
    try:
        text = str(raw).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        tz_name = getattr(app_config, "UI_LOCAL_TIMEZONE", "Etc/UTC") or "Etc/UTC"
        tz = zoneinfo.ZoneInfo(tz_name)
        localized = parsed.astimezone(tz)
        return format_display_time(localized)
    except Exception:
        return str(raw)


def _resolve_display_name(package_name: str) -> str | None:
    try:
        groups = group_artifacts()
        display_map = load_display_name_map(groups)
        return display_map.get(package_name.lower())
    except Exception:
        return None


def _identity_key(identity: dict[str, object]) -> str:
    return "|".join(
        [
            str(identity.get("base_apk_sha256") or ""),
            str(identity.get("artifact_set_hash") or ""),
            str(identity.get("run_signature") or ""),
            str(identity.get("run_signature_version") or ""),
        ]
    )


__all__ = ["resolve_plan_selection", "print_plan_selection_banner"]
__all__ = [
    "resolve_plan_selection",
    "resolve_plan_selection_noninteractive",
    "load_plan_candidates",
    "print_plan_selection_banner",
]
