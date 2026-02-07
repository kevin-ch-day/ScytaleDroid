"""Dynamic plan selection helpers for the CLI."""

from __future__ import annotations

import json
import zoneinfo
from datetime import UTC, datetime
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
    return ensure_plan_or_error(
        package_name,
        prompt_run_static=True,
        deterministic=False,
        run_static_callback=_run_static_for_package,
    )


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

    return ensure_plan_or_error(
        package_name,
        prompt_run_static=False,
        deterministic=True,
        run_static_callback=None,
    )


def ensure_plan_or_error(
    package_name: str,
    *,
    prompt_run_static: bool,
    deterministic: bool,
    run_static_callback,
) -> dict[str, object] | None:
    candidates, note = _load_plan_candidates(package_name)
    if not candidates:
        if not prompt_run_static:
            return None
        if _prompt_run_static_now(package_name, note, run_static_callback):
            candidates, _note = _load_plan_candidates(package_name)
    if not candidates:
        return None
    if deterministic:
        selection = _pick_newest_candidate(candidates)
        return _build_selection(selection)
    return _prompt_plan_selection(package_name, candidates)


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
        identity_raw = payload.get("run_identity") if isinstance(payload.get("run_identity"), dict) else {}
        if identity_raw.get("identity_valid") is False:
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


def _prompt_plan_selection(package_name: str, candidates: list[dict[str, object]]) -> dict[str, object] | None:
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
        if _run_static_for_package(package_name):
            refreshed, _note = _load_plan_candidates(package_name)
            if refreshed:
                selection = _pick_newest_candidate(refreshed)
                return _build_selection(selection)
        _warn_missing_plan()
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


def _prompt_run_static_now(
    package_name: str,
    note: str | None,
    run_static_callback,
) -> bool:
    print(status_messages.status(note or "No dynamic plan found for package.", level="warn"))
    print()
    run_static = prompt_utils.prompt_yes_no(
        "Run static analysis now for this app to generate a plan?",
        default=True,
    )
    if not run_static:
        print(status_messages.status("Baseline selection cancelled.", level="warn"))
        return False
    if run_static_callback is None:
        run_static_callback = _run_static_for_package
    if not run_static_callback(package_name):
        return False
    return True


def _warn_missing_plan() -> None:
    print(
        status_messages.status(
            "Static analysis completed but no plan was generated. Run static analysis interactively to diagnose.",
            level="error",
        )
    )


def _run_static_for_package(package_name: str) -> bool:
    from scytaledroid.Config import app_config
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from scytaledroid.StaticAnalysis.session import normalize_session_stamp

    groups = group_artifacts()
    group = next(
        (g for g in groups if (g.package_name or "").lower() == package_name.lower()),
        None,
    )
    if not group:
        print(status_messages.status("No APK artifacts found locally for this package.", level="error"))
        return False
    session_stamp = normalize_session_stamp(
        f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{package_name}"
    )
    selection = ScopeSelection(scope="app", label=group.package_name or package_name, groups=(group,))
    params = RunParameters(
        profile="full",
        scope=selection.scope,
        scope_label=selection.label,
        session_stamp=session_stamp,
        show_split_summaries=False,
    )
    base_dir = Path(app_config.DATA_DIR) / "device_apks"
    spec = build_static_run_spec(
        selection=selection,
        params=params,
        base_dir=base_dir,
        run_mode="interactive",
        quiet=False,
        noninteractive=False,
    )
    outcome = execute_run_spec(spec)
    if not outcome:
        print(status_messages.status("Static analysis did not return a result.", level="warn"))
        return False
    if getattr(outcome, "aborted", False):
        print(status_messages.status("Static analysis was aborted.", level="warn"))
        return False
    return True


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


__all__ = [
    "ensure_plan_or_error",
    "resolve_plan_selection",
    "resolve_plan_selection_noninteractive",
    "load_plan_candidates",
    "print_plan_selection_banner",
]
