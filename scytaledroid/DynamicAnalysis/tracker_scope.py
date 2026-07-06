"""Helpers for scoping dynamic tracker runs to the current active static identity."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.plan_selection import load_plan_candidates


def resolve_active_package_identity(package_name: str) -> tuple[str | None, str | None]:
    """Return the current active (version_code, base_apk_sha256) from the newest valid plan."""
    try:
        candidates, _note = load_plan_candidates(package_name)
    except Exception:
        return (None, None)
    if not candidates:
        return (None, None)
    newest = sorted(candidates, key=lambda row: row.get("generated_at") or "", reverse=True)[0]
    identity = newest.get("identity") if isinstance(newest.get("identity"), dict) else {}
    version_code = str(
        identity.get("version_code")
        or newest.get("version_code")
        or ""
    ).strip() or None
    base_sha = str(identity.get("base_apk_sha256") or "").strip().lower() or None
    return (version_code, base_sha)


def resolve_tracker_run_identity(
    package_name: str,
    run: dict,
    *,
    run_identity_cache: dict[str, tuple[str | None, str | None]],
    output_dir: str,
) -> tuple[str | None, str | None]:
    version_code = str(
        run.get("version_code")
        or run.get("observed_version_code")
        or ""
    ).strip() or None
    base_sha = str(run.get("base_apk_sha256") or "").strip().lower() or None
    if version_code or base_sha:
        return (version_code, base_sha)

    run_id = str(run.get("run_id") or "").strip()
    if not run_id:
        return (None, None)
    cached = run_identity_cache.get(run_id)
    if cached is not None:
        return cached

    manifest_path = Path(output_dir) / "evidence" / "dynamic" / run_id / "run_manifest.json"
    if not manifest_path.exists():
        run_identity_cache[run_id] = (None, None)
        return (None, None)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        run_identity_cache[run_id] = (None, None)
        return (None, None)

    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    ident = target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}
    pkg = str(target.get("package_name") or package_name or "").strip().lower()
    if pkg and pkg != str(package_name or "").strip().lower():
        run_identity_cache[run_id] = (None, None)
        return (None, None)

    version_code = str(
        ident.get("version_code")
        or target.get("version_code")
        or ""
    ).strip() or None
    base_sha = str(ident.get("base_apk_sha256") or "").strip().lower() or None
    resolved = (version_code, base_sha)
    run_identity_cache[run_id] = resolved
    return resolved


def scope_tracker_runs_to_active_identity(
    package_name: str,
    runs: list[dict],
    *,
    resolve_tracker_run_identity_fn,
    active_identity_fn=resolve_active_package_identity,
) -> dict[str, object]:
    valid_runs = [r for r in runs if isinstance(r, dict) and r.get("valid_dataset_run") is True]
    active_identity = active_identity_fn(package_name)
    if not (active_identity[0] or active_identity[1]):
        for r in sorted(valid_runs, key=lambda row: str(row.get("ended_at") or row.get("started_at") or ""), reverse=True):
            ident = resolve_tracker_run_identity_fn(package_name, r)
            if ident[0] or ident[1]:
                active_identity = ident
                break

    active_runs: list[dict] = []
    legacy_runs: list[dict] = []
    legacy_identity_seen: set[tuple[str, str]] = set()
    for r in valid_runs:
        ident = resolve_tracker_run_identity_fn(package_name, r)
        ident_key = (ident[0] or "", ident[1] or "")
        if (active_identity[0] or active_identity[1]) and ident != active_identity:
            legacy_runs.append(r)
            if ident_key != ("", ""):
                legacy_identity_seen.add(ident_key)
            continue
        active_runs.append(r)

    return {
        "active_identity": active_identity,
        "active_runs": active_runs,
        "valid_runs": valid_runs,
        "legacy_runs": legacy_runs,
        "legacy_valid": len(legacy_runs),
        "legacy_builds": len(legacy_identity_seen),
        "legacy_pcap_available": sum(1 for run in legacy_runs if bool(run.get("pcap_available"))),
    }


def build_scoped_dataset_counts(
    package_name: str,
    runs: list[dict],
    *,
    cfg: object | None = None,
    resolve_tracker_run_identity_fn,
    active_identity_fn=resolve_active_package_identity,
) -> dict[str, int | str]:
    scoped = scope_tracker_runs_to_active_identity(
        package_name,
        runs,
        resolve_tracker_run_identity_fn=resolve_tracker_run_identity_fn,
        active_identity_fn=active_identity_fn,
    )
    active_runs = list(scoped["active_runs"])
    valid_runs = list(scoped["valid_runs"])
    active_identity = scoped["active_identity"]

    out = {
        "baseline_countable": 0,
        "baseline_extra": 0,
        "baseline_not_idle_supplemental": 0,
        "baseline_low_signal_supplemental": 0,
        "interactive_countable": 0,
        "interactive_extra": 0,
        "interactive_low_signal_supplemental": 0,
        "interactive_scripted_countable": 0,
        "interactive_scripted_extra": 0,
        "interactive_manual_countable": 0,
        "interactive_manual_extra": 0,
        "interactive_other_countable": 0,
        "interactive_other_extra": 0,
        "legacy_valid": int(scoped["legacy_valid"]),
        "legacy_builds": int(scoped["legacy_builds"]),
        "legacy_pcap_available": int(scoped.get("legacy_pcap_available") or 0),
        "technical_valid_total": len(valid_runs),
        "technical_valid_active": len(active_runs),
        "active_version_code": active_identity[0] or "",
        "active_base_sha": active_identity[1] or "",
    }

    baseline_needed = max(0, int(getattr(cfg, "baseline_required", 3)))
    interactive_needed = max(0, int(getattr(cfg, "interactive_required", 4)))
    baseline_seen = 0
    interactive_seen = 0
    indexed: list[tuple[int, dict]] = [(i, r) for i, r in enumerate(active_runs)]
    indexed.sort(
        key=lambda item: (
            str(item[1].get("ended_at") or item[1].get("started_at") or ""),
            item[0],
        )
    )
    for _, r in indexed:
        prof = str(r.get("run_profile") or "").strip().lower()
        paper_eligible = r.get("paper_eligible")
        if paper_eligible is False:
            continue
        is_baseline = prof.startswith("baseline") or ("baseline" in prof) or ("idle" in prof)
        is_interactive = ("interaction" in prof) or ("interactive" in prof)
        countable_raw = r.get("countable")
        explicit_countable = (
            True
            if countable_raw is True
            else False
            if countable_raw is False
            else None
        )
        if explicit_countable is False and _is_repairable_stale_baseline_noncountable(r, prof):
            explicit_countable = None

        # Prefer the tracker/finalization truth when present. This avoids
        # recomputing quota progress from profile order alone for runs that were
        # intentionally retained as valid-but-supplemental.
        if explicit_countable is not None:
            if not explicit_countable:
                if bool(r.get("extra_run")):
                    if is_baseline:
                        if prof == "baseline_idle" and bool(r.get("low_signal")):
                            out["baseline_low_signal_supplemental"] += 1
                        elif prof == "baseline_idle" and bool(r.get("baseline_not_idle")):
                            out["baseline_not_idle_supplemental"] += 1
                        else:
                            out["baseline_extra"] += 1
                    elif is_interactive:
                        kind = "other"
                        if "interaction_manual" in prof or prof.endswith("_manual") or "manual" in prof:
                            kind = "manual"
                        elif "interaction_scripted" in prof or "scripted" in prof or "script" in prof:
                            kind = "scripted"
                        if bool(r.get("low_signal")):
                            out["interactive_low_signal_supplemental"] += 1
                        else:
                            out["interactive_extra"] += 1
                            out[f"interactive_{kind}_extra"] += 1
                continue
            if is_baseline:
                baseline_seen += 1
                out["baseline_countable"] += 1
                continue
            if is_interactive:
                kind = "other"
                if "interaction_manual" in prof or prof.endswith("_manual") or "manual" in prof:
                    kind = "manual"
                elif "interaction_scripted" in prof or "scripted" in prof or "script" in prof:
                    kind = "scripted"
                interactive_seen += 1
                out["interactive_countable"] += 1
                out[f"interactive_{kind}_countable"] += 1
                continue

        if is_baseline:
            if baseline_seen < baseline_needed:
                baseline_seen += 1
                out["baseline_countable"] += 1
            else:
                out["baseline_extra"] += 1
            continue
        if is_interactive:
            kind = "other"
            if "interaction_manual" in prof or prof.endswith("_manual") or "manual" in prof:
                kind = "manual"
            elif "interaction_scripted" in prof or "scripted" in prof or "script" in prof:
                kind = "scripted"
            if interactive_seen < interactive_needed:
                interactive_seen += 1
                out["interactive_countable"] += 1
                out[f"interactive_{kind}_countable"] += 1
            else:
                out["interactive_extra"] += 1
                out[f"interactive_{kind}_extra"] += 1
            continue
    return out


def _is_repairable_stale_baseline_noncountable(run: dict, profile_lc: str) -> bool:
    """Return whether a stale baseline ``countable=false`` can re-enter quota marking."""
    if not (profile_lc.startswith("baseline") or ("baseline" in profile_lc) or ("idle" in profile_lc)):
        return False
    if run.get("valid_dataset_run") is False or run.get("paper_eligible") is False:
        return False
    if bool(run.get("extra_run")):
        return False
    if profile_lc == "baseline_idle" and bool(run.get("low_signal")):
        return False
    if profile_lc == "baseline_idle" and bool(run.get("baseline_not_idle")):
        return False
    return True


def default_resolve_tracker_run_identity(package_name: str, run: dict) -> tuple[str | None, str | None]:
    return resolve_tracker_run_identity(
        package_name,
        run,
        run_identity_cache={},
        output_dir=app_config.OUTPUT_DIR,
    )


__all__ = [
    "build_scoped_dataset_counts",
    "default_resolve_tracker_run_identity",
    "resolve_active_package_identity",
    "resolve_tracker_run_identity",
    "scope_tracker_runs_to_active_identity",
]
