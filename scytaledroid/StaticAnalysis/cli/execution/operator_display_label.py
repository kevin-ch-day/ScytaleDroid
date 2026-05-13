"""Single operator-facing app label resolver for static scan UX (progress, persistence, summaries)."""

from __future__ import annotations

from collections.abc import Mapping


def build_operator_label_metadata_from_report(report: object | None) -> dict[str, object]:
    """Harvest-style keys for :func:`resolve_operator_app_label` (manifest + report metadata)."""

    meta: dict[str, object] = {}
    if report is None:
        return meta
    md = getattr(report, "metadata", None)
    if isinstance(md, Mapping):
        for key in ("app_label", "display_name"):
            val = md.get(key)
            if val is not None and str(val).strip():
                meta[str(key)] = val
    try:
        manifest = getattr(report, "manifest", None)
        if manifest is not None:
            al = getattr(manifest, "app_label", None)
            if al is not None and str(al).strip():
                meta.setdefault("app_label", al)
    except Exception:
        pass
    return meta


def resolve_operator_app_label(
    package_name: str,
    metadata: Mapping[str, object],
    v3_overrides: Mapping[str, str],
    db_display_names: Mapping[str, str],
) -> str | None:
    """Human-facing label: v3 override → harvest metadata → apps.display_name → package."""

    key = str(package_name or "").strip().lower()
    if not key:
        return None
    v3 = str(v3_overrides.get(key) or "").strip()
    if v3:
        return v3
    raw = None
    if isinstance(metadata, Mapping):
        raw = metadata.get("app_label") or metadata.get("display_name")
    meta_lbl = str(raw).strip() if raw is not None else ""
    if meta_lbl and meta_lbl.lower() != key:
        return meta_lbl
    db_lbl = str(db_display_names.get(key) or "").strip()
    if db_lbl:
        return db_lbl
    if meta_lbl:
        return meta_lbl
    return str(package_name).strip() or None


__all__ = ["build_operator_label_metadata_from_report", "resolve_operator_app_label"]
