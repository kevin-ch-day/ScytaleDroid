"""Current Permission Intel guard for active legacy Scytale readers."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from scytaledroid.Database.db_core import permission_intel

_AOSP_AUTHORITIES = frozenset({"AOSP_PUBLIC", "AOSP_HIDDEN", "AOSP_INTERNAL", "AOSP_MODULE"})
_HISTORICAL = frozenset({"historical", "legacy_removed", "removed"})


@dataclass(frozen=True)
class PermissionInterpretation:
    token: str
    canonical_permission: str | None
    identifier_recognition: str
    authority_scope: str
    identifier_kind: str
    declaration_state: str
    evidence_state: str
    feature_dependency: str | None
    protection_result: str | None
    platform_authority_accepted: bool
    source_row: dict[str, object]


def _text(value: object) -> str:
    return str(value or "").strip()


def _kind(non_permission: str, anomaly: str) -> str:
    value = (non_permission or anomaly).lower()
    if "action" in value:
        return "ACTION_OR_EVENT"
    if "policy" in value:
        return "POLICY_IDENTIFIER"
    if value in {
        "hardware_feature",
        "permission_group",
        "other_android_constant",
        "generic_shorthand",
    }:
        return "FEATURE_OR_OTHER_IDENTIFIER"
    return "MALFORMED_OR_VARIANT"


def interpret_permission_row(token: str, row: dict[str, object]) -> PermissionInterpretation:
    canonical = _text(row.get("canonical_permission")) or None
    exact = bool(canonical and token == canonical)
    case_only = bool(canonical and not exact and token.lower() == canonical.lower())
    authority = _text(row.get("authority_class")).upper()
    fact_scope = _text(row.get("fact_scope")).lower()
    fact_source = _text(row.get("fact_source_type")).lower()
    fact_permission = _text(row.get("fact_permission_string"))
    fact_exact = bool(fact_permission and token == fact_permission)
    fact_lifecycle = _text(row.get("fact_lifecycle")).lower()
    catalog_lifecycle = _text(row.get("catalog_lifecycle")).lower()
    legacy_lifecycle = _text(row.get("legacy_lifecycle")).lower()
    feature = _text(row.get("feature_dependency")) or None
    conflicts = int(row.get("unresolved_conflict_count") or 0)
    protection = _text(row.get("catalog_protection") or row.get("fact_protection")) or None
    historical = catalog_lifecycle in _HISTORICAL or (
        fact_exact
        and (fact_scope == "removed_api" or fact_lifecycle in _HISTORICAL)
    )
    recognition = (
        "EXACT_ACCEPTED_CANONICAL"
        if exact
        else "CASE_ONLY_CANONICAL_CANDIDATE"
        if case_only
        else "UNRESOLVED_IDENTIFIER"
    )

    if exact:
        platform = authority in _AOSP_AUTHORITIES
        scope = (
            "HISTORICAL_PLATFORM"
            if historical and platform
            else "AOSP_PLATFORM"
            if platform
            else "OEM_OR_VENDOR"
            if authority == "OEM_OR_VENDOR"
            else "THIRD_PARTY_APPLICATION_DEFINED"
            if authority == "APPLICATION_DEFINED"
            else "UNKNOWN"
        )
        return PermissionInterpretation(
            token,
            canonical,
            recognition,
            scope,
            "PERMISSION",
            "NOT_APPLICABLE"
            if historical
            else "MULTIPLE_FEATURE_DEPENDENT_ALTERNATIVES"
            if conflicts
            else "CONDITIONED"
            if feature
            else "UNCONDITIONAL",
            "ACCEPTED_CANONICAL",
            feature,
            None if conflicts or historical else protection,
            platform,
            row,
        )

    non_permission = _text(row.get("non_permission_class"))
    anomaly = _text(row.get("anomaly_class"))
    anomaly_blocks = bool(
        anomaly
        and not (
            anomaly.lower() == "vendor_namespace_in_android"
            and fact_source in {"sdk_vendor_docs", "sdk_inventory"}
        )
    )
    if non_permission or anomaly_blocks or legacy_lifecycle == "invalid_token":
        return PermissionInterpretation(
            token,
            canonical,
            recognition if case_only else "NONCANONICAL_KNOWN_IDENTIFIER",
            "UNKNOWN",
            _kind(non_permission, anomaly),
            "NOT_APPLICABLE",
            "SOURCE_BACKED_IDENTIFIER_KIND",
            None,
            None,
            False,
            row,
        )

    if fact_exact and (
        fact_scope == "removed_api"
        or (fact_lifecycle in _HISTORICAL and fact_source.startswith("aosp_"))
    ):
        scope, kind = "HISTORICAL_PLATFORM", "PERMISSION"
    elif fact_exact and fact_scope == "provider_permission" and fact_source.startswith("aosp_"):
        scope, kind = "AOSP_PROVIDER_ACL", "PROVIDER_PERMISSION"
    elif (
        fact_exact
        and fact_scope == "permission_definition"
        and fact_source == "aosp_package_manifest"
    ):
        scope, kind = "AOSP_PACKAGE_DEFINED", "PERMISSION"
    elif (
        fact_exact
        and fact_scope == "permission_definition"
        and token == _text(row.get("oem_permission_string"))
        and row.get("resolved_oem_vendor_id") is not None
    ):
        scope, kind = "OEM_OR_VENDOR", "PERMISSION"
    elif (
        fact_exact
        and fact_scope == "permission_definition"
        and fact_source in {"sdk_vendor_docs", "sdk_inventory"}
    ):
        scope, kind = "SDK_INTEGRATION_CUSTOM_PERMISSION", "PERMISSION"
    elif (
        fact_exact
        and fact_scope == "permission_definition"
        and fact_source in {"chromium_source", "androidx_manifest"}
    ):
        scope, kind = "THIRD_PARTY_APPLICATION_DEFINED", "PERMISSION"
    else:
        scope = kind = ""
    if scope:
        return PermissionInterpretation(
            token,
            canonical,
            recognition if case_only else "NONCANONICAL_KNOWN_IDENTIFIER",
            scope,
            kind,
            "NOT_APPLICABLE" if scope == "HISTORICAL_PLATFORM" else "UNCONDITIONAL",
            "SOURCE_BACKED_DEFINITION",
            None,
            None if scope == "HISTORICAL_PLATFORM" else protection,
            False,
            row,
        )

    provisional = (
        _text(row.get("legacy_source_type")).lower() == "queue_apply_shell"
        or _text(row.get("legacy_source_family")).lower() == "aosp_sparse_queue_apply_shell"
        or _text(row.get("concept_status")).lower() == "provisional"
    )
    return PermissionInterpretation(
        token,
        canonical,
        recognition,
        "UNKNOWN",
        "UNKNOWN",
        "NO_DECLARATION",
        "PROVISIONAL_SEED_ONLY" if provisional else "INSUFFICIENT",
        None,
        None,
        False,
        row,
    )


@lru_cache(maxsize=64)
def _interpretations_for_tokens(
    tokens: tuple[str, ...],
) -> tuple[tuple[str, PermissionInterpretation], ...]:
    rows = permission_intel.fetch_current_permission_interpretation_rows(tokens)
    by_norm: dict[str, dict[str, object]] = {}
    for row in rows:
        requested_key = row.get("lookup_token_norm")
        key = (
            str(requested_key).lower()
            if requested_key is not None
            else _text(row.get("constant_value") or row.get("canonical_permission")).lower()
        )
        materialized = dict(row)
        if key in by_norm and by_norm[key] != materialized:
            raise RuntimeError(f"conflicting Permission Intel evidence for requested token: {key}")
        by_norm[key] = materialized
    return tuple(
        (token, interpret_permission_row(token, by_norm.get(token.lower(), {}))) for token in tokens
    )


def fetch_current_interpretations(values: list[str]) -> dict[str, PermissionInterpretation]:
    tokens = tuple(
        dict.fromkeys(value for value in values if isinstance(value, str) and value.strip())
    )
    if not tokens:
        return {}
    return dict(_interpretations_for_tokens(tokens))


def clear_interpretation_cache() -> None:
    """Drop cached interpretation batches (tests that stub the Intel reader)."""

    _interpretations_for_tokens.cache_clear()


__all__ = [
    "PermissionInterpretation",
    "clear_interpretation_cache",
    "fetch_current_interpretations",
    "interpret_permission_row",
]
