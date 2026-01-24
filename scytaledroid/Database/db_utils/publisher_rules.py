"""Publisher mapping helpers using DB-driven rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Sequence

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..db_core import run_sql
from .package_utils import normalize_package_name


@dataclass(frozen=True)
class PublisherRule:
    publisher_key: str
    match_type: str
    pattern: str


_FALLBACK_RULES: Sequence[PublisherRule] = (
    PublisherRule("ANDROID_AOSP", "EXACT", "android"),
    PublisherRule("ANDROID_AOSP", "PREFIX", "com.android."),
    PublisherRule("GOOGLE", "PREFIX", "com.google."),
    PublisherRule("MOTOROLA", "PREFIX", "com.motorola."),
    PublisherRule("QUALCOMM", "PREFIX", "com.qualcomm."),
    PublisherRule("QUALCOMM", "PREFIX", "com.qti."),
    PublisherRule("QUALCOMM", "PREFIX", "vendor.qti."),
    PublisherRule("QUALCOMM", "PREFIX", "org.codeaurora."),
    PublisherRule("TMOBILE", "PREFIX", "com.tmobile."),
    PublisherRule("ATT", "PREFIX", "com.att."),
    PublisherRule("VERIZON", "PREFIX", "com.verizon."),
)


def load_publisher_rules() -> List[PublisherRule]:
    """Return DB-driven publisher rules or a minimal fallback list."""

    try:
        rows = run_sql(
            """
            SELECT publisher_key, match_type, pattern
            FROM android_publisher_prefix_rules
            WHERE is_active=1
            ORDER BY priority ASC, rule_id ASC
            """,
            fetch="all",
            dictionary=True,
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to load publisher rules; using fallback list ({exc}).",
            category="database",
        )
        return list(_FALLBACK_RULES)

    rules: List[PublisherRule] = []
    for row in rows or []:
        publisher_key = str(row.get("publisher_key") or "").strip()
        match_type = str(row.get("match_type") or "").strip().upper()
        pattern = str(row.get("pattern") or "").strip().lower()
        if not publisher_key or not pattern:
            continue
        rules.append(PublisherRule(publisher_key, match_type, pattern))

    if not rules:
        log.warning(
            "Publisher rules table is empty; using fallback list.",
            category="database",
        )
        return list(_FALLBACK_RULES)
    return rules


def resolve_publisher_key(package_name: str, rules: Sequence[PublisherRule]) -> Optional[str]:
    """Return the first matching publisher key for the supplied package."""

    if not package_name:
        return None
    for rule in rules:
        if rule.match_type == "EXACT":
            if package_name == rule.pattern:
                return rule.publisher_key
        elif rule.match_type == "PREFIX":
            if package_name.startswith(rule.pattern):
                return rule.publisher_key
    return None


def ensure_vendor_misc() -> None:
    """Ensure the VENDOR_MISC publisher exists."""

    run_sql(
        """
        INSERT IGNORE INTO android_app_publishers
            (publisher_key, display_name, description, sort_order, is_active)
        VALUES
            ('VENDOR_MISC', 'Vendor Misc', 'Unmapped vendor/apps bucket', 998, 1)
        """,
        query_name="publishers.ensure_vendor_misc",
    )


def apply_publisher_mapping(
    package_names: Iterable[str],
    *,
    context: Optional[Mapping[str, object]] = None,
) -> None:
    """Apply publisher rules to the provided package names."""

    packages = [normalize_package_name(pkg, context="database") for pkg in package_names]
    packages = [pkg for pkg in packages if pkg]
    if not packages:
        return

    ensure_vendor_misc()
    rules = load_publisher_rules()
    query_context = dict(context or {})

    for package_name in packages:
        row = run_sql(
            "SELECT publisher_key FROM apps WHERE package_name=%s",
            (package_name,),
            fetch="one",
            query_name="publishers.lookup",
            context=query_context,
        )
        if not row:
            continue
        current = str(row[0] or "").strip().upper()
        if current not in {"UNKNOWN", "VENDOR_MISC"}:
            continue
        mapped = resolve_publisher_key(package_name, rules) or "VENDOR_MISC"
        if mapped == current:
            continue
        run_sql(
            "UPDATE apps SET publisher_key=%s, updated_at=CURRENT_TIMESTAMP WHERE package_name=%s",
            (mapped, package_name),
            query_name="publishers.update",
            context=query_context,
        )


__all__ = [
    "PublisherRule",
    "load_publisher_rules",
    "resolve_publisher_key",
    "apply_publisher_mapping",
]
