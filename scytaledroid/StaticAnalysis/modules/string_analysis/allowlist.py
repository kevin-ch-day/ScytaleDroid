"""Documentary noise handling and suppression policy for string analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Sequence
from urllib.parse import urlsplit

from .constants import MULTI_LEVEL_SUFFIXES

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore


DEFAULT_POLICY_ROOT = Path("config/strings")


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome produced by a policy rule evaluation."""

    action: str
    rule: str | None = None
    reason: str | None = None
    tag: str | None = None
    note: str | None = None
    severity: str | None = None


@dataclass(frozen=True)
class PolicyContext:
    """Context describing a string observation under evaluation."""

    value: str
    source: str | None
    host: str | None
    scheme: str | None
    buckets: frozenset[str]
    host_variants: frozenset[str]
    host_full: str | None
    host_registrable: str | None
    value_lower: str = field(init=False)
    source_lower: str | None = field(init=False)

    def __post_init__(self) -> None:  # pragma: no cover - trivial assignments
        object.__setattr__(self, "value_lower", self.value.lower())
        lowered_source = self.source.lower() if self.source else None
        object.__setattr__(self, "source_lower", lowered_source)


@dataclass(frozen=True)
class RuleCondition:
    """Set of predicates that must hold for a policy rule to fire."""

    buckets_any: frozenset[str] | None = None
    host_in_group: str | None = None
    host_not_in_group: str | None = None
    host_key: str | None = None
    value_contains_group: str | None = None
    source_prefix_in: str | None = None
    source_prefix_not_in: str | None = None
    source_exact_in: str | None = None
    source_exact_not_in: str | None = None
    scheme: str | None = None

    def matches(self, context: PolicyContext, policy: "NoisePolicy") -> bool:
        if self.scheme is not None:
            if context.scheme is None or context.scheme != self.scheme:
                return False
        if self.buckets_any is not None:
            if not context.buckets or context.buckets.isdisjoint(self.buckets_any):
                return False
        if self.host_in_group is not None:
            key = self.host_key or policy.default_host_key
            if not policy._host_in_group(self.host_in_group, key, context):
                return False
        if self.host_not_in_group is not None:
            key = self.host_key or policy.default_host_key
            if policy._host_in_group(self.host_not_in_group, key, context):
                return False
        if self.value_contains_group is not None:
            substrings = policy.substring_groups.get(self.value_contains_group)
            if not substrings:
                return False
            if not any(token in context.value_lower for token in substrings):
                return False
        if self.source_prefix_in is not None:
            prefixes = policy.source_prefix_groups.get(self.source_prefix_in)
            source = context.source_lower or ""
            if not prefixes or not any(source.startswith(prefix) for prefix in prefixes):
                return False
        if self.source_prefix_not_in is not None:
            prefixes = policy.source_prefix_groups.get(self.source_prefix_not_in)
            if prefixes:
                source = context.source_lower or ""
                if any(source.startswith(prefix) for prefix in prefixes):
                    return False
        if self.source_exact_in is not None:
            exacts = policy.source_exact_groups.get(self.source_exact_in)
            if not exacts or (context.source_lower or "") not in exacts:
                return False
        if self.source_exact_not_in is not None:
            exacts = policy.source_exact_groups.get(self.source_exact_not_in)
            if exacts and (context.source_lower or "") in exacts:
                return False
        return True


@dataclass(frozen=True)
class PolicyRule:
    """Declarative rule describing how to treat matching observations."""

    name: str
    conditions: RuleCondition
    action: str
    reason: str | None = None
    tag: str | None = None
    note: str | None = None
    severity: str | None = None

    def evaluate(self, context: PolicyContext, policy: "NoisePolicy") -> PolicyDecision | None:
        if not self.conditions.matches(context, policy):
            return None
        return PolicyDecision(
            action=self.action,
            rule=self.name,
            reason=self.reason,
            tag=self.tag,
            note=self.note,
            severity=self.severity,
        )


@dataclass(frozen=True)
class HostGroup:
    """Represents both full-host and registrable host variants."""

    full_hosts: frozenset[str]
    registrable_hosts: frozenset[str]


@dataclass(frozen=True)
class NoisePolicy:
    """Represents host/source allow-lists and policy rules."""

    hosts_documentary: frozenset[str]
    sources_documentary: frozenset[str]
    host_groups: Mapping[str, HostGroup] = field(default_factory=dict)
    substring_groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    source_prefix_groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    source_exact_groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    block_override_full: frozenset[str] = frozenset()
    block_override_registrable: frozenset[str] = frozenset()
    rules: tuple[PolicyRule, ...] = ()
    default_buckets: tuple[str, ...] = ()
    default_host_key: str = "etld_plus_one"
    doc_host_defaults_full: frozenset[str] = frozenset()
    doc_host_defaults_registrable: frozenset[str] = frozenset()

    def __post_init__(self) -> None:  # pragma: no cover - normalisation
        if not self.doc_host_defaults_full and self.hosts_documentary:
            object.__setattr__(
                self,
                "doc_host_defaults_full",
                frozenset(self.hosts_documentary),
            )
        if not self.doc_host_defaults_registrable and self.hosts_documentary:
            object.__setattr__(
                self,
                "doc_host_defaults_registrable",
                frozenset(self.hosts_documentary),
            )

    def is_documentary_host(self, host: str | None) -> bool:
        if not host:
            return False
        full, registrable = _host_components(host)
        if (full and full in self.block_override_full) or (
            registrable and registrable in self.block_override_registrable
        ):
            return False
        if full and full in self.doc_host_defaults_full:
            return True
        if registrable and registrable in self.doc_host_defaults_registrable:
            return True
        return False

    def is_documentary_source(self, source: str | None) -> bool:
        if not source:
            return False
        lowered = source.lower()
        if lowered in self.sources_documentary:
            return True
        for exacts in self.source_exact_groups.values():
            if lowered in exacts:
                return True
        for prefixes in self.source_prefix_groups.values():
            if any(lowered.startswith(prefix) for prefix in prefixes):
                return True
        return False

    def evaluate(
        self,
        *,
        value: str,
        source: str | None = None,
        host: str | None = None,
        scheme: str | None = None,
        buckets: Sequence[str] | None = None,
    ) -> PolicyDecision | None:
        bucket_set = frozenset(str(bucket).lower() for bucket in buckets or ())
        lowered_host = host.lower() if host else None
        full_host, registrable = _host_components(lowered_host)
        variants = frozenset(value for value in (full_host, registrable) if value)
        lowered_scheme = scheme.lower() if scheme else None
        context = PolicyContext(
            value=value,
            source=source,
            host=lowered_host,
            scheme=lowered_scheme,
            buckets=bucket_set,
            host_variants=variants,
            host_full=full_host,
            host_registrable=registrable,
        )
        if (context.host_full and context.host_full in self.block_override_full) or (
            context.host_registrable
            and context.host_registrable in self.block_override_registrable
        ):
            return None
        for rule in self.rules:
            decision = rule.evaluate(context, self)
            if decision is not None:
                return decision
        return None

    def _host_in_group(self, name: str, key: str, context: PolicyContext) -> bool:
        group = self.host_groups.get(name)
        if not group:
            return False
        match_key = key.lower() if key else "etld_plus_one"
        if match_key == "full_host":
            candidate = context.host_full
            allowed = group.full_hosts
        else:
            candidate = context.host_registrable or context.host_full
            allowed = group.registrable_hosts or group.full_hosts
        if not candidate or not allowed:
            return False
        return candidate in allowed


def _load_config(path: Path) -> Mapping[str, object]:
    if path.is_dir():
        merged: MutableMapping[str, object] = {}
        for child in sorted(path.glob("*.toml")):
            merged = _merge_config_dicts(merged, tomllib.loads(child.read_text("utf-8")))
        return merged
    return tomllib.loads(path.read_text("utf-8"))


def _merge_config_dicts(
    base: MutableMapping[str, object], incoming: Mapping[str, object]
) -> MutableMapping[str, object]:
    merged: MutableMapping[str, object] = dict(base)
    for key, value in incoming.items():
        if isinstance(value, Mapping):
            existing = merged.get(key)
            if isinstance(existing, Mapping):
                merged[key] = _merge_config_dicts(dict(existing), value)
            else:
                merged[key] = _merge_config_dicts({}, value)
        elif isinstance(value, list):
            existing_list = list(merged.get(key, ()))
            existing_list.extend(value)
            merged[key] = existing_list
        else:
            merged[key] = value
    return merged


def load_noise_policy(path: str | Path | None) -> NoisePolicy:
    """Load a :class:`NoisePolicy` from *path* if the file exists."""

    if path is None:
        return NoisePolicy(frozenset(), frozenset())
    file_path = Path(path)
    if not file_path.exists():
        return NoisePolicy(frozenset(), frozenset())

    config = _load_config(file_path)
    defaults = config.get("defaults", {}) or {}
    default_host_key = str(defaults.get("host_key", "etld_plus_one")).lower()
    if default_host_key not in {"etld_plus_one", "full_host"}:
        default_host_key = "etld_plus_one"
    default_buckets = tuple(
        str(bucket).lower() for bucket in defaults.get("buckets", ()) if bucket
    )

    host_groups: MutableMapping[str, HostGroup] = {}
    substring_groups: MutableMapping[str, tuple[str, ...]] = {}
    source_prefix_groups: MutableMapping[str, tuple[str, ...]] = {}
    source_exact_groups: MutableMapping[str, tuple[str, ...]] = {}
    doc_hosts: set[str] = set()
    doc_host_defaults_full: set[str] = set()
    doc_host_defaults_registrable: set[str] = set()
    block_overrides_full: set[str] = set()
    block_overrides_registrable: set[str] = set()

    hosts_section = config.get("hosts", {}) or {}
    for group_name, group_data in hosts_section.items():
        entries = list(group_data.get("list", ())) if isinstance(group_data, dict) else []
        key = f"hosts.{group_name}"
        group = _build_host_group(entries)
        host_groups[key] = group
        if group_name == "block_overrides":
            block_overrides_full.update(group.full_hosts)
            block_overrides_registrable.update(group.registrable_hosts)
            continue
        doc_hosts.update(group.full_hosts)
        doc_hosts.update(group.registrable_hosts)
        if group_name == "allow_doc":
            doc_host_defaults_full.update(group.full_hosts)
            doc_host_defaults_registrable.update(group.registrable_hosts)

    placeholders = config.get("placeholders", {}) or {}
    for group_name, group_data in placeholders.items():
        entries = list(group_data.get("list", ())) if isinstance(group_data, dict) else []
        key = f"placeholders.{group_name}"
        if group_name.endswith("_contains"):
            substring_groups[key] = _normalise_substrings(entries)
        else:
            host_groups[key] = _build_host_group(entries)

    sources = config.get("sources", {}) or {}
    sources_documentary: set[str] = set()
    for group_name, group_data in sources.items():
        if not isinstance(group_data, Mapping):
            continue
        base_key = f"sources.{group_name}"
        prefix_entries = list(group_data.get("prefix", {}).get("list", ()))
        if prefix_entries:
            source_prefix_groups[f"{base_key}.prefix"] = _normalise_sources(prefix_entries)
        exact_entries = list(group_data.get("exact", {}).get("list", ()))
        if exact_entries:
            normalized_exact = _normalise_sources(exact_entries)
            source_exact_groups[f"{base_key}.exact"] = normalized_exact
            sources_documentary.update(normalized_exact)

    doc_hosts.difference_update(block_overrides_full)
    doc_hosts.difference_update(block_overrides_registrable)
    doc_host_defaults_full.difference_update(block_overrides_full)
    doc_host_defaults_registrable.difference_update(block_overrides_registrable)

    rules_config = config.get("rules", ())
    rules: list[PolicyRule] = []
    for index, raw_rule in enumerate(rules_config):
        if not isinstance(raw_rule, Mapping):
            continue
        name = str(raw_rule.get("name") or f"rule_{index}")
        when = raw_rule.get("when", {}) or {}
        then = raw_rule.get("then", {}) or {}
        action_raw = str(then.get("action", "")).strip().lower()
        if not action_raw:
            continue
        conditions = _parse_conditions(when)
        rules.append(
            PolicyRule(
                name=name,
                conditions=conditions,
                action=action_raw,
                reason=_optional_str(then.get("reason")),
                tag=_optional_str(then.get("tag")),
                note=_optional_str(then.get("note")),
                severity=_optional_str(then.get("severity")),
            )
        )

    return NoisePolicy(
        hosts_documentary=frozenset(doc_hosts),
        sources_documentary=frozenset(sources_documentary),
        host_groups=dict(host_groups),
        substring_groups=dict(substring_groups),
        source_prefix_groups=dict(source_prefix_groups),
        source_exact_groups=dict(source_exact_groups),
        block_override_full=frozenset(block_overrides_full),
        block_override_registrable=frozenset(block_overrides_registrable),
        rules=tuple(rules),
        default_buckets=default_buckets,
        default_host_key=default_host_key,
        doc_host_defaults_full=frozenset(doc_host_defaults_full),
        doc_host_defaults_registrable=frozenset(doc_host_defaults_registrable),
    )


def _parse_conditions(raw: Mapping[str, object]) -> RuleCondition:
    buckets_any = _normalise_optional_str_iterable(raw.get("buckets_any"))
    host_in_group = _optional_str(raw.get("host_in_group"))
    host_not_in_group = _optional_str(raw.get("host_not_in_group"))
    host_key = _optional_str(raw.get("host_key"))
    if host_key is not None:
        host_key = host_key.lower()
    value_contains_group = _optional_str(raw.get("value_contains_group"))
    source_prefix_in = _optional_str(raw.get("source_prefix_in"))
    source_prefix_not_in = _optional_str(raw.get("source_prefix_not_in"))
    source_exact_in = _optional_str(raw.get("source_exact_in"))
    source_exact_not_in = _optional_str(raw.get("source_exact_not_in"))
    scheme = _optional_str(raw.get("scheme"))
    if scheme is not None:
        scheme = scheme.lower()
    return RuleCondition(
        buckets_any=buckets_any,
        host_in_group=host_in_group,
        host_not_in_group=host_not_in_group,
        host_key=host_key,
        value_contains_group=value_contains_group,
        source_prefix_in=source_prefix_in,
        source_prefix_not_in=source_prefix_not_in,
        source_exact_in=source_exact_in,
        source_exact_not_in=source_exact_not_in,
        scheme=scheme,
    )


def _build_host_group(entries: Iterable[str]) -> HostGroup:
    full_hosts: set[str] = set()
    registrable_hosts: set[str] = set()
    for entry in entries:
        full, registrable = _host_components(entry)
        if full:
            full_hosts.add(full)
        if registrable:
            registrable_hosts.add(registrable)
    return HostGroup(
        full_hosts=frozenset(full_hosts),
        registrable_hosts=frozenset(registrable_hosts),
    )


def _normalise_substrings(entries: Iterable[str]) -> tuple[str, ...]:
    tokens = {str(entry).lower() for entry in entries if entry}
    return tuple(sorted(tokens))


def _normalise_sources(entries: Iterable[str]) -> tuple[str, ...]:
    values = {str(entry).strip().lower() for entry in entries if entry}
    return tuple(sorted(values))


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalise_optional_str_iterable(value: object) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes)):
        return frozenset({str(value).strip().lower()})
    try:
        iterator = iter(value)  # type: ignore[arg-type]
    except TypeError:
        return None
    items = {str(item).strip().lower() for item in iterator if item}
    return frozenset(items) if items else None


def _expand_host_variants(host: str | None) -> set[str]:
    full, registrable = _host_components(host)
    variants = {value for value in (full, registrable) if value}
    return variants


def _host_components(host: str | None) -> tuple[str | None, str | None]:
    if not host:
        return None, None
    candidate = str(host).strip().lower()
    if not candidate:
        return None, None
    if "//" in candidate:
        parsed = urlsplit(candidate)
        candidate = (parsed.hostname or "").strip(".")
    else:
        candidate = candidate.split("/", 1)[0].strip(".")
    if not candidate:
        return None, None
    registrable = _registrable_root(candidate)
    return candidate or None, registrable or candidate or None


def _registrable_root(host: str | None) -> str | None:
    if not host:
        return None
    lowered = host.strip(".").lower()
    if not lowered:
        return None
    parts = lowered.split(".")
    if len(parts) <= 2:
        return lowered
    suffix_two = ".".join(parts[-2:])
    suffix_three = ".".join(parts[-3:])
    if suffix_three in MULTI_LEVEL_SUFFIXES:
        return suffix_three
    return suffix_two


__all__ = [
    "NoisePolicy",
    "PolicyDecision",
    "load_noise_policy",
    "DEFAULT_POLICY_ROOT",
]
