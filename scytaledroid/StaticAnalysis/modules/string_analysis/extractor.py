"""String collection and normalization helpers."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import ipaddress
import logging
import math
import os
import re
import zlib
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from .allowlist import NoisePolicy
from .bucketing.classifier import BucketDecision, classify
from .constants import (
    AUTH_KEYWORDS,
    AWS_ACCESS_KEY_PATTERN,
    AWS_SECRET_KEY_PATTERN,
    BASE64_ALPHABET,
    BASE64_URLSAFE_ALPHABET,
    CLOUD_PATTERNS,
    CONTEXT_TOKENIZER,
    ENDPOINT_PATTERN,
    FEATURE_KEYWORDS,
    GOOGLE_API_KEY_PATTERN,
    GRAPHQL_HINT,
    GRPC_HINT,
    INTERNAL_HOST_SUFFIXES,
    JWT_PATTERN,
    REDIRECTOR_HOSTS,
    SCHEME_PREFIXES,
)
from .indexing import IndexedString, StringIndex, build_string_index
from .parsing.host_normalizer import NormalizedHost, normalize_host
from .parsing.punctuation import strip_wrap_punct
from .parsing.url_tokenizer import Candidate, extract_candidates
from .parsing.validators import is_private_ip
from .policy.evaluator import evaluate as evaluate_policy

logger = logging.getLogger(__name__)

_RESOURCE_PATH_PATTERN = re.compile(
    r"^(?:/)?(?:res|assets|lib|meta-inf|kotlin|androidx|org|com)/[^\s]+"
    r"\.(?:xml|json|png|jpg|jpeg|webp|svg|ttf|otf|so|dex|jar|arsc|proto|bin|dat|txt|css|js)$",
    re.IGNORECASE,
)
_FRAMEWORK_PREFIXES = (
    "androidx.",
    "kotlin.",
    "kotlinx.",
    "com.google.protobuf.",
    "com.google.android.gms.",
    "com.android.",
    "android.",
    "org.jetbrains.",
    "com.squareup.",
    "okhttp3.",
)
_LOW_ENTROPY_LENGTH = 256
_LOW_ENTROPY_THRESHOLD = 3.2


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ExploratoryIssue:
    """Heuristic issue raised from collection metrics."""

    slug: str
    message: str
    severity: str = "info"


@dataclass(frozen=True)
class NormalizedString:
    """Enriched representation of a collected string."""

    value: str
    value_hash: str
    value_preview: str
    source_path: str
    source_type: str
    byte_offset: int | None
    sha_short: str
    context: str
    context_words: tuple[str, ...]
    kind: str
    tags: tuple[str, ...]
    confidence: str
    apk_sha256: str | None
    split_id: str
    apk_offset_kind: str
    dex_id: int | None
    locale_qualifier: str | None
    decoded: str | None = None
    decoded_kind: str = "none"
    decoded_len: int | None = None
    decoded_hash: str | None = None
    host: str | None = None
    is_allowlisted: bool = False
    auth_proximity: int | None = None
    unknown_fingerprint: tuple[str, ...] | None = None
    obfuscation_hint: bool = False
    derived_from: tuple[str, ...] | None = None
    derived: bool = False
    policy_action: str | None = None
    policy_rule: str | None = None
    policy_reason: str | None = None
    policy_tag: str | None = None
    policy_note: str | None = None
    policy_severity: str | None = None


@dataclass(frozen=True)
class CollectionMetrics:
    """Summary metrics describing a string collection run."""

    strings_total: int
    strings_by_source: Mapping[str, int]
    strings_by_split: Mapping[str, int]
    strings_by_locale: Mapping[str, int]
    endpoints_nonlocal_http: int
    ws_cleartext: int
    ip_literals_public: int
    graphql_markers: int
    grpc_markers: int
    aws_pairs: int
    jwt_near_auth: int
    base64_candidates: int
    hex_candidates: int
    regex_skipped: int
    noise_counts: Mapping[str, int]
    decoded_blobs_total: int
    decoded_total_bytes: int
    decoded_yield_rate: float
    base64_decode_failures: int
    hex_decode_failures: int
    s3_buckets: int
    firebase_projects: int
    doc_noise_count: int
    doc_noise_ratio: float
    unknown_kind_count: int
    unknown_kind_ratio: float
    splits_present: tuple[str, ...]
    obfuscation_hint: bool
    auth_close_hits: int
    issue_flags: tuple[ExploratoryIssue, ...]
    effective_http: int
    effective_https: int
    placeholders_dropped: int
    doc_suppressed: int
    suppressed_doc_host: int
    suppressed_doc_cdn: int
    suppressed_doc_http: int
    downgraded_placeholder: int
    annotated_fragment: int
    ipv6_seen: int
    ws_seen: int
    wss_seen: int
    https_seen: int


@dataclass(frozen=True)
class CollectionSummary:
    """Normalized strings paired with per-run metrics."""

    strings: tuple[NormalizedString, ...]
    metrics: CollectionMetrics


@dataclass(frozen=True)
class DecodedBlob:
    text: str
    kind: str
    length: int
    sha1: str


_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


class _MetricsCounter:
    def __init__(self, *, include_https_for_risk: bool = False) -> None:
        self.strings_by_source: MutableMapping[str, int] = {}
        self.strings_by_split: MutableMapping[str, int] = {}
        self.strings_by_locale: MutableMapping[str, int] = {}
        self.endpoints_nonlocal_http = 0
        self.http_effective = 0
        self.ws_cleartext = 0
        self.ip_literals_public = 0
        self.graphql_markers = 0
        self.grpc_markers = 0
        self.aws_pairs = 0
        self.jwt_near_auth = 0
        self.base64_candidates = 0
        self.hex_candidates = 0
        self.regex_skipped = 0
        self.noise_counts: MutableMapping[str, int] = {}
        self.decoded_success = 0
        self.hex_decoded_success = 0
        self.decoded_total_bytes = 0
        self.s3_buckets = 0
        self.firebase_projects = 0
        self.doc_noise_count = 0
        self.unknown_kind_count = 0
        self.obfuscation_hits = 0
        self.auth_close_hits = 0
        self.include_https_for_risk = include_https_for_risk
        self.effective_https = 0
        self.placeholders_dropped = 0
        self.doc_suppressed = 0
        self.suppressed_doc_host = 0
        self.suppressed_doc_cdn = 0
        self.suppressed_doc_http = 0
        self.downgraded_placeholder = 0
        self.annotated_fragment = 0
        self.ipv6_seen = 0
        self.ws_seen = 0
        self.wss_seen = 0
        self.https_seen = 0

    def bump_source(self, source: str) -> None:
        self.strings_by_source[source] = self.strings_by_source.get(source, 0) + 1

    def bump_split(self, split_id: str) -> None:
        self.strings_by_split[split_id] = self.strings_by_split.get(split_id, 0) + 1

    def bump_locale(self, locale: str | None) -> None:
        if not locale:
            return
        self.strings_by_locale[locale] = self.strings_by_locale.get(locale, 0) + 1

    def note_obfuscation(self) -> None:
        self.obfuscation_hits += 1

    def to_metrics(self, total: int) -> CollectionMetrics:
        doc_ratio = self.doc_noise_count / total if total else 0.0
        yield_rate = self.decoded_success / self.base64_candidates if self.base64_candidates else 0.0
        failures = max(self.base64_candidates - self.decoded_success, 0)
        hex_failures = max(self.hex_candidates - self.hex_decoded_success, 0)
        unknown_ratio = self.unknown_kind_count / total if total else 0.0
        issues = _derive_issue_flags(
            total=total,
            cleartext=self.endpoints_nonlocal_http,
            ws_cleartext=self.ws_cleartext,
            aws_pairs=self.aws_pairs,
            jwt_hits=self.jwt_near_auth,
            doc_ratio=doc_ratio,
            unknown_ratio=unknown_ratio,
            yield_rate=yield_rate,
            candidates=self.base64_candidates,
            failures=failures,
            auth_close=self.auth_close_hits,
            obfuscation=self.obfuscation_hits,
            decoded=self.decoded_success,
            decoded_bytes=self.decoded_total_bytes,
        )
        return CollectionMetrics(
            strings_total=total,
            strings_by_source=dict(self.strings_by_source),
            strings_by_split=dict(self.strings_by_split),
            strings_by_locale=dict(self.strings_by_locale),
            endpoints_nonlocal_http=self.endpoints_nonlocal_http,
            ws_cleartext=self.ws_cleartext,
            ip_literals_public=self.ip_literals_public,
            graphql_markers=self.graphql_markers,
            grpc_markers=self.grpc_markers,
            aws_pairs=self.aws_pairs,
            jwt_near_auth=self.jwt_near_auth,
            base64_candidates=self.base64_candidates,
            hex_candidates=self.hex_candidates,
            regex_skipped=self.regex_skipped,
            noise_counts=dict(self.noise_counts),
            decoded_blobs_total=self.decoded_success,
            decoded_total_bytes=self.decoded_total_bytes,
            decoded_yield_rate=yield_rate,
            base64_decode_failures=max(self.base64_candidates - self.decoded_success, 0),
            hex_decode_failures=hex_failures,
            s3_buckets=self.s3_buckets,
            firebase_projects=self.firebase_projects,
            doc_noise_count=self.doc_noise_count,
            doc_noise_ratio=doc_ratio,
            unknown_kind_count=self.unknown_kind_count,
            unknown_kind_ratio=unknown_ratio,
            splits_present=tuple(sorted(self.strings_by_split)),
            obfuscation_hint=self.obfuscation_hits > 0,
            auth_close_hits=self.auth_close_hits,
            issue_flags=issues,
            effective_http=self.http_effective,
            effective_https=self.effective_https,
            placeholders_dropped=self.placeholders_dropped,
            doc_suppressed=self.doc_suppressed,
            suppressed_doc_host=self.suppressed_doc_host,
            suppressed_doc_cdn=self.suppressed_doc_cdn,
            suppressed_doc_http=self.suppressed_doc_http,
            downgraded_placeholder=self.downgraded_placeholder,
            annotated_fragment=self.annotated_fragment,
            ipv6_seen=self.ipv6_seen,
            ws_seen=self.ws_seen,
            wss_seen=self.wss_seen,
            https_seen=self.https_seen,
        )


def normalise_index(
    index: StringIndex,
    *,
    noise_policy: NoisePolicy | None = None,
    include_https_for_risk: bool | None = None,
    debug: bool | None = None,
) -> CollectionSummary:
    """Enrich *index* entries with tags and compute run metrics."""

    if include_https_for_risk is None:
        from scytaledroid.StaticAnalysis.engine.strings_runtime import get_config
        include_https_for_risk = bool(get_config().include_https_risk)
    if debug is None:
        from scytaledroid.StaticAnalysis.engine.strings_runtime import get_config
        debug = bool(get_config().debug)

    policy = noise_policy or NoisePolicy(frozenset(), frozenset())
    counter = _MetricsCounter(include_https_for_risk=include_https_for_risk)
    records: list[NormalizedString] = []

    base_entries = list(index.strings)
    reconstructed = _reconstruct_constant_hosts(base_entries)
    all_entries: list[IndexedString] = base_entries + list(reconstructed)

    for entry in all_entries:
        counter.bump_source(entry.origin_type or "unknown")
        counter.bump_split(entry.split_id or "base")
        counter.bump_locale(entry.locale_qualifier)
        normalized = _normalise_entry(
            entry,
            policy,
            counter,
            derived=entry.synthetic,
            debug=bool(debug),
        )
        records.append(normalized)

    metrics = counter.to_metrics(len(records))
    if debug:
        logger.debug(
            (
                "[strings] summary effective_http=%s effective_https=%s placeholders=%s "
                "doc_suppressed=%s doc_host=%s doc_cdn=%s doc_http=%s"
            ),
            metrics.effective_http,
            metrics.effective_https,
            metrics.placeholders_dropped,
            metrics.doc_suppressed,
            metrics.suppressed_doc_host,
            metrics.suppressed_doc_cdn,
            metrics.suppressed_doc_http,
        )
    return CollectionSummary(strings=tuple(records), metrics=metrics)


def _is_component_piece(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if lowered in SCHEME_PREFIXES:
        return True
    if lowered.startswith("/") or lowered.endswith("/"):
        return False
    if lowered.startswith(".") or lowered.endswith("."):
        lowered = lowered.strip(".")
        if not lowered:
            return False
    if len(lowered) > 64:
        return False
    return all(char.isalnum() or char in {"-", "."} for char in lowered)


def _is_candidate_string(value: str) -> bool:
    stripped = strip_wrap_punct(value.strip())
    if not stripped:
        return False
    for candidate in extract_candidates(stripped):
        normalized = normalize_host(candidate.host or candidate.raw)
        decision = classify(candidate, normalized)
        if decision.placeholder:
            continue
        if normalized.full_host or candidate.host:
            return True
    return False


def _reconstruct_constant_hosts(entries: Sequence[IndexedString]) -> tuple[IndexedString, ...]:
    """Reconstruct simple constant-folded host/URL sequences."""

    seen_values = {entry.value.strip() for entry in entries}
    grouped: MutableMapping[tuple[str, str | None], list[IndexedString]] = {}
    for entry in entries:
        if entry.origin_type != "dex" or entry.byte_offset is None:
            continue
        key = (entry.origin, entry.source_sha256)
        grouped.setdefault(key, []).append(entry)

    synthetic: list[IndexedString] = []
    for bucket in grouped.values():
        bucket.sort(key=lambda item: item.byte_offset or 0)
        for index, base in enumerate(bucket):
            if not _is_component_piece(base.value):
                continue
            for end_idx in range(index + 1, min(index + 4, len(bucket))):
                parts = bucket[index : end_idx + 1]
                last = parts[-1]
                if not _is_component_piece(last.value):
                    break
                valid = True
                for prev, current in zip(parts, parts[1:], strict=False):
                    if prev.byte_offset is None or current.byte_offset is None:
                        valid = False
                        break
                    if current.byte_offset - prev.byte_offset > 48:
                        valid = False
                        break
                if not valid:
                    break
                combined = "".join(piece.value for piece in parts)
                if len(combined) > 256:
                    break
                normalized = combined.strip()
                if not _is_candidate_string(normalized):
                    continue
                if normalized in seen_values:
                    continue
                derived_from = tuple(piece.sha256 for piece in parts)
                context = " + ".join(piece.value for piece in parts)
                synthetic_entry = parts[0].clone_with_value(
                    normalized,
                    byte_offset=parts[0].byte_offset,
                    context=context,
                    derived_from=derived_from,
                )
                synthetic.append(synthetic_entry)
                seen_values.add(normalized)
    return tuple(synthetic)


def _normalise_entry(
    entry: IndexedString,
    policy: NoisePolicy,
    counter: _MetricsCounter,
    *,
    derived: bool = False,
    debug: bool = False,
) -> NormalizedString:
    value = entry.value
    context = _context_for_entry(entry)
    context_words = _tokenize_context(context)
    tags: list[str] = []
    confidence = "low"
    host: str | None = None
    kind = "unknown"
    decoded_text: str | None = None
    decoded_kind = "none"
    decoded_len: int | None = None
    decoded_hash: str | None = None
    source_allowlisted = policy.is_documentary_source(entry.origin)
    is_allowlisted = source_allowlisted
    stripped = value.strip()
    auth_proximity = _auth_distance(value, context)
    obfuscation_hint = _looks_obfuscated(entry)
    if obfuscation_hint:
        counter.note_obfuscation()

    noise_tag = _detect_noise_tag(value, entry.origin, policy)
    if noise_tag:
        tags.append(noise_tag)
        is_allowlisted = True

    skip_regex = _should_skip_regex(value) or bool(noise_tag)
    if skip_regex:
        counter.regex_skipped += 1
    if noise_tag:
        counter.noise_counts[noise_tag] = counter.noise_counts.get(noise_tag, 0) + 1

    base64_candidate = False
    decoded_blob: DecodedBlob | None = None
    if _is_hex_candidate(stripped):
        counter.hex_candidates += 1
        decoded_blob = _decode_hex_strict(stripped)
        if decoded_blob:
            counter.decoded_success += 1
            counter.hex_decoded_success += 1
            counter.decoded_total_bytes += decoded_blob.length
            decoded_text = decoded_blob.text[:512]
            decoded_kind = decoded_blob.kind
            decoded_len = decoded_blob.length
            decoded_hash = decoded_blob.sha1
            tags.append("encoded")
            tags.append("hex-encoded")
        else:
            decoded_kind = "junk"
    if not decoded_blob and _is_base64_candidate(stripped):
        base64_candidate = True
        counter.base64_candidates += 1
        decoded_blob = _decode_base64_strict(stripped)
        if decoded_blob:
            counter.decoded_success += 1
            counter.decoded_total_bytes += decoded_blob.length
            decoded_text = decoded_blob.text[:512]
            decoded_kind = decoded_blob.kind
            decoded_len = decoded_blob.length
            decoded_hash = decoded_blob.sha1
            tags.append("encoded")
        else:
            decoded_kind = "junk"

    policy_action: str | None = None
    policy_rule: str | None = None
    policy_reason: str | None = None
    policy_tag: str | None = None
    policy_note: str | None = None
    policy_severity: str | None = None

    scheme_lower: str | None = None
    normalized_host = None
    bucket_decision = None

    stripped_for_candidates = strip_wrap_punct(value)
    selected_candidate: Candidate | None = None
    placeholder_candidate: tuple[Candidate, NormalizedHost, BucketDecision] | None = None
    if not skip_regex:
        for candidate in extract_candidates(stripped_for_candidates):
            normalized_candidate = normalize_host(candidate.host or candidate.raw)
            decision = classify(candidate, normalized_candidate)
            for tag in decision.tags:
                if tag not in tags:
                    tags.append(tag)
            if decision.placeholder:
                if "placeholder" not in tags:
                    tags.append("placeholder")
                counter.placeholders_dropped += 1
                if placeholder_candidate is None:
                    placeholder_candidate = (candidate, normalized_candidate, decision)
                continue
            host_candidate = (
                normalized_candidate.full_host or candidate.host or candidate.raw
            )
            if not host_candidate:
                continue
            if selected_candidate is None:
                selected_candidate = candidate
                normalized_host = normalized_candidate
                host = host_candidate
                scheme_lower = candidate.scheme.lower() if candidate.scheme else None
                bucket_decision = decision
                if candidate.scheme:
                    tags.extend(
                        _tags_for_url(candidate.raw, host=host_candidate, context=context)
                    )
                break

        if selected_candidate is None and placeholder_candidate is not None:
            candidate, normalized_candidate, decision = placeholder_candidate
            selected_candidate = candidate
            normalized_host = normalized_candidate
            host = (
                normalized_candidate.full_host or candidate.host or candidate.raw
            )
            scheme_lower = candidate.scheme.lower() if candidate.scheme else None
            bucket_decision = decision
            if candidate.scheme:
                tags.extend(
                    _tags_for_url(candidate.raw, host=host or candidate.host, context=context)
                )

    if selected_candidate:
        if selected_candidate.scheme:
            kind = "url"
            confidence = "high"
        elif normalized_host and normalized_host.is_ip:
            kind = "ip"
            confidence = "medium"
        else:
            kind = "host"
            confidence = _raise_confidence(confidence, "medium")
        is_allowlisted = is_allowlisted or policy.is_documentary_host(host)
        if bucket_decision and not bucket_decision.buckets and host:
            bucket_decision = BucketDecision(
                buckets=("endpoints",),
                tags=bucket_decision.tags,
                placeholder=bucket_decision.placeholder,
            )
        if scheme_lower == "https":
            counter.https_seen += 1
        elif scheme_lower == "ws":
            counter.ws_seen += 1
        elif scheme_lower == "wss":
            counter.wss_seen += 1
        if (
            normalized_host
            and normalized_host.is_ip
            and ":" in (normalized_host.full_host or "")
        ):
            counter.ipv6_seen += 1
        host_public = bool(
            normalized_host
            and (
                not normalized_host.is_ip
                or (host and not is_private_ip(host))
            )
        )
        if (
            not is_allowlisted
            and bucket_decision
            and host_public
            and not bucket_decision.placeholder
        ):
            if "http_cleartext" in bucket_decision.buckets:
                counter.endpoints_nonlocal_http += 1
                counter.http_effective += 1
            elif (
                selected_candidate.scheme
                and selected_candidate.scheme.lower() == "ws"
            ):
                counter.endpoints_nonlocal_http += 1
            elif (
                selected_candidate.scheme
                and selected_candidate.scheme.lower() == "https"
            ):
                counter.effective_https += 1
                if counter.include_https_for_risk:
                    counter.endpoints_nonlocal_http += 1
        if (
            not is_allowlisted
            and (not bucket_decision or not bucket_decision.placeholder)
            and "websocket" in tags
            and "cleartext" in tags
        ):
            counter.ws_cleartext += 1
        if (
            not is_allowlisted
            and normalized_host
            and normalized_host.is_ip
            and not is_private_ip(host)
        ):
            counter.ip_literals_public += 1
    else:
        host = None

    lowered = value.lower()

    if not skip_regex and GRAPHQL_HINT.search(value) and "graphql" not in tags:
        tags.append("graphql")
        if not is_allowlisted:
            counter.graphql_markers += 1
    if not skip_regex and GRPC_HINT.search(value) and "grpc" not in tags:
        tags.append("grpc")
        if not is_allowlisted:
            counter.grpc_markers += 1

    if not skip_regex and AWS_ACCESS_KEY_PATTERN.search(value) and AWS_SECRET_KEY_PATTERN.search(value):
        tags.extend(["aws-pair", "auth-adjacent"])
        confidence = "high"
        kind = "token"
        if not is_allowlisted:
            counter.aws_pairs += 1

    if not skip_regex and GOOGLE_API_KEY_PATTERN.search(value):
        tags.append("google-api-key")
        kind = "token"
        confidence = _raise_confidence(confidence, "medium")

    token_match = JWT_PATTERN.search(value) if not skip_regex else None
    if token_match and ("authorization" in lowered or "bearer" in lowered):
        tags.extend(["auth-token", "jwt-format"])
        if "bearer" in lowered:
            tags.append("bearer-context")
        kind = "token"
        confidence = "high"
        if not is_allowlisted:
            counter.jwt_near_auth += 1

    if not skip_regex:
        for pattern_name, pattern in CLOUD_PATTERNS.items():
            match = pattern.search(value)
            if not match:
                continue
            if "firebase" in pattern_name:
                tags.append("firebase")
                if not is_allowlisted:
                    counter.firebase_projects += 1
            else:
                tags.append("cloud-bucket")
                if not is_allowlisted:
                    counter.s3_buckets += 1
            break

    has_url_candidate = bool(selected_candidate and selected_candidate.scheme)
    if any(keyword in lowered for keyword in FEATURE_KEYWORDS) and has_url_candidate:
        tags.append("feature-flag")
        tags.append("remote-control")

    if "encoded" in tags and decoded_blob:
        extra_tags = _tags_from_decoded(decoded_blob.text)
        if extra_tags:
            tags.extend(extra_tags)
        if decoded_kind in {"url", "key", "token"}:
            confidence = _raise_confidence(confidence, "medium")

    tags = list(dict.fromkeys(tags))

    outcome = evaluate_policy(
        policy,
        bucket_decision,
        normalized_host,
        source_path=entry.origin,
        value=value,
        scheme=scheme_lower,
    )
    if outcome.is_actionable:
        policy_action = outcome.action
        policy_rule = outcome.rule
        policy_reason = outcome.reason
        policy_tag = outcome.tag
        policy_note = outcome.note
        policy_severity = outcome.severity
        if outcome.tag and outcome.tag not in tags:
            tags.append(outcome.tag)
        if outcome.action == "suppress":
            is_allowlisted = True
            reason_text = outcome.reason or ""
            if reason_text:
                if reason_text.startswith("policy_drift:doc_reference"):
                    counter.suppressed_doc_host += 1
                    counter.doc_suppressed += 1
                elif reason_text.startswith("policy_drift:doc_cdn"):
                    counter.suppressed_doc_cdn += 1
                    counter.doc_suppressed += 1
                elif reason_text.startswith("policy_drift:http_doc_cdn"):
                    counter.suppressed_doc_cdn += 1
                    counter.suppressed_doc_http += 1
                    counter.doc_suppressed += 1
                elif reason_text.startswith("policy_drift:http_in_metadata"):
                    counter.suppressed_doc_http += 1
                    counter.doc_suppressed += 1
                elif reason_text.startswith("policy_drift:templated_doc_asset"):
                    counter.doc_suppressed += 1
            else:
                counter.doc_suppressed += 1
        elif outcome.action == "downgrade" and outcome.tag == "dev_placeholder_host":
            counter.downgraded_placeholder += 1
        elif outcome.action == "annotate" and outcome.tag == "format_fragment_host":
            counter.annotated_fragment += 1
    if is_allowlisted:
        kind = "doc_namespace"
        counter.doc_noise_count += 1

    unknown_fingerprint: tuple[str, ...] | None = None
    if not tags and kind == "unknown" and base64_candidate and decoded_kind == "junk":
        tags.append("encoded")
    if kind == "unknown":
        counter.unknown_kind_count += 1
        unknown_fingerprint = _unknown_fingerprint(value)

    if auth_proximity is not None and auth_proximity <= 32:
        counter.auth_close_hits += 1

    tags_tuple = tuple(tags)

    if debug and selected_candidate:
        policy_descriptor = (
            f"{policy_action}:{policy_reason}" if policy_action else "none"
        )
        bucket_descriptor = (
            ",".join(bucket_decision.buckets) if bucket_decision else ""
        )
        logger.debug(
            "[strings] raw=%s stripped=%s host=%s etld1=%s buckets=%s policy=%s src=%s",
            value,
            stripped_for_candidates,
            host,
            normalized_host.etld_plus_one if normalized_host else None,
            bucket_descriptor,
            policy_descriptor,
            entry.origin,
        )

    return NormalizedString(
        value=value,
        value_hash=_value_hash(value),
        value_preview=_value_preview(value),
        source_path=entry.origin,
        source_type=entry.origin_type,
        byte_offset=entry.byte_offset,
        sha_short=entry.sha_short,
        context=context,
        context_words=context_words,
        kind=kind,
        tags=tags_tuple,
        confidence=confidence,
        apk_sha256=entry.apk_sha256,
        split_id=entry.split_id,
        apk_offset_kind=entry.apk_offset_kind,
        dex_id=entry.dex_id,
        locale_qualifier=entry.locale_qualifier,
        decoded=decoded_text,
        decoded_kind=decoded_kind,
        decoded_len=decoded_len,
        decoded_hash=decoded_hash,
        host=host,
        is_allowlisted=is_allowlisted,
        auth_proximity=auth_proximity,
        unknown_fingerprint=unknown_fingerprint,
        obfuscation_hint=obfuscation_hint,
        derived_from=entry.derived_from,
        derived=derived,
        policy_action=policy_action,
        policy_rule=policy_rule,
        policy_reason=policy_reason,
        policy_tag=policy_tag,
        policy_note=policy_note,
        policy_severity=policy_severity,
    )


def _context_for_entry(entry: IndexedString, *, limit: int = 160) -> str:
    if entry.context:
        return entry.context
    value = entry.value
    snippet = value[:limit]
    if len(value) > limit:
        snippet += "…"
    return snippet


def _tokenize_context(context: str) -> tuple[str, ...]:
    tokens = CONTEXT_TOKENIZER.findall(context.lower())
    return tuple(dict.fromkeys(tokens))


def _raise_confidence(current: str, new_level: str) -> str:
    if _CONFIDENCE_ORDER.get(new_level, 0) > _CONFIDENCE_ORDER.get(current, 0):
        return new_level
    return current


def _is_base64_candidate(value: str) -> bool:
    length = len(value)
    if length < 32 or length > 256 or length % 4:
        return False
    alphabet = BASE64_URLSAFE_ALPHABET if {"-", "_"} & set(value) else BASE64_ALPHABET
    if not all(char in alphabet for char in value):
        return False
    padding = len(value) - len(value.rstrip("="))
    return padding in {0, 1, 2}


_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")


def _is_hex_candidate(value: str) -> bool:
    length = len(value)
    if length < 32 or length > 512 or length % 2:
        return False
    if not _HEX_PATTERN.match(value):
        return False
    unique = len(set(value.lower()))
    return unique > 3


_MAX_DECODE_BYTES = 1024 * 1024


def _maybe_decompress(raw: bytes) -> bytes | None:
    if not raw:
        return None
    if raw.startswith(b"\x1f\x8b"):
        try:
            payload = gzip.decompress(raw)
        except OSError:
            return None
        return payload[:_MAX_DECODE_BYTES]
    if raw[:1] == b"\x78":
        try:
            payload = zlib.decompress(raw, max_length=_MAX_DECODE_BYTES)
        except zlib.error:
            return None
        return payload
    return None


def _decode_hex_strict(value: str) -> DecodedBlob | None:
    try:
        raw = binascii.unhexlify(value)
    except (binascii.Error, ValueError):
        return None
    payload = _maybe_decompress(raw) or raw
    return _decode_bytes(payload)


def _decode_base64_strict(value: str) -> DecodedBlob | None:
    try:
        if "-" in value or "_" in value:
            raw = base64.urlsafe_b64decode(value)
        else:
            raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    payload = _maybe_decompress(raw) or raw
    return _decode_bytes(payload)


def _decode_bytes(raw: bytes) -> DecodedBlob | None:
    if not raw:
        return None
    printable_ratio = sum(32 <= byte < 127 for byte in raw) / max(len(raw), 1)
    text = raw.decode("utf-8", errors="ignore")
    kind = _classify_decoded(text)
    if printable_ratio < 0.05 and kind == "junk":
        return None
    if kind == "junk":
        return None
    return DecodedBlob(text=text, kind=kind, length=len(raw), sha1=hashlib.sha1(raw).hexdigest())


_ISSUE_SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


def _derive_issue_flags(
    *,
    total: int,
    cleartext: int,
    ws_cleartext: int,
    aws_pairs: int,
    jwt_hits: int,
    doc_ratio: float,
    unknown_ratio: float,
    yield_rate: float,
    candidates: int,
    failures: int,
    auth_close: int,
    obfuscation: int,
    decoded: int,
    decoded_bytes: int,
) -> tuple[ExploratoryIssue, ...]:
    issues: list[ExploratoryIssue] = []
    if cleartext:
        issues.append(
            ExploratoryIssue(
                slug="cleartext_endpoints",
                message=f"Non-local cleartext endpoints observed ({cleartext})",
                severity="high",
            )
        )
    if ws_cleartext:
        issues.append(
            ExploratoryIssue(
                slug="cleartext_websocket",
                message=f"Cleartext WebSockets present ({ws_cleartext})",
                severity="high",
            )
        )
    if aws_pairs:
        issues.append(
            ExploratoryIssue(
                slug="aws_pairs",
                message=f"AWS key pairs detected ({aws_pairs})",
                severity="high",
            )
        )
    if jwt_hits:
        issues.append(
            ExploratoryIssue(
                slug="jwt_near_auth",
                message=f"JWT-like tokens near authorization context ({jwt_hits})",
                severity="medium",
            )
        )
    if candidates >= 5 and yield_rate < 0.05:
        issues.append(
            ExploratoryIssue(
                slug="base64_low_yield",
                message=f"Base64 decode yield low ({decoded}/{candidates})",
                severity="info",
            )
        )
    if failures >= 10:
        issues.append(
            ExploratoryIssue(
                slug="base64_failures",
                message=f"High base64 decode failure count ({failures})",
                severity="info",
            )
        )
    if doc_ratio > 0.5:
        issues.append(
            ExploratoryIssue(
                slug="doc_noise",
                message=f"Documentary noise high ({doc_ratio:.2f})",
                severity="info",
            )
        )
    if unknown_ratio > 0.15 and total:
        issues.append(
            ExploratoryIssue(
                slug="unknown_bucket",
                message=f"Unknown string bucket large ({unknown_ratio:.2f})",
                severity="medium",
            )
        )
    if auth_close:
        issues.append(
            ExploratoryIssue(
                slug="auth_proximity",
                message=f"{auth_close} strings appear within 32 bytes of auth keywords",
                severity="medium",
            )
        )
    if obfuscation:
        issues.append(
            ExploratoryIssue(
                slug="obfuscation",
                message="Obfuscation hints detected in dex strings",
                severity="info",
            )
        )
    if decoded_bytes > 0 and decoded_bytes / max(total, 1) > 1024:
        issues.append(
            ExploratoryIssue(
                slug="large_decoded_payloads",
                message="Large volume of decoded payload bytes recovered",
                severity="info",
            )
        )
    issues.sort(key=lambda issue: (_ISSUE_SEVERITY_ORDER.get(issue.severity, 99), issue.slug))
    return tuple(issues)


def _classify_decoded(text: str) -> str:
    if not text.strip():
        return "junk"
    if ENDPOINT_PATTERN.search(text):
        return "url"
    if AWS_ACCESS_KEY_PATTERN.search(text) and AWS_SECRET_KEY_PATTERN.search(text):
        return "key"
    if JWT_PATTERN.search(text):
        return "token"
    if GOOGLE_API_KEY_PATTERN.search(text):
        return "key"
    lowered = text.lower()
    if any(keyword in lowered for keyword in AUTH_KEYWORDS):
        return "text"
    return "junk"


def _tags_from_decoded(text: str) -> list[str]:
    tags: list[str] = []
    match = ENDPOINT_PATTERN.search(text)
    if match:
        url = match.group("url")
        parsed = urlsplit(url)
        tags.extend(_tags_for_url(url, host=parsed.hostname, context=text))
    if AWS_ACCESS_KEY_PATTERN.search(text) and AWS_SECRET_KEY_PATTERN.search(text):
        tags.extend(["aws-pair", "auth-adjacent"])
    if JWT_PATTERN.search(text):
        tags.append("jwt-format")
    if GOOGLE_API_KEY_PATTERN.search(text):
        tags.append("google-api-key")
    return list(dict.fromkeys(tags))


def _value_hash(value: str) -> str:
    return f"sha1:{hashlib.sha1(value.encode('utf-8')).hexdigest()}"


def _value_preview(value: str, *, limit: int = 120) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _auth_distance(value: str, context: str, *, threshold: int = 200) -> int | None:
    haystack = context or ""
    haystack_lower = haystack.lower()
    value_pos = haystack_lower.find(value.lower()) if value else -1
    if value_pos == -1:
        value_pos = len(haystack_lower) // 2
    positions: list[int] = []
    for keyword in ("authorization", "bearer", "hmac", "oauth", "x-api-key"):
        start = haystack_lower.find(keyword)
        while start != -1:
            positions.append(start)
            start = haystack_lower.find(keyword, start + 1)
    if not positions:
        return None
    distance = min(abs(pos - value_pos) for pos in positions)
    return distance if distance <= threshold else None


def _unknown_fingerprint(value: str, *, limit: int = 6) -> tuple[str, ...]:
    cleaned = value.replace("\n", " ").replace("\r", " ")
    bigrams: list[str] = []
    for idx in range(len(cleaned) - 1):
        gram = cleaned[idx : idx + 2]
        if any(char.isspace() for char in gram):
            continue
        bigrams.append(gram)
        if len(bigrams) >= limit:
            break
    return tuple(bigrams)


def _detect_noise_tag(value: str, source: str | None, policy: NoisePolicy) -> str | None:
    lowered = value.strip().lower()
    if not lowered:
        return None
    source_lower = source.replace("\\", "/").lower() if source else ""
    value_contains = policy.substring_groups.get("noise.value_contains")
    if value_contains and any(token in lowered for token in value_contains):
        return "noise_config"
    source_prefix = policy.source_prefix_groups.get("noise.source_prefix")
    if source_prefix and any(source_lower.startswith(prefix) for prefix in source_prefix):
        return "noise_config"
    source_exact = policy.source_exact_groups.get("noise.source_exact")
    if source_exact and source_lower in source_exact:
        return "noise_config"
    if any(lowered.startswith(prefix) for prefix in _FRAMEWORK_PREFIXES):
        return "noise_framework"
    if _RESOURCE_PATH_PATTERN.match(lowered):
        return "noise_resource_path"
    if source:
        normalised = source.replace("\\", "/").lower()
        if "/protobuf/" in normalised or "protobuf" in normalised:
            return "noise_protobuf"
    if "protobuf" in lowered and lowered.count(".") >= 2:
        return "noise_protobuf"
    return None


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: MutableMapping[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _should_skip_regex(value: str) -> bool:
    length = len(value)
    from scytaledroid.StaticAnalysis.engine.strings_runtime import get_config
    cfg = get_config()
    min_length = cfg.long_string_length
    min_entropy = cfg.low_entropy_threshold
    if length < min_length:
        return False
    return _shannon_entropy(value) < min_entropy


def _looks_obfuscated(entry: IndexedString) -> bool:
    if entry.origin_type != "dex":
        return False
    token = entry.value
    if not token or len(token) > 48:
        return False
    alpha = sum(ch.isalpha() for ch in token)
    if alpha < 4:
        return False
    vowels = sum(ch.lower() in {"a", "e", "i", "o", "u"} for ch in token)
    if vowels and vowels / alpha < 0.15:
        return True
    if token.startswith("L") and token.endswith(";"):
        parts = token[1:-1].split("/")
        if parts and all(len(part) <= 2 for part in parts[1:]):
            return True
    return False


def _tags_for_url(url: str, *, host: str | None, context: str) -> list[str]:
    tags = ["endpoint"]
    scheme = urlsplit(url).scheme.lower()
    if scheme in {"http", "ws"}:
        tags.append("cleartext")
    if scheme in {"ws", "wss"}:
        tags.append("websocket")
    if host and host.lower() in REDIRECTOR_HOSTS:
        tags.append("redirector")
    if host and _is_public_host(host):
        tags.append("prod-domain")
    if host and _is_ip_literal(host):
        tags.append("ip-literal")
    lowered_context = context.lower()
    if any(keyword in lowered_context for keyword in AUTH_KEYWORDS):
        tags.append("auth-adjacent")
    if GRAPHQL_HINT.search(url) or GRAPHQL_HINT.search(context):
        tags.append("graphql")
    if GRPC_HINT.search(context):
        tags.append("grpc")
    return tags


def _is_public_host(host: str) -> bool:
    if _is_ip_literal(host):
        return not _is_private_ip(host)
    lowered = host.lower().strip(".")
    if not lowered:
        return False
    if lowered == "localhost":
        return False
    if any(lowered.endswith(f".{suffix}") for suffix in INTERNAL_HOST_SUFFIXES):
        return False
    return True


def _is_ip_literal(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _maybe_ip_literal(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


__all__ = [
    "IndexedString",
    "StringIndex",
    "build_string_index",
    "NormalizedString",
    "ExploratoryIssue",
    "CollectionSummary",
    "CollectionMetrics",
    "normalise_index",
]
