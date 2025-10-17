"""String collection and normalization helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, MutableMapping, Sequence
from urllib.parse import urlsplit

from .allowlist import NoisePolicy
from .indexing import IndexedString, StringIndex, build_string_index

_URL_PATTERN = re.compile(r"(?P<url>(?:https?|wss?)://[^\s\"'<>]+)")
_HOST_PATTERN = re.compile(r"^(?=.{4,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_JWT_PATTERN = re.compile(r"([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")
_AWS_ACCESS_KEY = re.compile(r"A(?:KI|SI)A[0-9A-Z]{16}")
_AWS_SECRET_KEY = re.compile(r"(?<![A-Z0-9])[A-Za-z0-9/+=]{40,64}(?![A-Za-z0-9/+=])")
_GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
_SCHEME_PARTS = {"http://", "https://", "ws://", "wss://"}
_HOST_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+(?:\.|$)")
_BASE64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_BASE64_URLSAFE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
_GRAPHQL_HINT = re.compile(r"(?:/graphql|\"query\"\s*:\s*\")", re.IGNORECASE)
_GRPC_HINT = re.compile(r"\":authority\"|\":path\"", re.IGNORECASE)
_FEATURE_KEYWORDS = ("feature", "flag", "toggle", "remote_config")
_AUTH_KEYWORDS = {"auth", "oauth", "token", "bearer", "secret", "hmac"}
_REDIRECTOR_HOSTS = {"t.co", "bit.ly", "goo.gl", "tinyurl.com", "lnkd.in"}
_CONTEXT_TOKENIZER = re.compile(r"[A-Za-z0-9_]+")

_INTERNAL_SUFFIXES = {"lan", "local", "corp", "internal"}

_CLOUD_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "aws_s3_host": re.compile(r"(?P<bucket>[a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
    "aws_s3_uri": re.compile(r"s3://(?P<bucket>[a-z0-9._-]+)/?"),
    "gcs_host": re.compile(r"storage.googleapis.com/(?P<bucket>[a-z0-9._-]+)/?"),
    "gcs_uri": re.compile(r"gs://(?P<bucket>[a-z0-9._-]+)/?"),
    "firebase_project": re.compile(r"(?P<project>[a-z0-9-]+)\.firebase(?:io|app)\.com"),
    "firebase_storage": re.compile(r"firebasestorage.googleapis.com/v0/b/(?P<bucket>[a-z0-9._-]+)/?"),
}


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
    decoded_blobs_total: int
    decoded_total_bytes: int
    decoded_yield_rate: float
    base64_decode_failures: int
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
    def __init__(self) -> None:
        self.strings_by_source: MutableMapping[str, int] = {}
        self.strings_by_split: MutableMapping[str, int] = {}
        self.strings_by_locale: MutableMapping[str, int] = {}
        self.endpoints_nonlocal_http = 0
        self.ws_cleartext = 0
        self.ip_literals_public = 0
        self.graphql_markers = 0
        self.grpc_markers = 0
        self.aws_pairs = 0
        self.jwt_near_auth = 0
        self.base64_candidates = 0
        self.decoded_success = 0
        self.decoded_total_bytes = 0
        self.s3_buckets = 0
        self.firebase_projects = 0
        self.doc_noise_count = 0
        self.unknown_kind_count = 0
        self.obfuscation_hits = 0
        self.auth_close_hits = 0

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
            decoded_blobs_total=self.decoded_success,
            decoded_total_bytes=self.decoded_total_bytes,
            decoded_yield_rate=yield_rate,
            base64_decode_failures=max(self.base64_candidates - self.decoded_success, 0),
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
        )


def normalise_index(index: StringIndex, *, noise_policy: NoisePolicy | None = None) -> CollectionSummary:
    """Enrich *index* entries with tags and compute run metrics."""

    policy = noise_policy or NoisePolicy(frozenset(), frozenset())
    counter = _MetricsCounter()
    records: list[NormalizedString] = []

    base_entries = list(index.strings)
    reconstructed = _reconstruct_constant_hosts(base_entries)
    all_entries: list[IndexedString] = base_entries + list(reconstructed)

    for entry in all_entries:
        counter.bump_source(entry.origin_type or "unknown")
        counter.bump_split(entry.split_id or "base")
        counter.bump_locale(entry.locale_qualifier)
        normalized = _normalise_entry(entry, policy, counter, derived=entry.synthetic)
        records.append(normalized)

    metrics = counter.to_metrics(len(records))
    return CollectionSummary(strings=tuple(records), metrics=metrics)


def _is_component_piece(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if lowered in _SCHEME_PARTS:
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
    stripped = value.strip()
    if not stripped:
        return False
    if _URL_PATTERN.match(stripped):
        return True
    return bool(_HOST_PATTERN.match(stripped.lower()))


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
                for prev, current in zip(parts, parts[1:]):
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

    base64_candidate = False
    decoded_blob: DecodedBlob | None = None
    if _is_base64_candidate(stripped):
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

    url_match = _URL_PATTERN.search(value)
    if url_match:
        url = url_match.group("url")
        parsed = urlsplit(url)
        host = parsed.hostname
        host_allowlisted = policy.is_documentary_host(host)
        is_allowlisted = is_allowlisted or host_allowlisted
        tags.extend(_tags_for_url(url, host=host, context=context))
        kind = "url"
        confidence = "high"
        if not is_allowlisted:
            if host and _is_public_host(host) and parsed.scheme.lower() in {"http", "ws"}:
                counter.endpoints_nonlocal_http += 1
            if "websocket" in tags and "cleartext" in tags:
                counter.ws_cleartext += 1
            if "ip-literal" in tags and host and not _is_private_ip(host):
                counter.ip_literals_public += 1
            if "graphql" in tags:
                counter.graphql_markers += 1
            if "grpc" in tags:
                counter.grpc_markers += 1
    elif _HOST_PATTERN.match(stripped):
        host = stripped.lower()
        kind = "host"
        confidence = "medium"
        if _is_public_host(host):
            tags.append("prod-domain")
    else:
        maybe_ip = _maybe_ip_literal(stripped)
        if maybe_ip:
            host = maybe_ip
            kind = "ip"
            confidence = "medium"
            if not _is_private_ip(maybe_ip):
                tags.append("ip-literal")
                counter.ip_literals_public += 1

    lowered = value.lower()

    if _GRAPHQL_HINT.search(value) and "graphql" not in tags:
        tags.append("graphql")
        if not is_allowlisted:
            counter.graphql_markers += 1
    if _GRPC_HINT.search(value) and "grpc" not in tags:
        tags.append("grpc")
        if not is_allowlisted:
            counter.grpc_markers += 1

    if _AWS_ACCESS_KEY.search(value) and _AWS_SECRET_KEY.search(value):
        tags.extend(["aws-pair", "auth-adjacent"])
        confidence = "high"
        kind = "token"
        if not is_allowlisted:
            counter.aws_pairs += 1

    if _GOOGLE_API_KEY.search(value):
        tags.append("google-api-key")
        kind = "token"
        confidence = _raise_confidence(confidence, "medium")

    token_match = _JWT_PATTERN.search(value)
    if token_match and ("authorization" in lowered or "bearer" in lowered):
        tags.extend(["auth-token", "jwt-format"])
        if "bearer" in lowered:
            tags.append("bearer-context")
        kind = "token"
        confidence = "high"
        if not is_allowlisted:
            counter.jwt_near_auth += 1

    for pattern_name, pattern in _CLOUD_PATTERNS.items():
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

    if any(keyword in lowered for keyword in _FEATURE_KEYWORDS) and url_match:
        tags.append("feature-flag")
        tags.append("remote-control")

    if "encoded" in tags and decoded_blob:
        extra_tags = _tags_from_decoded(decoded_blob.text)
        if extra_tags:
            tags.extend(extra_tags)
        if decoded_kind in {"url", "key", "token"}:
            confidence = _raise_confidence(confidence, "medium")

    tags = list(dict.fromkeys(tags))

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
    tokens = _CONTEXT_TOKENIZER.findall(context.lower())
    return tuple(dict.fromkeys(tokens))


def _raise_confidence(current: str, new_level: str) -> str:
    if _CONFIDENCE_ORDER.get(new_level, 0) > _CONFIDENCE_ORDER.get(current, 0):
        return new_level
    return current


def _is_base64_candidate(value: str) -> bool:
    length = len(value)
    if length < 32 or length > 256 or length % 4:
        return False
    alphabet = _BASE64_URLSAFE if {"-", "_"} & set(value) else _BASE64_ALPHABET
    if not all(char in alphabet for char in value):
        return False
    padding = len(value) - len(value.rstrip("="))
    return padding in {0, 1, 2}


def _decode_base64_strict(value: str) -> DecodedBlob | None:
    try:
        if "-" in value or "_" in value:
            raw = base64.urlsafe_b64decode(value)
        else:
            raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
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
    if _URL_PATTERN.search(text):
        return "url"
    if _AWS_ACCESS_KEY.search(text) and _AWS_SECRET_KEY.search(text):
        return "key"
    if _JWT_PATTERN.search(text):
        return "token"
    if _GOOGLE_API_KEY.search(text):
        return "key"
    lowered = text.lower()
    if any(keyword in lowered for keyword in _AUTH_KEYWORDS):
        return "text"
    return "junk"


def _tags_from_decoded(text: str) -> list[str]:
    tags: list[str] = []
    match = _URL_PATTERN.search(text)
    if match:
        url = match.group("url")
        parsed = urlsplit(url)
        tags.extend(_tags_for_url(url, host=parsed.hostname, context=text))
    if _AWS_ACCESS_KEY.search(text) and _AWS_SECRET_KEY.search(text):
        tags.extend(["aws-pair", "auth-adjacent"])
    if _JWT_PATTERN.search(text):
        tags.append("jwt-format")
    if _GOOGLE_API_KEY.search(text):
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
    if host and host.lower() in _REDIRECTOR_HOSTS:
        tags.append("redirector")
    if host and _is_public_host(host):
        tags.append("prod-domain")
    if host and _is_ip_literal(host):
        tags.append("ip-literal")
    lowered_context = context.lower()
    if any(keyword in lowered_context for keyword in _AUTH_KEYWORDS):
        tags.append("auth-adjacent")
    if _GRAPHQL_HINT.search(url) or _GRAPHQL_HINT.search(context):
        tags.append("graphql")
    if _GRPC_HINT.search(context):
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
    if any(lowered.endswith(f".{suffix}") for suffix in _INTERNAL_SUFFIXES):
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
