"""Enrichment helpers for post-run string payloads."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import replace
import re

from .constants import AUTH_KEYWORDS, DOCUMENTARY_ROOTS
from .hit_record import StringHit
from .verifiers import verification_status_for

_CLOUD_STORAGE_ROOTS = (
    "amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "firebaseio.com",
    "firebasedatabase.app",
    "firebasestorage.googleapis.com",
)
_CDN_ROOTS = (
    "cloudfront.net",
    "akamaihd.net",
    "fastly.net",
    "cdn.",
)
_PROVIDER_ROOTS: Mapping[str, tuple[str, ...]] = {
    "aws": ("amazonaws.com", "cloudfront.net"),
    "google": ("googleapis.com", "googleusercontent.com", "gstatic.com", "google.com"),
    "firebase": (
        "firebaseio.com",
        "firebasedatabase.app",
        "firebasestorage.googleapis.com",
        "googleapis.com",
    ),
    "stripe": ("stripe.com", "stripe.network"),
    "github": ("github.com", "githubusercontent.com"),
    "slack": ("slack.com", "slack-msgs.com"),
    "twilio": ("twilio.com",),
    "paypal": ("paypal.com", "paypalobjects.com"),
    "square": ("squareup.com", "squarecdn.com"),
}
_COMMON_PACKAGE_TOKENS = {
    "android",
    "app",
    "apps",
    "client",
    "com",
    "google",
    "mobile",
    "phone",
    "prod",
    "release",
    "www",
}


def summarize_xref_context(value: str | None, *, limit: int = 120) -> str | None:
    text = " ".join(str(value or "").split())
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def infer_api_context(
    *,
    bucket: str,
    value: str,
    context: str | None,
    provider: str | None,
    tag: str | None,
) -> str | None:
    joined = " ".join(
        part for part in (value, context or "", provider or "", tag or "") if part
    ).lower()
    if any(token in joined for token in ("secretkeyspec", "cipher.getinstance", "cipher.init", "keystore", "javax.crypto", "hmac", "aes")):
        return "crypto_material"
    if any(token in joined for token in ("authorization", "bearer", "oauth", "client_secret", "x-api-key", "token", "signin")):
        return "auth_flow"
    if any(token in joined for token in ("okhttp", "retrofit", "httpurlconnection", "httpsurlconnection", "websocket", "grpc")):
        return "network_client"
    if any(token in joined for token in ("webview", "javascriptinterface", "loadurl", "setmixedcontentmode")):
        return "webview_surface"
    if provider in {"aws", "google", "firebase", "azure", "stripe", "github", "twilio"}:
        return "provider_sdk"
    if bucket in {"endpoints", "http_cleartext"}:
        return "network_target"
    return None


def _package_tokens(package_name: str | None) -> set[str]:
    if not package_name:
        return set()
    return {
        token
        for token in re.split(r"[^a-z0-9]+", package_name.lower())
        if len(token) >= 4 and token not in _COMMON_PACKAGE_TOKENS
    }


def classify_ownership(
    *,
    root_domain: str | None,
    provider: str | None,
    bucket: str,
    scheme: str | None,
    package_name: str | None,
) -> str:
    root = str(root_domain or "").strip().lower()
    if bucket == "analytics_ids":
        return "analytics"
    if bucket == "uris" or scheme in {"content", "file"}:
        return "local_or_non_network"
    if not root:
        if provider in {"aws", "firebase", "google", "azure"} and bucket == "cloud_refs":
            return "cloud_storage"
        return "local_or_non_network"
    if root in DOCUMENTARY_ROOTS:
        return "documentary"
    if provider and provider.lower() in {"google_analytics", "gtag", "firebase", "admob", "adjust", "appsflyer", "segment", "mixpanel"}:
        return "analytics"
    if any(root.endswith(suffix) for suffix in _CLOUD_STORAGE_ROOTS):
        return "cloud_storage"
    if any(marker in root for marker in _CDN_ROOTS):
        return "cdn"
    package_tokens = _package_tokens(package_name)
    root_tokens = {token for token in re.split(r"[^a-z0-9]+", root) if len(token) >= 4}
    if package_tokens and package_tokens & root_tokens:
        return "first_party"
    return "unknown_third_party"


def initial_posture(
    *,
    bucket: str,
    risk_tag: str | None,
    ownership_class: str | None,
    confidence: str | None,
) -> str:
    if bucket == "high_entropy":
        return "exploratory"
    if bucket in {"api_keys", "http_cleartext"}:
        return "actionable"
    if bucket == "cloud_refs" and ownership_class == "cloud_storage":
        return "actionable"
    if risk_tag == "http_cleartext":
        return "actionable"
    if confidence == "high" and bucket == "endpoints":
        return "exploratory"
    return "exploratory"


def enrich_hit(
    hit: StringHit,
    *,
    context: str | None,
    package_name: str | None,
) -> StringHit:
    xref_context = summarize_xref_context(context)
    api_context = infer_api_context(
        bucket=hit.bucket,
        value=hit.value,
        context=xref_context,
        provider=hit.provider,
        tag=hit.tag,
    )
    ownership_class = classify_ownership(
        root_domain=hit.root_domain,
        provider=hit.provider,
        bucket=hit.bucket,
        scheme=hit.scheme,
        package_name=package_name,
    )
    posture = initial_posture(
        bucket=hit.bucket,
        risk_tag=hit.risk_tag,
        ownership_class=ownership_class,
        confidence=hit.confidence,
    )
    return replace(
        hit,
        xref_context=xref_context,
        api_context=api_context,
        ownership_class=ownership_class,
        posture=posture,
        verification_status=verification_status_for(provider=hit.provider, bucket=hit.bucket),
        dynamic_corroboration="unknown",
    )


def _provider_for_root(root_domain: str | None) -> str | None:
    root = str(root_domain or "").strip().lower()
    if not root:
        return None
    for provider, suffixes in _PROVIDER_ROOTS.items():
        if any(root.endswith(suffix) for suffix in suffixes):
            return provider
    return None


def apply_pair_enrichment(
    sample_hits: Mapping[str, Sequence[StringHit]],
) -> tuple[dict[str, list[StringHit]], list[dict[str, object]]]:
    bucket_hits: dict[str, list[StringHit]] = {
        bucket: [hit for hit in hits]
        for bucket, hits in sample_hits.items()
    }
    pair_matches: list[dict[str, object]] = []

    endpoints = list(bucket_hits.get("endpoints", ())) + list(bucket_hits.get("http_cleartext", ()))
    api_hits = list(bucket_hits.get("api_keys", ()))
    provider_roots: MutableMapping[str, set[str]] = defaultdict(set)
    for hit in endpoints:
        provider = _provider_for_root(hit.root_domain)
        if provider and hit.root_domain:
            provider_roots[provider].add(hit.root_domain)

    pair_index: MutableMapping[str, set[tuple[str, str, str | None]]] = defaultdict(set)
    for bucket_name, hits in bucket_hits.items():
        for idx, hit in enumerate(hits):
            pair_group = None
            provider = (hit.provider or "").lower()
            if provider and provider in provider_roots:
                pair_group = f"{provider}:token_endpoint_family"
            elif provider == "aws" and hit.tag == "aws_secret":
                pair_group = "aws:secret_candidate"
            elif hit.tag == "jwt" and endpoints:
                pair_group = "generic:auth_material_network_target"
            if pair_group:
                hits[idx] = replace(
                    hit,
                    pair_group=pair_group,
                    posture="actionable",
                )
                pair_index[pair_group].add((bucket_name, hit.value, hit.src))

    api_tags = {str(hit.tag or "").lower() for hit in api_hits}
    if "aws_access_key" in api_tags and "aws_secret" in api_tags:
        pair_group = "aws:access_secret_pair"
        pair_matches.append(
            {
                "pair_group": pair_group,
                "pair_type": "credential_pair",
                "provider": "aws",
                "matched_endpoint_roots": sorted(provider_roots.get("aws", set())),
                "hit_count": sum(1 for hit in api_hits if (hit.provider or "").lower() == "aws"),
            }
        )
        for bucket_name, hits in bucket_hits.items():
            for idx, hit in enumerate(hits):
                if (hit.provider or "").lower() == "aws":
                    hits[idx] = replace(hit, pair_group=pair_group, posture="actionable")
                    pair_index[pair_group].add((bucket_name, hit.value, hit.src))

    for provider, roots in sorted(provider_roots.items()):
        token_count = sum(1 for hit in api_hits if (hit.provider or "").lower() == provider)
        if token_count <= 0:
            continue
        pair_group = f"{provider}:token_endpoint_family"
        pair_matches.append(
            {
                "pair_group": pair_group,
                "pair_type": "provider_endpoint_family",
                "provider": provider,
                "matched_endpoint_roots": sorted(roots),
                "hit_count": token_count,
            }
        )
        pair_index[pair_group].update(
            ("api_keys", hit.value, hit.src)
            for hit in api_hits
            if (hit.provider or "").lower() == provider
        )

    if endpoints and any(
        (hit.api_context == "auth_flow") or str(hit.tag or "").lower() == "jwt"
        for hit in api_hits
    ):
        roots = sorted(
            {
                str(hit.root_domain or "").strip()
                for hit in endpoints
                if str(hit.root_domain or "").strip()
            }
        )
        pair_matches.append(
            {
                "pair_group": "generic:auth_material_network_target",
                "pair_type": "auth_material_network_target",
                "provider": None,
                "matched_endpoint_roots": roots,
                "hit_count": len(api_hits),
            }
        )

    for bucket_name, hits in bucket_hits.items():
        for idx, hit in enumerate(hits):
            if hit.pair_group or hit.posture == "actionable":
                continue
            if hit.bucket == "endpoints":
                provider = _provider_for_root(hit.root_domain)
                if provider and provider in provider_roots and any(
                    entry.get("pair_group") == f"{provider}:token_endpoint_family"
                    for entry in pair_matches
                ):
                    hits[idx] = replace(hit, pair_group=f"{provider}:token_endpoint_family", posture="actionable")

    deduped_pairs: list[dict[str, object]] = []
    seen_pairs: set[tuple[object, ...]] = set()
    for row in pair_matches:
        key = (
            row.get("pair_group"),
            row.get("pair_type"),
            row.get("provider"),
            tuple(row.get("matched_endpoint_roots") or ()),
        )
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        deduped_pairs.append(row)
    return bucket_hits, deduped_pairs


def posture_summary_rows(
    sample_hits: Mapping[str, Sequence[StringHit]],
    *,
    posture: str,
    limit: int = 12,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for bucket, hits in sample_hits.items():
        for hit in hits:
            if hit.posture != posture:
                continue
            rows.append(
                {
                    "bucket": bucket,
                    "value_masked": hit.masked or hit.value,
                    "src": hit.src,
                    "provider": hit.provider,
                    "root_domain": hit.root_domain,
                    "ownership_class": hit.ownership_class,
                    "api_context": hit.api_context,
                    "pair_group": hit.pair_group,
                    "verification_status": hit.verification_status,
                    "dynamic_corroboration": hit.dynamic_corroboration,
                }
            )
    rows.sort(
        key=lambda item: (
            str(item.get("bucket") or ""),
            str(item.get("provider") or ""),
            str(item.get("root_domain") or ""),
            str(item.get("src") or ""),
        )
    )
    return rows[:limit]


__all__ = [
    "apply_pair_enrichment",
    "classify_ownership",
    "enrich_hit",
    "infer_api_context",
    "initial_posture",
    "posture_summary_rows",
    "summarize_xref_context",
]
