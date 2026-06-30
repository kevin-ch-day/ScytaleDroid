"""Shared domain-context classification rules for dynamic evidence interpretation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


COMMON_TWO_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "co.jp",
    "com.br",
}


@dataclass(frozen=True)
class DomainReference:
    package_name_scope: str
    domain_pattern: str
    match_type: str
    owner_class: str
    role_class: str
    confidence: str
    classification_basis: str
    source_label: str = "repo_seed"
    source_url: str | None = None
    notes: str | None = None


def _norm_text(value: object) -> str:
    return str(value or "").strip()


def normalize_domain(value: Any) -> str:
    raw = _norm_text(value).lower()
    if not raw:
        return ""
    raw = raw.strip(" \t\r\n\"'()[]{}<>").rstrip(").,;")
    if raw.startswith("*."):
        raw = raw[2:]
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in raw:
        host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            raw = host
    if "." not in raw or ".." in raw:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(ch not in allowed for ch in raw):
        return ""
    return raw.strip(".-")


def root_domain(host: str) -> str:
    text = normalize_domain(host)
    if "." not in text:
        return text
    parts = [part for part in text.split(".") if part]
    if len(parts) < 2:
        return text
    tail = ".".join(parts[-2:])
    if len(parts) >= 3 and tail in COMMON_TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return tail


def suffix_match(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def default_domain_references() -> tuple[DomainReference, ...]:
    return (
        DomainReference("", "a1.api.bbc.com", "EXACT", "first_party", "publisher_api", "high", "curated_exact"),
        DomainReference(
            "", "bbc-global-app.api.bbc.com", "EXACT", "first_party", "publisher_api", "high", "curated_exact"
        ),
        DomainReference("", "idcta.api.bbc.com", "EXACT", "first_party", "identity_api", "high", "curated_exact"),
        DomainReference("", "ichef.bbci.co.uk", "EXACT", "first_party", "content_delivery", "high", "curated_exact"),
        DomainReference(
            "bbc.mobile.news.ww",
            "bbcx-internal.com",
            "SUFFIX",
            "first_party",
            "publisher_api",
            "medium",
            "curated_suffix",
            source_url="https://www.bbc.com",
            notes="Observed in current BBC News runtime traffic as a likely first-party live/app API endpoint.",
        ),
        DomainReference(
            "com.espn.score_center",
            "fan.api.espn.com",
            "EXACT",
            "first_party",
            "publisher_api",
            "high",
            "curated_exact",
            source_url="https://www.espn.com/",
        ),
        DomainReference(
            "com.espn.score_center",
            "pinpoint.espn.com",
            "EXACT",
            "first_party",
            "publisher_collection",
            "medium",
            "curated_exact",
            source_url="https://www.espn.com/",
        ),
        DomainReference(
            "com.espn.score_center",
            "espn.api.edge.bamgrid.com",
            "EXACT",
            "first_party",
            "publisher_api",
            "medium",
            "curated_exact",
            source_url="https://thewaltdisneycompany.com/news/espn-subscription-streaming-service-launches-april-12/",
        ),
        DomainReference(
            "com.espn.score_center",
            "espn.connections.edge.bamgrid.com",
            "EXACT",
            "first_party",
            "publisher_api",
            "medium",
            "curated_exact",
            source_url="https://thewaltdisneycompany.com/news/espn-subscription-streaming-service-launches-april-12/",
        ),
        DomainReference("", "www.cnn.com", "EXACT", "first_party", "publisher_content", "high", "curated_exact"),
        DomainReference(
            "", "collector.cdp.cnn.com", "EXACT", "first_party", "publisher_collection", "medium", "curated_exact"
        ),
        DomainReference("", "zion.api.cnn.io", "EXACT", "first_party", "publisher_api", "medium", "curated_exact"),
        DomainReference(
            "com.facebook.katana",
            "graph.facebook.com",
            "EXACT",
            "first_party",
            "social_graph_api",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "com.facebook.orca",
            "graph.facebook.com",
            "EXACT",
            "first_party",
            "social_graph_api",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "com.instagram.android",
            "graph.facebook.com",
            "EXACT",
            "first_party",
            "social_graph_api",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "com.whatsapp",
            "graph.whatsapp.com",
            "EXACT",
            "first_party",
            "messaging_platform_api",
            "high",
            "curated_exact",
            source_url="https://developers.facebook.com/docs/whatsapp/cloud-api/",
            notes="WhatsApp-owned graph endpoint observed in current-build runtime traffic; classified as first-party messaging platform API.",
        ),
        DomainReference(
            "com.whatsapp",
            "api.whatsapp.net",
            "EXACT",
            "first_party",
            "messaging_platform_api",
            "high",
            "curated_exact",
            source_url="https://developers.facebook.com/docs/whatsapp/cloud-api/",
            notes="WhatsApp API endpoint observed in current-build runtime traffic; classified as first-party messaging platform API.",
        ),
        DomainReference(
            "com.whatsapp",
            "v.whatsapp.net",
            "EXACT",
            "first_party",
            "realtime_call_transport",
            "medium",
            "curated_exact",
            source_url="https://www.whatsapp.com/security/",
            notes="Dominant runtime call/video transport hostname observed during connected WhatsApp calling activity.",
        ),
        DomainReference(
            "com.whatsapp",
            "g.whatsapp.net",
            "EXACT",
            "first_party",
            "realtime_messaging",
            "medium",
            "curated_exact",
            source_url="https://www.whatsapp.com/security/",
            notes="WhatsApp realtime transport/signaling hostname observed during current-build messaging traffic.",
        ),
        DomainReference(
            "com.whatsapp",
            "mmg.whatsapp.net",
            "EXACT",
            "first_party",
            "media_delivery",
            "medium",
            "curated_exact",
            source_url="https://developers.facebook.com/docs/whatsapp/cloud-api/reference/media",
            notes="WhatsApp media-delivery hostname observed in current-build runtime traffic.",
        ),
        DomainReference(
            "com.whatsapp",
            "scontent.whatsapp.net",
            "EXACT",
            "first_party",
            "content_delivery",
            "medium",
            "curated_exact",
            source_url="https://www.whatsapp.com/security/",
            notes="WhatsApp first-party content/media delivery hostname observed in current-build runtime traffic.",
        ),
        DomainReference(
            "com.whatsapp",
            "static.whatsapp.net",
            "EXACT",
            "first_party",
            "static_asset_delivery",
            "medium",
            "curated_exact",
            source_url="https://www.whatsapp.com/security/",
            notes="WhatsApp static asset delivery hostname observed in current-build runtime traffic.",
        ),
        DomainReference(
            "com.whatsapp",
            "cdn.whatsapp.net",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "medium",
            "curated_suffix",
            source_url="https://www.whatsapp.com/security/",
            notes="WhatsApp CDN hostname family used for current-build media/content delivery.",
        ),
        DomainReference("", "graph.facebook.com", "EXACT", "third_party", "social_graph_api", "medium", "curated_exact"),
        DomainReference(
            "com.facebook.katana",
            "b-graph.facebook.com",
            "EXACT",
            "first_party",
            "social_graph_api",
            "medium",
            "curated_exact",
            source_url="https://developers.facebook.com/docs/graph-api/",
            notes="Graph-service variant inferred from hostname pattern and official Graph API documentation.",
        ),
        DomainReference(
            "",
            "b-graph.facebook.com",
            "EXACT",
            "third_party",
            "social_graph_api",
            "medium",
            "curated_exact",
            source_url="https://developers.facebook.com/docs/graph-api/",
            notes="Graph-service variant inferred from hostname pattern and official Graph API documentation.",
        ),
        DomainReference(
            "com.facebook.katana",
            "connect.facebook.net",
            "EXACT",
            "first_party",
            "identity_api",
            "medium",
            "curated_exact",
            source_url="https://developers.facebook.com/docs/javascript/quickstart/",
            notes="Meta JavaScript SDK / Pixel bootstrap host.",
        ),
        DomainReference(
            "",
            "connect.facebook.net",
            "EXACT",
            "third_party",
            "identity_api",
            "medium",
            "curated_exact",
            source_url="https://developers.facebook.com/docs/javascript/quickstart/",
            notes="Meta JavaScript SDK / Pixel bootstrap host.",
        ),
        DomainReference(
            "com.facebook.katana",
            "edge-mqtt.facebook.com",
            "EXACT",
            "first_party",
            "realtime_messaging",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "com.facebook.orca",
            "edge-mqtt.facebook.com",
            "EXACT",
            "first_party",
            "realtime_messaging",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "com.instagram.android",
            "edge-mqtt.facebook.com",
            "EXACT",
            "first_party",
            "realtime_messaging",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "",
            "edge-mqtt.facebook.com",
            "EXACT",
            "third_party",
            "realtime_messaging",
            "medium",
            "curated_exact",
        ),
        DomainReference(
            "com.facebook.orca",
            "chat-e2ee-mini.facebook.com",
            "EXACT",
            "first_party",
            "messaging_e2ee",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "com.facebook.katana",
            "chat-e2ee-mini.facebook.com",
            "EXACT",
            "first_party",
            "messaging_e2ee",
            "medium",
            "curated_exact",
        ),
        DomainReference(
            "",
            "chat-e2ee-mini.facebook.com",
            "EXACT",
            "third_party",
            "messaging_e2ee",
            "medium",
            "curated_exact",
        ),
        DomainReference(
            "com.facebook.katana",
            "payments-graph.facebook.com",
            "EXACT",
            "first_party",
            "payments_api",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "com.instagram.android",
            "payments-graph.facebook.com",
            "EXACT",
            "first_party",
            "payments_api",
            "high",
            "curated_exact",
        ),
        DomainReference(
            "",
            "payments-graph.facebook.com",
            "EXACT",
            "third_party",
            "payments_api",
            "medium",
            "curated_exact",
        ),
        DomainReference("", "urbanairship.com", "SUFFIX", "third_party", "engagement_push", "high", "curated_suffix"),
        DomainReference("", "chartbeat.net", "SUFFIX", "third_party", "analytics_measurement", "high", "curated_suffix"),
        DomainReference(
            "", "scorecardresearch.com", "SUFFIX", "third_party", "audience_measurement", "high", "curated_suffix"
        ),
        DomainReference("", "piano.io", "SUFFIX", "third_party", "analytics_measurement", "medium", "curated_suffix"),
        DomainReference(
            "", "permutive.app", "SUFFIX", "third_party", "audience_personalization", "high", "curated_suffix"
        ),
        DomainReference(
            "",
            "permutive.com",
            "SUFFIX",
            "third_party",
            "audience_personalization",
            "high",
            "curated_suffix",
            source_url="https://permutive.com/",
        ),
        DomainReference(
            "",
            "rlcdn.com",
            "SUFFIX",
            "third_party",
            "identity_sync",
            "high",
            "curated_suffix",
            source_url="https://docs.liveramp.com/identity/en/implementing-liveramp-s-cookie-sync-tag.html",
        ),
        DomainReference(
            "",
            "dianomi.com",
            "SUFFIX",
            "third_party",
            "adtech_monetization",
            "high",
            "curated_suffix",
            source_url="https://www.dianomi.com/who-we-help/publishers/",
        ),
        DomainReference(
            "",
            "amazon-adsystem.com",
            "SUFFIX",
            "third_party",
            "adtech_monetization",
            "medium",
            "curated_suffix",
            source_url="https://advertising.amazon.com/",
        ),
        DomainReference("", "doubleclick.net", "SUFFIX", "third_party", "adtech_monetization", "high", "curated_suffix"),
        DomainReference(
            "",
            "fwmrm.net",
            "SUFFIX",
            "third_party",
            "adtech_video_monetization",
            "high",
            "curated_suffix",
            source_url="https://www.freewheel.com/",
        ),
        DomainReference(
            "", "googlesyndication.com", "SUFFIX", "third_party", "adtech_monetization", "high", "curated_suffix"
        ),
        DomainReference(
            "",
            "googletagservices.com",
            "SUFFIX",
            "third_party",
            "tag_delivery",
            "high",
            "curated_suffix",
            source_url="https://support.google.com/admanager/answer/181073?hl=en",
        ),
        DomainReference(
            "",
            "imasdk.googleapis.com",
            "EXACT",
            "third_party",
            "adtech_monetization",
            "medium",
            "curated_exact",
            source_url="https://developers.google.com/interactive-media-ads",
        ),
        DomainReference(
            "",
            "firebaselogging-pa.googleapis.com",
            "EXACT",
            "third_party",
            "google_api_platform",
            "medium",
            "curated_exact",
            source_url="https://firebase.google.com/docs/perf-mon/get-started-web",
        ),
        DomainReference(
            "",
            "firebaselogging.googleapis.com",
            "EXACT",
            "third_party",
            "google_api_platform",
            "medium",
            "curated_exact",
            source_url="https://firebase.google.com/docs/analytics",
            notes="Firebase logging endpoint classification inferred from hostname naming and official Firebase analytics platform documentation.",
        ),
        DomainReference(
            "",
            "firebaseremoteconfig.googleapis.com",
            "EXACT",
            "third_party",
            "google_api_platform",
            "medium",
            "curated_exact",
            source_url="https://firebase.google.com/docs/remote-config",
            notes="Firebase Remote Config endpoint classification inferred from hostname naming and official Firebase Remote Config documentation.",
        ),
        DomainReference(
            "",
            "time.google.com",
            "EXACT",
            "third_party",
            "google_infrastructure",
            "medium",
            "curated_exact",
            source_url="https://developers.google.com/time",
        ),
        DomainReference(
            "",
            "whoami.akamai.net",
            "EXACT",
            "third_party",
            "network_diagnostics",
            "medium",
            "curated_exact",
            source_url="https://www.akamai.com/blog/developers/introducing-new-whoami-tool-dns-resolver-information",
            notes="Akamai diagnostic hostname used for resolver and edge information; classify as infrastructure rather than app first-party traffic.",
        ),
        DomainReference(
            "",
            "gpp-decoder.dianomi.workers.dev",
            "EXACT",
            "third_party",
            "adtech_monetization",
            "medium",
            "curated_exact",
            source_url="https://www.dianomi.com/",
            notes="Dianomi-hosted worker endpoint classification inferred from observed CNN runtime traffic and the hostname's Dianomi-specific subdomain.",
        ),
        DomainReference(
            "", "googlevideo.com", "SUFFIX", "third_party", "embedded_media_delivery", "medium", "curated_suffix"
        ),
        DomainReference("", "gstatic.com", "SUFFIX", "third_party", "google_infrastructure", "medium", "curated_suffix"),
        DomainReference(
            "",
            "litix.io",
            "SUFFIX",
            "third_party",
            "video_analytics_measurement",
            "medium",
            "curated_suffix",
            source_url="https://www.mux.com/docs/core/content-security-policy",
        ),
        DomainReference(
            "", "appsflyersdk.com", "SUFFIX", "third_party", "attribution_measurement", "high", "curated_suffix"
        ),
        DomainReference(
            "", "optimizely.com", "SUFFIX", "third_party", "experimentation_personalization", "high", "curated_suffix"
        ),
        DomainReference("", "doubleverify.com", "SUFFIX", "third_party", "ad_verification", "high", "curated_suffix"),
        DomainReference(
            "",
            "adsafeprotected.com",
            "SUFFIX",
            "third_party",
            "ad_verification",
            "high",
            "curated_suffix",
            source_url="https://integralads.com/innovation/",
        ),
        DomainReference(
            "",
            "brightline.tv",
            "SUFFIX",
            "third_party",
            "interactive_ctv_advertising",
            "high",
            "curated_suffix",
            source_url="https://brightline.tv/",
        ),
        DomainReference("", "2mdn.net", "SUFFIX", "third_party", "ad_creative_delivery", "high", "curated_suffix"),
        DomainReference("", "demdex.net", "SUFFIX", "third_party", "audience_identity", "high", "curated_suffix"),
        DomainReference("", "adobedtm.com", "SUFFIX", "third_party", "tag_delivery", "high", "curated_suffix"),
        DomainReference("", "admaster.cc", "SUFFIX", "third_party", "ad_measurement", "medium", "curated_suffix"),
        DomainReference(
            "",
            "newrelic.com",
            "SUFFIX",
            "third_party",
            "analytics_measurement",
            "medium",
            "curated_suffix",
            source_url="https://docs.newrelic.com/docs/mobile-monitoring/new-relic-mobile/mobile-sdk/configure-settings/",
        ),
        DomainReference(
            "",
            "vtwenty.com",
            "SUFFIX",
            "third_party",
            "audience_measurement",
            "medium",
            "curated_suffix",
            source_url="https://www.netify.ai/resources/domains/vtwenty.com",
            notes="Secondary source for hostname ownership; aligns with Nielsen DCR measurement materials.",
        ),
        DomainReference(
            "",
            "adtrafficquality.google",
            "SUFFIX",
            "third_party",
            "ad_measurement",
            "medium",
            "curated_suffix",
            source_url="https://support.google.com/google-ads/answer/2616016?hl=en",
        ),
        DomainReference(
            "",
            "flashtalking.com",
            "SUFFIX",
            "third_party",
            "ad_creative_delivery",
            "high",
            "curated_suffix",
            source_url="https://www.flashtalking.com/primary-ad-serving",
        ),
        DomainReference(
            "", "the-ozone-project.com", "SUFFIX", "third_party", "adtech_monetization", "high", "curated_suffix"
        ),
        DomainReference(
            "",
            "oraclecloud.com",
            "SUFFIX",
            "third_party",
            "cloud_infrastructure",
            "medium",
            "curated_suffix",
            source_url="https://docs.cloud.oracle.com/",
        ),
        DomainReference(
            "bbc.mobile.news.ww", "bbc.com", "SUFFIX", "first_party", "first_party_misc", "medium", "package_root_hint"
        ),
        DomainReference(
            "bbc.mobile.news.ww",
            "bbc.co.uk",
            "SUFFIX",
            "first_party",
            "identity_api",
            "medium",
            "curated_suffix",
            source_url="https://www.bbc.com",
        ),
        DomainReference(
            "bbc.mobile.news.ww", "bbci.co.uk", "SUFFIX", "first_party", "first_party_misc", "medium", "package_root_hint"
        ),
        DomainReference(
            "com.cnn.mobile.android.phone", "cnn.com", "SUFFIX", "first_party", "first_party_misc", "medium", "package_root_hint"
        ),
        DomainReference(
            "com.cnn.mobile.android.phone", "cnn.io", "SUFFIX", "first_party", "first_party_misc", "medium", "package_root_hint"
        ),
        DomainReference(
            "com.cnn.mobile.android.phone",
            "ngtv.io",
            "SUFFIX",
            "first_party",
            "streaming_delivery",
            "low",
            "curated_suffix",
            source_url="https://www.max.com/",
        ),
        DomainReference(
            "com.cnn.mobile.android.phone",
            "discomax.com",
            "SUFFIX",
            "first_party",
            "streaming_platform_api",
            "medium",
            "curated_suffix",
            source_url="https://www.max.com/",
        ),
        DomainReference(
            "com.cnn.mobile.android.phone",
            "warnermediacdn.com",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "medium",
            "curated_suffix",
            source_url="https://www.max.com/",
        ),
        DomainReference(
            "com.cnn.mobile.android.phone",
            "adobe.com",
            "SUFFIX",
            "third_party",
            "identity_api",
            "medium",
            "curated_suffix",
            source_url="https://experienceleague.adobe.com/en/docs/pass/authentication/home",
        ),
        DomainReference(
            "com.cnn.mobile.android.phone",
            "turner.com",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "medium",
            "curated_suffix",
            source_url="https://www.cnn.com",
        ),
        DomainReference(
            "",
            "config.mapbox.com",
            "EXACT",
            "third_party",
            "sdk_configuration",
            "medium",
            "curated_exact",
            source_url="https://docs.mapbox.com/api/overview/",
        ),
        DomainReference(
            "",
            "cloudflare.com",
            "SUFFIX",
            "third_party",
            "static_asset_delivery",
            "medium",
            "curated_suffix",
            source_url="https://cdnjs.com/about",
        ),
        DomainReference(
            "",
            "ampproject.org",
            "SUFFIX",
            "third_party",
            "content_delivery",
            "medium",
            "curated_suffix",
            source_url="https://developers.google.com/amp/cache/overview",
        ),
        DomainReference(
            "",
            "smartadserver.com",
            "SUFFIX",
            "third_party",
            "identity_sync",
            "medium",
            "curated_suffix",
            source_url="https://equativ.com/",
        ),
        DomainReference(
            "com.espn.score_center",
            "espn.com",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://www.espn.com/",
        ),
        DomainReference(
            "com.espn.score_center",
            "bamgrid.com",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://thewaltdisneycompany.com/news/espn-subscription-streaming-service-launches-april-12/",
        ),
        DomainReference(
            "com.facebook.katana", "facebook.com", "SUFFIX", "first_party", "first_party_misc", "medium", "package_root_hint"
        ),
        DomainReference(
            "com.facebook.katana", "fbcdn.net", "SUFFIX", "first_party", "first_party_misc", "medium", "package_root_hint"
        ),
        DomainReference(
            "com.facebook.katana",
            "facebook.net",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://developers.facebook.com/",
        ),
        DomainReference(
            "com.facebook.orca",
            "facebook.net",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://developers.facebook.com/",
        ),
        DomainReference(
            "com.instagram.android",
            "facebook.net",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://developers.facebook.com/",
        ),
        DomainReference(
            "com.whatsapp",
            "whatsapp.com",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://www.whatsapp.com/security/",
        ),
        DomainReference(
            "com.whatsapp",
            "whatsapp.net",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://www.whatsapp.com/security/",
        ),
        DomainReference("", "facebook.com", "SUFFIX", "third_party", "social_graph_api", "medium", "curated_suffix"),
        DomainReference("", "facebook.net", "SUFFIX", "third_party", "social_graph_api", "medium", "curated_suffix"),
        DomainReference("", "fbcdn.net", "SUFFIX", "third_party", "content_delivery", "low", "curated_suffix"),
        DomainReference(
            "com.facebook.katana",
            "cdninstagram.com",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "medium",
            "curated_suffix",
            source_url="https://developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login/get-started",
            notes="Package-scoped first-party content mapping for Instagram CDN traffic observed inside the Facebook app.",
        ),
        DomainReference(
            "com.guardian",
            "ophan.theguardian.com",
            "EXACT",
            "first_party",
            "publisher_collection",
            "medium",
            "curated_exact",
            source_url="https://open-platform.theguardian.com/",
            notes="Guardian-owned Ophan telemetry endpoint observed during app runtime traffic.",
        ),
        DomainReference(
            "com.guardian",
            "theguardian.com",
            "SUFFIX",
            "first_party",
            "publisher_content",
            "high",
            "curated_suffix",
            source_url="https://open-platform.theguardian.com/",
        ),
        DomainReference(
            "com.guardian",
            "guardianapis.com",
            "SUFFIX",
            "first_party",
            "publisher_api",
            "high",
            "curated_suffix",
            source_url="https://open-platform.theguardian.com/",
        ),
        DomainReference(
            "com.guardian",
            "guim.co.uk",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "medium",
            "curated_suffix",
            source_url="https://www.theguardian.com/about",
        ),
        DomainReference(
            "com.guardian",
            "privacy-mgmt.com",
            "SUFFIX",
            "third_party",
            "consent_management",
            "high",
            "curated_suffix",
            source_url="https://developer.onetrust.com/onetrust/docs/introduction-to-cmp",
        ),
        DomainReference(
            "",
            "crashlytics.com",
            "SUFFIX",
            "third_party",
            "crash_reporting",
            "high",
            "curated_suffix",
            source_url="https://firebase.google.com/docs/crashlytics",
        ),
        DomainReference(
            "",
            "adjust.com",
            "SUFFIX",
            "third_party",
            "attribution_measurement",
            "high",
            "curated_suffix",
            source_url="https://dev.adjust.com/en/sdk/android/",
        ),
        DomainReference(
            "com.twitter.android",
            "probe.twitter.com",
            "EXACT",
            "first_party",
            "realtime_engagement",
            "medium",
            "curated_exact",
            source_url="https://www.netify.ai/resources/hostnames/probe.twitter.com",
            notes="Curated from observed X/Twitter runtime traffic and external hostname references indicating live-engagement/realtime probe behavior.",
        ),
        DomainReference(
            "com.twitter.android",
            "video-s.twimg.com",
            "EXACT",
            "first_party",
            "content_delivery",
            "high",
            "curated_exact",
            source_url="https://bugzilla.mozilla.org/show_bug.cgi?id=1977810",
            notes="Curated from observed X/Twitter runtime traffic and external webcompat evidence tying the hostname to Twitter/X video delivery.",
        ),
        DomainReference(
            "com.twitter.android",
            "twitter.com",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://developer.x.com/",
        ),
        DomainReference(
            "com.twitter.android",
            "twimg.com",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "medium",
            "package_root_hint",
            source_url="https://developer.x.com/",
        ),
        DomainReference(
            "com.twitter.android",
            "x.com",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
            source_url="https://developer.x.com/",
        ),
        DomainReference(
            "",
            "atdmt.com",
            "SUFFIX",
            "third_party",
            "adtech_monetization",
            "medium",
            "curated_suffix",
            source_url="https://learn.microsoft.com/en-us/xandr/bidders/creative-macro-check-service",
            notes="Microsoft/Xandr Atlas ad-serving and click-tracking infrastructure.",
        ),
        DomainReference(
            "com.zhiliaoapp.musically",
            "tiktokcdn-us.com",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "high",
            "package_root_hint",
        ),
        DomainReference(
            "com.zhiliaoapp.musically",
            "tiktokv.us",
            "SUFFIX",
            "first_party",
            "first_party_misc",
            "medium",
            "package_root_hint",
        ),
        DomainReference(
            "com.zhiliaoapp.musically",
            "ibyteimg.com",
            "SUFFIX",
            "first_party",
            "content_delivery",
            "medium",
            "package_root_hint",
        ),
    )


def classify_domain(
    domain: str,
    *,
    package_name: str,
    references: tuple[DomainReference, ...] | None = None,
) -> dict[str, str | bool]:
    domain_lc = normalize_domain(domain)
    root = root_domain(domain_lc)
    refs = references or default_domain_references()
    package_key = _norm_text(package_name).lower()

    exact_matches = [
        ref
        for ref in refs
        if ref.match_type.upper() == "EXACT"
        and normalize_domain(ref.domain_pattern) == domain_lc
        and (not ref.package_name_scope or ref.package_name_scope.lower() == package_key)
    ]
    exact_matches.sort(key=lambda ref: (0 if ref.package_name_scope else 1, len(ref.domain_pattern) * -1))
    if exact_matches:
        ref = exact_matches[0]
        return {
            "domain": domain_lc,
            "root_domain": root,
            "owner_class": ref.owner_class,
            "role_class": ref.role_class,
            "confidence": ref.confidence,
            "basis": ref.classification_basis,
            "match_type": ref.match_type.upper(),
            "package_name_scope": ref.package_name_scope,
            "first_party": ref.owner_class == "first_party",
        }

    suffix_refs = [
        ref
        for ref in refs
        if ref.match_type.upper() == "SUFFIX"
        and suffix_match(domain_lc, normalize_domain(ref.domain_pattern))
        and (not ref.package_name_scope or ref.package_name_scope.lower() == package_key)
    ]
    suffix_refs.sort(key=lambda ref: (0 if ref.package_name_scope else 1, len(ref.domain_pattern) * -1))
    if suffix_refs:
        ref = suffix_refs[0]
        role_class = ref.role_class
        if ref.classification_basis == "package_root_hint":
            if ".api." in domain_lc or domain_lc.startswith("api."):
                role_class = "publisher_api"
            elif "cdn" in domain_lc or "image" in domain_lc or "media" in domain_lc:
                role_class = "content_delivery"
        return {
            "domain": domain_lc,
            "root_domain": root,
            "owner_class": ref.owner_class,
            "role_class": role_class,
            "confidence": ref.confidence,
            "basis": ref.classification_basis,
            "match_type": ref.match_type.upper(),
            "package_name_scope": ref.package_name_scope,
            "first_party": ref.owner_class == "first_party",
        }

    return {
        "domain": domain_lc,
        "root_domain": root,
        "owner_class": "unknown",
        "role_class": "unknown",
        "confidence": "low",
        "basis": "unclassified",
        "match_type": "",
        "package_name_scope": "",
        "first_party": False,
    }


def default_domain_reference_seed_rows() -> list[dict[str, str | None]]:
    rows: list[dict[str, str | None]] = []
    for ref in default_domain_references():
        rows.append(
            {
                "package_name_scope": ref.package_name_scope,
                "domain_pattern": normalize_domain(ref.domain_pattern),
                "match_type": ref.match_type.upper(),
                "owner_class": ref.owner_class,
                "role_class": ref.role_class,
                "confidence": ref.confidence,
                "classification_basis": ref.classification_basis,
                "source_label": ref.source_label,
                "source_url": ref.source_url,
                "notes": ref.notes,
            }
        )
    return rows


__all__ = [
    "COMMON_TWO_PART_SUFFIXES",
    "DomainReference",
    "classify_domain",
    "default_domain_reference_seed_rows",
    "default_domain_references",
    "normalize_domain",
    "root_domain",
    "suffix_match",
]
