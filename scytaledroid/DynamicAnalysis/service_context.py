"""Shared service/provider context rules for dynamic network interpretation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scytaledroid.DynamicAnalysis.domain_context import normalize_domain, root_domain, suffix_match


@dataclass(frozen=True)
class ServiceCatalogEntry:
    service_key: str
    display_name: str
    owner_name: str
    owner_class: str
    service_category: str
    primary_use_case: str | None
    documentation_url: str | None = None
    privacy_policy_url: str | None = None
    source_label: str = "repo_seed"
    source_url: str | None = None
    confidence: str = "medium"
    notes: str | None = None


@dataclass(frozen=True)
class ServiceDomainMapEntry:
    service_key: str
    domain_pattern: str
    match_type: str
    package_name_scope: str = ""
    role_class: str | None = None
    source_label: str = "repo_seed"
    source_url: str | None = None
    confidence: str = "medium"
    notes: str | None = None


def _norm_text(value: object) -> str:
    return str(value or "").strip()


def default_service_catalog_entries() -> tuple[ServiceCatalogEntry, ...]:
    return (
        ServiceCatalogEntry(
            service_key="bbc_first_party",
            display_name="BBC First-Party Services",
            owner_name="BBC",
            owner_class="first_party",
            service_category="publisher",
            primary_use_case="news_content_and_api",
            source_url="https://www.bbc.com",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="cnn_first_party",
            display_name="CNN First-Party Services",
            owner_name="CNN",
            owner_class="first_party",
            service_category="publisher",
            primary_use_case="news_content_and_api",
            source_url="https://www.cnn.com",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="espn_first_party",
            display_name="ESPN First-Party Services",
            owner_name="ESPN / Disney",
            owner_class="first_party",
            service_category="publisher",
            primary_use_case="sports_content_and_api",
            source_url="https://www.espn.com/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="urbanairship",
            display_name="Airship",
            owner_name="Airship",
            owner_class="third_party",
            service_category="engagement",
            primary_use_case="push_and_customer_engagement",
            documentation_url="https://www.airship.com/",
            privacy_policy_url="https://www.airship.com/legal/privacy/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="google_ads",
            display_name="Google Ads / DoubleClick",
            owner_name="Google",
            owner_class="third_party",
            service_category="adtech",
            primary_use_case="advertising_and_monetization",
            documentation_url="https://support.google.com/admanager/",
            privacy_policy_url="https://policies.google.com/privacy",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="google_platform",
            display_name="Google Platform Infrastructure",
            owner_name="Google",
            owner_class="third_party",
            service_category="platform_infrastructure",
            primary_use_case="shared_platform_delivery",
            documentation_url="https://developers.google.com/",
            privacy_policy_url="https://policies.google.com/privacy",
            confidence="medium",
        ),
        ServiceCatalogEntry(
            service_key="chartbeat",
            display_name="Chartbeat",
            owner_name="Chartbeat",
            owner_class="third_party",
            service_category="analytics",
            primary_use_case="audience_measurement",
            documentation_url="https://chartbeat.com/",
            privacy_policy_url="https://chartbeat.com/privacy/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="doubleverify",
            display_name="DoubleVerify",
            owner_name="DoubleVerify",
            owner_class="third_party",
            service_category="ad_verification",
            primary_use_case="media_quality_and_ad_verification",
            documentation_url="https://doubleverify.com/company/about",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="dianomi",
            display_name="Dianomi",
            owner_name="Dianomi",
            owner_class="third_party",
            service_category="adtech",
            primary_use_case="native_advertising_and_publisher_monetization",
            documentation_url="https://www.dianomi.com/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="permutive",
            display_name="Permutive",
            owner_name="Permutive",
            owner_class="third_party",
            service_category="audience_personalization",
            primary_use_case="publisher_audience_activation",
            documentation_url="https://permutive.com/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="appsflyer",
            display_name="AppsFlyer",
            owner_name="AppsFlyer",
            owner_class="third_party",
            service_category="attribution",
            primary_use_case="install_attribution_and_engagement_measurement",
            documentation_url="https://www.appsflyer.com/",
            privacy_policy_url="https://www.appsflyer.com/legal/services-privacy-policy/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="liveramp",
            display_name="LiveRamp",
            owner_name="LiveRamp",
            owner_class="third_party",
            service_category="identity_and_adtech",
            primary_use_case="identity_resolution_and_cookie_sync",
            documentation_url="https://docs.liveramp.com/identity/en/implementing-liveramp-s-cookie-sync-tag.html",
            privacy_policy_url="https://liveramp.com/privacy/service-privacy-policy",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="flashtalking",
            display_name="Flashtalking / Innovid",
            owner_name="Innovid",
            owner_class="third_party",
            service_category="adtech",
            primary_use_case="ad_serving_and_creative_delivery",
            documentation_url="https://www.flashtalking.com/",
            privacy_policy_url="https://www.flashtalking.com/consumer-privacy",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="optimizely",
            display_name="Optimizely",
            owner_name="Optimizely",
            owner_class="third_party",
            service_category="experimentation",
            primary_use_case="experimentation_and_personalization",
            documentation_url="https://www.optimizely.com/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="piano",
            display_name="Piano",
            owner_name="Piano",
            owner_class="third_party",
            service_category="analytics",
            primary_use_case="analytics_and_customer_experience",
            documentation_url="https://www.piano.io/",
            confidence="medium",
        ),
        ServiceCatalogEntry(
            service_key="adobe_experience_cloud",
            display_name="Adobe Experience Cloud",
            owner_name="Adobe",
            owner_class="third_party",
            service_category="identity_and_tag_management",
            primary_use_case="identity_service_and_tag_delivery",
            documentation_url="https://experienceleague.adobe.com/en/docs/id-service/using/intro/cookies",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="integral_ad_science",
            display_name="Integral Ad Science",
            owner_name="Integral Ad Science",
            owner_class="third_party",
            service_category="ad_verification",
            primary_use_case="media_quality_and_brand_safety",
            documentation_url="https://integralads.com/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="amazon_ads",
            display_name="Amazon Ads",
            owner_name="Amazon",
            owner_class="third_party",
            service_category="adtech",
            primary_use_case="advertising_and_measurement",
            documentation_url="https://advertising.amazon.com/",
            confidence="medium",
        ),
        ServiceCatalogEntry(
            service_key="admaster",
            display_name="AdMaster",
            owner_name="AdMaster",
            owner_class="third_party",
            service_category="ad_measurement",
            primary_use_case="advertising_measurement_and_verification",
            documentation_url="https://www.admaster.com.cn/",
            confidence="medium",
        ),
        ServiceCatalogEntry(
            service_key="scorecardresearch",
            display_name="ScorecardResearch",
            owner_name="Comscore",
            owner_class="third_party",
            service_category="analytics",
            primary_use_case="audience_measurement",
            documentation_url="https://www.comscore.com/",
            privacy_policy_url="https://www.comscore.com/About/Privacy-Policy",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="new_relic",
            display_name="New Relic Mobile Monitoring",
            owner_name="New Relic",
            owner_class="third_party",
            service_category="analytics",
            primary_use_case="mobile_telemetry_and_monitoring",
            documentation_url="https://docs.newrelic.com/docs/mobile-monitoring/new-relic-mobile/mobile-sdk/configure-settings/",
            confidence="medium",
        ),
        ServiceCatalogEntry(
            service_key="nielsen_dcr",
            display_name="Nielsen Digital Content Ratings",
            owner_name="Nielsen",
            owner_class="third_party",
            service_category="analytics",
            primary_use_case="digital_audience_measurement",
            documentation_url="https://learning.nielsen.com/page/digital-content-ratings-dcr",
            source_url="https://www.netify.ai/resources/domains/vtwenty.com",
            confidence="medium",
            notes="Service association uses a secondary hostname source and should be treated as curated but reviewable.",
        ),
        ServiceCatalogEntry(
            service_key="ozone_project",
            display_name="The Ozone Project",
            owner_name="The Ozone Project",
            owner_class="third_party",
            service_category="adtech",
            primary_use_case="publisher_ad_exchange",
            documentation_url="https://www.theozoneproject.com/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="facebook_platform",
            display_name="Facebook / Meta Platform",
            owner_name="Meta",
            owner_class="first_party",
            service_category="social_platform",
            primary_use_case="social_graph_and_messaging",
            documentation_url="https://developers.facebook.com/",
            privacy_policy_url="https://www.facebook.com/privacy/policy/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="meta_sdk",
            display_name="Meta Platform SDK / APIs",
            owner_name="Meta",
            owner_class="third_party",
            service_category="social_platform",
            primary_use_case="social_graph_sdk_and_identity",
            documentation_url="https://developers.facebook.com/",
            privacy_policy_url="https://www.facebook.com/privacy/policy/",
            confidence="medium",
        ),
        ServiceCatalogEntry(
            service_key="x_platform",
            display_name="X / Twitter Platform",
            owner_name="X",
            owner_class="first_party",
            service_category="social_platform",
            primary_use_case="social_graph_and_platform_api",
            documentation_url="https://docs.x.com/x-api/introduction",
            source_url="https://developer.x.com/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="x_media_cdn",
            display_name="X / Twitter Media Delivery",
            owner_name="X",
            owner_class="first_party",
            service_category="content_delivery",
            primary_use_case="media_and_static_asset_delivery",
            documentation_url="https://developer.x.com/",
            source_url="https://devcommunity.x.com/t/pbs-twimg-com-cdn-problems/92623",
            confidence="medium",
            notes="Used for twimg-hosted media and static asset delivery observed during X/Twitter app runtime traffic.",
        ),
        ServiceCatalogEntry(
            service_key="x_ads_platform",
            display_name="X / Twitter Advertising Platform",
            owner_name="X",
            owner_class="first_party",
            service_category="adtech",
            primary_use_case="advertising_api_and_measurement",
            documentation_url="https://docs.x.com/x-api/introduction",
            source_url="https://developer.x.com/",
            confidence="medium",
            notes="Used for X/Twitter-owned advertising endpoints; treat as first-party ad/measurement context rather than third-party tracker by default.",
        ),
        ServiceCatalogEntry(
            service_key="microsoft_ads_atlas",
            display_name="Microsoft Advertising / Atlas",
            owner_name="Microsoft",
            owner_class="third_party",
            service_category="adtech",
            primary_use_case="ad_serving_click_tracking_and_measurement",
            documentation_url="https://learn.microsoft.com/en-us/xandr/bidders/creative-macro-check-service",
            confidence="medium",
            notes="Used for ATDMT / Atlas ad-serving and click-tracking infrastructure.",
        ),
        ServiceCatalogEntry(
            service_key="tiktok_platform",
            display_name="TikTok / ByteDance Platform",
            owner_name="ByteDance",
            owner_class="first_party",
            service_category="social_platform",
            primary_use_case="content_delivery_and_platform_control",
            documentation_url="https://developers.tiktok.com/",
            privacy_policy_url="https://www.tiktok.com/legal/privacy-policy",
            source_url="https://developers.tiktok.com/doc/display-api-get-started/",
            confidence="high",
        ),
        ServiceCatalogEntry(
            service_key="turner_cnn_legacy",
            display_name="Turner / CNN Legacy Media Infrastructure",
            owner_name="Warner Bros. Discovery",
            owner_class="first_party",
            service_category="publisher",
            primary_use_case="legacy_media_delivery_and_auth",
            documentation_url="https://www.cnn.com",
            confidence="medium",
        ),
        ServiceCatalogEntry(
            service_key="oracle_cloud",
            display_name="Oracle Cloud Infrastructure",
            owner_name="Oracle",
            owner_class="third_party",
            service_category="platform_infrastructure",
            primary_use_case="cloud_infrastructure_and_hosting",
            documentation_url="https://docs.cloud.oracle.com/",
            source_url="https://www.oracle.com/cloud/",
            confidence="medium",
        ),
    )


def default_service_domain_map_entries() -> tuple[ServiceDomainMapEntry, ...]:
    return (
        ServiceDomainMapEntry("bbc_first_party", "bbc.com", "SUFFIX", "bbc.mobile.news.ww", "publisher_api", confidence="high"),
        ServiceDomainMapEntry("bbc_first_party", "bbc.co.uk", "SUFFIX", "bbc.mobile.news.ww", "identity_api", confidence="medium"),
        ServiceDomainMapEntry("bbc_first_party", "bbci.co.uk", "SUFFIX", "bbc.mobile.news.ww", "content_delivery", confidence="high"),
        ServiceDomainMapEntry("cnn_first_party", "cnn.com", "SUFFIX", "com.cnn.mobile.android.phone", "publisher_content", confidence="high"),
        ServiceDomainMapEntry("cnn_first_party", "cnn.io", "SUFFIX", "com.cnn.mobile.android.phone", "publisher_api", confidence="medium"),
        ServiceDomainMapEntry("urbanairship", "urbanairship.com", "SUFFIX", role_class="engagement_push", confidence="high"),
        ServiceDomainMapEntry("dianomi", "dianomi.com", "SUFFIX", role_class="adtech_monetization", confidence="high"),
        ServiceDomainMapEntry("doubleverify", "doubleverify.com", "SUFFIX", role_class="ad_verification", confidence="high"),
        ServiceDomainMapEntry("permutive", "permutive.app", "SUFFIX", role_class="audience_personalization", confidence="high"),
        ServiceDomainMapEntry("permutive", "permutive.com", "SUFFIX", role_class="audience_personalization", confidence="high"),
        ServiceDomainMapEntry("appsflyer", "appsflyersdk.com", "SUFFIX", role_class="attribution_measurement", confidence="high"),
        ServiceDomainMapEntry("liveramp", "rlcdn.com", "SUFFIX", role_class="identity_sync", confidence="high"),
        ServiceDomainMapEntry("flashtalking", "flashtalking.com", "SUFFIX", role_class="ad_creative_delivery", confidence="high"),
        ServiceDomainMapEntry("optimizely", "optimizely.com", "SUFFIX", role_class="experimentation_personalization", confidence="high"),
        ServiceDomainMapEntry("piano", "piano.io", "SUFFIX", role_class="analytics_measurement", confidence="medium"),
        ServiceDomainMapEntry("adobe_experience_cloud", "adobedtm.com", "SUFFIX", role_class="tag_delivery", confidence="high"),
        ServiceDomainMapEntry("adobe_experience_cloud", "demdex.net", "SUFFIX", role_class="audience_identity", confidence="high"),
        ServiceDomainMapEntry("adobe_experience_cloud", "adobe.com", "SUFFIX", "com.cnn.mobile.android.phone", "identity_api", confidence="medium"),
        ServiceDomainMapEntry("integral_ad_science", "adsafeprotected.com", "SUFFIX", role_class="ad_verification", confidence="high"),
        ServiceDomainMapEntry("amazon_ads", "amazon-adsystem.com", "SUFFIX", role_class="adtech_monetization", confidence="medium"),
        ServiceDomainMapEntry("admaster", "admaster.cc", "SUFFIX", role_class="ad_measurement", confidence="medium"),
        ServiceDomainMapEntry("google_ads", "doubleclick.net", "SUFFIX", role_class="adtech_monetization", confidence="high"),
        ServiceDomainMapEntry("google_ads", "googlesyndication.com", "SUFFIX", role_class="adtech_monetization", confidence="high"),
        ServiceDomainMapEntry("google_ads", "2mdn.net", "SUFFIX", role_class="ad_creative_delivery", confidence="high"),
        ServiceDomainMapEntry("google_ads", "googletagservices.com", "SUFFIX", role_class="tag_delivery", confidence="high"),
        ServiceDomainMapEntry("google_ads", "adtrafficquality.google", "SUFFIX", role_class="ad_measurement", confidence="medium"),
        ServiceDomainMapEntry("google_ads", "imasdk.googleapis.com", "EXACT", role_class="adtech_monetization", confidence="medium"),
        ServiceDomainMapEntry("google_platform", "gstatic.com", "SUFFIX", role_class="google_infrastructure", confidence="medium"),
        ServiceDomainMapEntry("google_platform", "googlevideo.com", "SUFFIX", role_class="embedded_media_delivery", confidence="medium"),
        ServiceDomainMapEntry("google_platform", "googleapis.com", "SUFFIX", role_class="google_api_platform", confidence="medium"),
        ServiceDomainMapEntry("oracle_cloud", "oraclecloud.com", "SUFFIX", role_class="cloud_infrastructure", confidence="medium"),
        ServiceDomainMapEntry("chartbeat", "chartbeat.net", "SUFFIX", role_class="analytics_measurement", confidence="high"),
        ServiceDomainMapEntry("scorecardresearch", "scorecardresearch.com", "SUFFIX", role_class="audience_measurement", confidence="high"),
        ServiceDomainMapEntry("new_relic", "newrelic.com", "SUFFIX", role_class="analytics_measurement", confidence="medium"),
        ServiceDomainMapEntry("nielsen_dcr", "vtwenty.com", "SUFFIX", role_class="audience_measurement", confidence="medium"),
        ServiceDomainMapEntry("ozone_project", "the-ozone-project.com", "SUFFIX", role_class="adtech_monetization", confidence="high"),
        ServiceDomainMapEntry("turner_cnn_legacy", "turner.com", "SUFFIX", "com.cnn.mobile.android.phone", "content_delivery", confidence="medium"),
        ServiceDomainMapEntry("espn_first_party", "fan.api.espn.com", "EXACT", "com.espn.score_center", "publisher_api", confidence="high"),
        ServiceDomainMapEntry("espn_first_party", "pinpoint.espn.com", "EXACT", "com.espn.score_center", "publisher_collection", confidence="medium"),
        ServiceDomainMapEntry("espn_first_party", "espn.api.edge.bamgrid.com", "EXACT", "com.espn.score_center", "publisher_api", confidence="medium"),
        ServiceDomainMapEntry("espn_first_party", "espn.connections.edge.bamgrid.com", "EXACT", "com.espn.score_center", "publisher_api", confidence="medium"),
        ServiceDomainMapEntry("espn_first_party", "espn.com", "SUFFIX", "com.espn.score_center", "publisher_api", confidence="medium"),
        ServiceDomainMapEntry("espn_first_party", "bamgrid.com", "SUFFIX", "com.espn.score_center", "publisher_api", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "b-graph.facebook.com", "EXACT", "com.facebook.katana", "social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "connect.facebook.net", "EXACT", "com.facebook.katana", "identity_api", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "facebook.com", "SUFFIX", "com.facebook.katana", "social_graph_api", confidence="high"),
        ServiceDomainMapEntry("facebook_platform", "facebook.com", "SUFFIX", "com.facebook.orca", "social_graph_api", confidence="high"),
        ServiceDomainMapEntry("facebook_platform", "facebook.com", "SUFFIX", "com.instagram.android", "social_graph_api", confidence="high"),
        ServiceDomainMapEntry("facebook_platform", "facebook.net", "SUFFIX", "com.facebook.katana", "social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "facebook.net", "SUFFIX", "com.facebook.orca", "social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "facebook.net", "SUFFIX", "com.instagram.android", "social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "fbcdn.net", "SUFFIX", "com.facebook.katana", "content_delivery", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "fbcdn.net", "SUFFIX", "com.facebook.orca", "content_delivery", confidence="medium"),
        ServiceDomainMapEntry("facebook_platform", "fbcdn.net", "SUFFIX", "com.instagram.android", "content_delivery", confidence="medium"),
        ServiceDomainMapEntry("meta_sdk", "b-graph.facebook.com", "EXACT", role_class="social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("meta_sdk", "connect.facebook.net", "EXACT", role_class="identity_api", confidence="medium"),
        ServiceDomainMapEntry("meta_sdk", "facebook.com", "SUFFIX", role_class="social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("meta_sdk", "facebook.net", "SUFFIX", role_class="social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("meta_sdk", "fbcdn.net", "SUFFIX", role_class="content_delivery", confidence="low"),
        ServiceDomainMapEntry("x_platform", "api.twitter.com", "EXACT", "com.twitter.android", "social_graph_api", confidence="high"),
        ServiceDomainMapEntry("x_platform", "api-stream.twitter.com", "EXACT", "com.twitter.android", "social_graph_api", confidence="high"),
        ServiceDomainMapEntry("x_platform", "api.x.com", "EXACT", "com.twitter.android", "social_graph_api", confidence="high"),
        ServiceDomainMapEntry("x_platform", "x.com", "EXACT", "com.twitter.android", "social_graph_api", confidence="medium"),
        ServiceDomainMapEntry("x_media_cdn", "pbs.twimg.com", "EXACT", "com.twitter.android", "content_delivery", confidence="high"),
        ServiceDomainMapEntry("x_media_cdn", "video.twimg.com", "EXACT", "com.twitter.android", "content_delivery", confidence="high"),
        ServiceDomainMapEntry("x_media_cdn", "abs.twimg.com", "EXACT", "com.twitter.android", "static_asset_delivery", confidence="medium"),
        ServiceDomainMapEntry("x_ads_platform", "ads-api.x.com", "EXACT", "com.twitter.android", "ad_measurement", confidence="medium"),
        ServiceDomainMapEntry("microsoft_ads_atlas", "atdmt.com", "SUFFIX", role_class="adtech_monetization", confidence="medium"),
        ServiceDomainMapEntry("google_platform", "time.google.com", "EXACT", role_class="google_infrastructure", confidence="medium"),
        ServiceDomainMapEntry("tiktok_platform", "tiktokcdn-us.com", "SUFFIX", "com.zhiliaoapp.musically", "content_delivery", confidence="high"),
        ServiceDomainMapEntry("tiktok_platform", "tiktokv.us", "SUFFIX", "com.zhiliaoapp.musically", "first_party_misc", confidence="high"),
        ServiceDomainMapEntry("tiktok_platform", "ibyteimg.com", "SUFFIX", "com.zhiliaoapp.musically", "content_delivery", confidence="medium"),
    )


def default_service_catalog_seed_rows() -> list[dict[str, str | None]]:
    return [
        {
            "service_key": entry.service_key,
            "display_name": entry.display_name,
            "owner_name": entry.owner_name,
            "owner_class": entry.owner_class,
            "service_category": entry.service_category,
            "primary_use_case": entry.primary_use_case,
            "documentation_url": entry.documentation_url,
            "privacy_policy_url": entry.privacy_policy_url,
            "source_label": entry.source_label,
            "source_url": entry.source_url,
            "confidence": entry.confidence,
            "notes": entry.notes,
        }
        for entry in default_service_catalog_entries()
    ]


def default_service_domain_map_seed_rows() -> list[dict[str, str | None]]:
    return [
        {
            "service_key": entry.service_key,
            "package_name_scope": entry.package_name_scope,
            "domain_pattern": normalize_domain(entry.domain_pattern),
            "match_type": entry.match_type.upper(),
            "role_class": entry.role_class,
            "source_label": entry.source_label,
            "source_url": entry.source_url,
            "confidence": entry.confidence,
            "notes": entry.notes,
        }
        for entry in default_service_domain_map_entries()
    ]


def resolve_service_for_domain(
    domain: str,
    *,
    package_name: str,
    service_rows: tuple[dict[str, Any], ...],
    map_rows: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    normalized_package = _norm_text(package_name).lower()
    root = root_domain(normalized)
    if not normalized:
        return {
            "domain": "",
            "root_domain": "",
            "service_key": None,
            "service_display_name": None,
            "owner_name": None,
            "owner_class": None,
            "service_category": None,
            "primary_use_case": None,
            "role_class": None,
            "confidence": None,
            "match_type": None,
            "package_name_scope": None,
            "source_url": None,
        }

    by_key = {str(row.get("service_key") or ""): row for row in service_rows}
    candidates: list[dict[str, Any]] = []
    for row in map_rows:
        pattern = normalize_domain(row.get("domain_pattern"))
        match_type = str(row.get("match_type") or "").upper()
        scope = _norm_text(row.get("package_name_scope")).lower()
        if scope and scope != normalized_package:
            continue
        matched = False
        if match_type == "EXACT":
            matched = pattern == normalized
        elif match_type == "SUFFIX":
            matched = suffix_match(normalized, pattern)
        if matched:
            score = (0 if scope else 1, 0 if match_type == "EXACT" else 1, -len(pattern))
            candidates.append({"row": row, "score": score})
    candidates.sort(key=lambda item: item["score"])
    if not candidates:
        return {
            "domain": normalized,
            "root_domain": root,
            "service_key": None,
            "service_display_name": None,
            "owner_name": None,
            "owner_class": None,
            "service_category": None,
            "primary_use_case": None,
            "role_class": None,
            "confidence": None,
            "match_type": None,
            "package_name_scope": None,
            "source_url": None,
        }
    chosen = candidates[0]["row"]
    service = by_key.get(str(chosen.get("service_key") or ""), {})
    return {
        "domain": normalized,
        "root_domain": root,
        "service_key": service.get("service_key"),
        "service_display_name": service.get("display_name"),
        "owner_name": service.get("owner_name"),
        "owner_class": service.get("owner_class"),
        "service_category": service.get("service_category"),
        "primary_use_case": service.get("primary_use_case"),
        "role_class": chosen.get("role_class"),
        "confidence": chosen.get("confidence") or service.get("confidence"),
        "match_type": chosen.get("match_type"),
        "package_name_scope": chosen.get("package_name_scope"),
        "source_url": chosen.get("source_url") or service.get("source_url") or service.get("documentation_url"),
    }


__all__ = [
    "ServiceCatalogEntry",
    "ServiceDomainMapEntry",
    "default_service_catalog_entries",
    "default_service_catalog_seed_rows",
    "default_service_domain_map_entries",
    "default_service_domain_map_seed_rows",
    "resolve_service_for_domain",
]
