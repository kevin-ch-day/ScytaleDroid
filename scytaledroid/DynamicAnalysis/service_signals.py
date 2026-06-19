"""DB-backed signal taxonomy for dynamic service/provider interpretation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SignalCatalogEntry:
    signal_key: str
    display_name: str
    signal_family: str
    focus_area: str
    severity_hint: str
    description: str
    analyst_guidance: str
    source_label: str = "repo_seed"
    source_url: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class ServiceSignalMapEntry:
    service_key: str
    signal_key: str
    signal_strength: str = "primary"
    confidence: str = "high"
    rationale: str | None = None
    source_label: str = "repo_seed"
    source_url: str | None = None
    notes: str | None = None


def default_signal_catalog_entries() -> tuple[SignalCatalogEntry, ...]:
    return (
        SignalCatalogEntry(
            signal_key="third_party_advertising",
            display_name="Third-Party Advertising",
            signal_family="advertising",
            focus_area="privacy",
            severity_hint="medium",
            description="Observed service participates in ad delivery or monetization flows.",
            analyst_guidance="Treat as monetization/ad-tech context and correlate with static ad/tracker surface.",
        ),
        SignalCatalogEntry(
            signal_key="ad_measurement_or_verification",
            display_name="Ad Measurement / Verification",
            signal_family="advertising_measurement",
            focus_area="privacy",
            severity_hint="medium",
            description="Observed service measures ad quality, attribution, or brand-safety outcomes.",
            analyst_guidance="Use to distinguish ad-tech measurement from first-party publisher content traffic.",
        ),
        SignalCatalogEntry(
            signal_key="audience_profiling_or_personalization",
            display_name="Audience Profiling / Personalization",
            signal_family="profiling",
            focus_area="privacy",
            severity_hint="high",
            description="Observed service supports audience segmentation, curation, or personalization.",
            analyst_guidance="Treat as strong privacy-relevant context, especially when combined with news/social apps.",
        ),
        SignalCatalogEntry(
            signal_key="cross_app_attribution",
            display_name="Cross-App Attribution",
            signal_family="attribution",
            focus_area="privacy",
            severity_hint="high",
            description="Observed service supports install or engagement attribution across apps or campaigns.",
            analyst_guidance="Flag as cross-app measurement context and compare with declared analytics/tracker posture.",
        ),
        SignalCatalogEntry(
            signal_key="third_party_analytics_measurement",
            display_name="Third-Party Analytics / Measurement",
            signal_family="analytics",
            focus_area="privacy",
            severity_hint="medium",
            description="Observed service supports usage analytics, audience measurement, or experience telemetry.",
            analyst_guidance="Treat as analytics context rather than direct content delivery.",
        ),
        SignalCatalogEntry(
            signal_key="push_or_engagement_platform",
            display_name="Push / Engagement Platform",
            signal_family="engagement",
            focus_area="mixed",
            severity_hint="medium",
            description="Observed service supports notifications, engagement, or customer messaging.",
            analyst_guidance="Interpret as engagement infrastructure; correlate with app messaging/notification behavior.",
        ),
        SignalCatalogEntry(
            signal_key="shared_platform_infrastructure",
            display_name="Shared Platform Infrastructure",
            signal_family="infrastructure",
            focus_area="context",
            severity_hint="low",
            description="Observed service is broad shared platform infrastructure rather than app-specific business logic.",
            analyst_guidance="Usually lower-priority unless paired with stronger privacy/security signals.",
        ),
        SignalCatalogEntry(
            signal_key="first_party_publisher_api",
            display_name="First-Party Publisher API",
            signal_family="first_party_content",
            focus_area="context",
            severity_hint="low",
            description="Observed service appears to be a publisher-owned API or content endpoint.",
            analyst_guidance="Useful as benign first-party context and contrast against third-party traffic.",
        ),
        SignalCatalogEntry(
            signal_key="first_party_social_platform",
            display_name="First-Party Social Platform",
            signal_family="first_party_platform",
            focus_area="context",
            severity_hint="medium",
            description="Observed service belongs to the app publisher’s own social/content platform stack.",
            analyst_guidance="Interpret as first-party platform behavior, not third-party tracking by default.",
        ),
        SignalCatalogEntry(
            signal_key="identity_or_tag_management",
            display_name="Identity / Tag Management",
            signal_family="identity_management",
            focus_area="privacy",
            severity_hint="high",
            description="Observed service supports identity sync, tag delivery, or authentication-related orchestration.",
            analyst_guidance="High-value context when combined with measurement, ad-tech, or user identity surfaces.",
        ),
    )


def default_service_signal_map_entries() -> tuple[ServiceSignalMapEntry, ...]:
    return (
        ServiceSignalMapEntry("bbc_first_party", "first_party_publisher_api"),
        ServiceSignalMapEntry("cnn_first_party", "first_party_publisher_api"),
        ServiceSignalMapEntry("espn_first_party", "first_party_publisher_api"),
        ServiceSignalMapEntry("facebook_platform", "first_party_social_platform"),
        ServiceSignalMapEntry("tiktok_platform", "first_party_social_platform"),
        ServiceSignalMapEntry("x_platform", "first_party_social_platform"),
        ServiceSignalMapEntry("x_media_cdn", "first_party_social_platform", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("x_ads_platform", "ad_measurement_or_verification", confidence="medium"),
        ServiceSignalMapEntry("x_ads_platform", "first_party_social_platform", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("meta_sdk", "identity_or_tag_management", confidence="medium"),
        ServiceSignalMapEntry("google_ads", "third_party_advertising"),
        ServiceSignalMapEntry("google_ads", "ad_measurement_or_verification", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("amazon_ads", "third_party_advertising", confidence="medium"),
        ServiceSignalMapEntry("microsoft_ads_atlas", "third_party_advertising", confidence="medium"),
        ServiceSignalMapEntry("microsoft_ads_atlas", "ad_measurement_or_verification", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("ozone_project", "third_party_advertising"),
        ServiceSignalMapEntry("dianomi", "third_party_advertising"),
        ServiceSignalMapEntry("flashtalking", "third_party_advertising"),
        ServiceSignalMapEntry("flashtalking", "ad_measurement_or_verification", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("doubleverify", "ad_measurement_or_verification"),
        ServiceSignalMapEntry("integral_ad_science", "ad_measurement_or_verification"),
        ServiceSignalMapEntry("permutive", "audience_profiling_or_personalization"),
        ServiceSignalMapEntry("appsflyer", "cross_app_attribution"),
        ServiceSignalMapEntry("liveramp", "identity_or_tag_management"),
        ServiceSignalMapEntry("adobe_experience_cloud", "identity_or_tag_management"),
        ServiceSignalMapEntry("adobe_experience_cloud", "third_party_analytics_measurement", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("admaster", "ad_measurement_or_verification", confidence="medium"),
        ServiceSignalMapEntry("chartbeat", "third_party_analytics_measurement"),
        ServiceSignalMapEntry("scorecardresearch", "third_party_analytics_measurement"),
        ServiceSignalMapEntry("new_relic", "third_party_analytics_measurement", confidence="medium"),
        ServiceSignalMapEntry("nielsen_dcr", "third_party_analytics_measurement", confidence="medium"),
        ServiceSignalMapEntry("piano", "third_party_analytics_measurement", confidence="medium"),
        ServiceSignalMapEntry("urbanairship", "push_or_engagement_platform"),
        ServiceSignalMapEntry("google_platform", "shared_platform_infrastructure"),
        ServiceSignalMapEntry("oracle_cloud", "shared_platform_infrastructure", confidence="medium"),
        ServiceSignalMapEntry("optimizely", "audience_profiling_or_personalization", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("optimizely", "third_party_analytics_measurement", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("turner_cnn_legacy", "first_party_publisher_api", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("wbd_streaming_platform", "shared_platform_infrastructure", confidence="medium"),
        ServiceSignalMapEntry("freewheel", "third_party_advertising"),
        ServiceSignalMapEntry("freewheel", "ad_measurement_or_verification", signal_strength="secondary", confidence="medium"),
        ServiceSignalMapEntry("mux_data", "third_party_analytics_measurement", confidence="medium"),
        ServiceSignalMapEntry("brightline_ctv", "third_party_advertising"),
    )


def default_signal_catalog_seed_rows() -> list[dict[str, str | None]]:
    return [
        {
            "signal_key": entry.signal_key,
            "display_name": entry.display_name,
            "signal_family": entry.signal_family,
            "focus_area": entry.focus_area,
            "severity_hint": entry.severity_hint,
            "description": entry.description,
            "analyst_guidance": entry.analyst_guidance,
            "source_label": entry.source_label,
            "source_url": entry.source_url,
            "notes": entry.notes,
        }
        for entry in default_signal_catalog_entries()
    ]


def default_service_signal_map_seed_rows() -> list[dict[str, str | None]]:
    return [
        {
            "service_key": entry.service_key,
            "signal_key": entry.signal_key,
            "signal_strength": entry.signal_strength,
            "confidence": entry.confidence,
            "rationale": entry.rationale,
            "source_label": entry.source_label,
            "source_url": entry.source_url,
            "notes": entry.notes,
        }
        for entry in default_service_signal_map_entries()
    ]


__all__ = [
    "SignalCatalogEntry",
    "ServiceSignalMapEntry",
    "default_signal_catalog_entries",
    "default_signal_catalog_seed_rows",
    "default_service_signal_map_entries",
    "default_service_signal_map_seed_rows",
]
