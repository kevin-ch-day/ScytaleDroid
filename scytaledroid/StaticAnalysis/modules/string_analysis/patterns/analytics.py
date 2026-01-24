"""Analytics, observability, and marketing credential patterns."""

from __future__ import annotations

import re

from .base import DEFAULT_ORIGINS, StringPattern

PATTERNS: tuple[StringPattern, ...] = (
    StringPattern(
        name="sentry_dsn",
        description="Potential Sentry DSN",
        pattern=re.compile(r"https?://[a-f0-9]{32}@o\d+\.ingest\.sentry\.io/\d+"),
        category="analytics",
        provider="Sentry",
        tags=("dsn", "sentry"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="bugsnag_api_key",
        description="Potential Bugsnag API key",
        pattern=re.compile(r"(?i)bugsnag[^a-f0-9]{0,6}([0-9a-f]{32})"),
        category="analytics",
        provider="Bugsnag",
        tags=("api_key", "bugsnag"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="onesignal_app_id",
        description="Potential OneSignal app ID",
        pattern=re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"),
        category="analytics",
        provider="OneSignal",
        tags=("app_id", "onesignal"),
        preferred_origins=DEFAULT_ORIGINS,
        context_keywords=("onesignal",),
    ),
    StringPattern(
        name="analytics_write_key",
        description="Potential analytics token assignment",
        pattern=re.compile(
            r'(?i)(?:api[_-]?key|write[_-]?key|token)["\'=:\s]+([A-Za-z0-9\-_]{20,128})'
        ),
        category="analytics",
        tags=("token", "assignment"),
        preferred_origins=DEFAULT_ORIGINS,
        context_keywords=(
            "mixpanel",
            "segment",
            "amplitude",
            "adjust",
            "branch",
            "appsflyer",
            "datadog",
        ),
    ),
    StringPattern(
        name="datadog_api_key",
        description="Potential Datadog API key",
        pattern=re.compile(r"DD[a-zA-Z0-9]{32}"),
        category="observability",
        provider="Datadog",
        tags=("api_key", "datadog"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="newrelic_license_key",
        description="Potential New Relic ingest license key",
        pattern=re.compile(r"[A-Za-z0-9]{2}NRAL-[A-Z0-9]{42}"),
        category="observability",
        provider="New Relic",
        tags=("license_key", "newrelic"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
)

__all__ = ["PATTERNS"]
