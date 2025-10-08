"""Messaging, email, and collaboration credential patterns."""

from __future__ import annotations

import re

from .base import DEFAULT_ORIGINS, StringPattern

PATTERNS: tuple[StringPattern, ...] = (
    # Communications & messaging
    StringPattern(
        name="twilio_account_sid",
        description="Potential Twilio account SID",
        pattern=re.compile(r"(AC[0-9a-fA-F]{32})"),
        category="communications",
        provider="Twilio",
        tags=("account_sid", "twilio"),
        preferred_origins=DEFAULT_ORIGINS,
        context_keywords=("twilio",),
    ),
    StringPattern(
        name="twilio_auth_token",
        description="Potential Twilio auth token",
        pattern=re.compile(r"([0-9a-fA-F]{32})"),
        category="communications",
        provider="Twilio",
        tags=("auth_token", "twilio"),
        preferred_origins=DEFAULT_ORIGINS,
        context_keywords=("twilio",),
    ),
    StringPattern(
        name="twilio_api_key",
        description="Potential Twilio API key",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
        category="communications",
        provider="Twilio",
        tags=("api_key", "twilio"),
        preferred_origins=DEFAULT_ORIGINS,
        context_keywords=("twilio",),
    ),
    StringPattern(
        name="sendgrid_api_key",
        description="Potential SendGrid API key",
        pattern=re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
        category="communications",
        provider="SendGrid",
        tags=("api_key", "sendgrid"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    # Collaboration / chat
    StringPattern(
        name="slack_webhook",
        description="Potential Slack webhook URL",
        pattern=re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),
        category="collaboration",
        provider="Slack",
        tags=("webhook", "url"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="slack_token",
        description="Potential Slack token",
        pattern=re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        category="collaboration",
        provider="Slack",
        tags=("token", "slack"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="discord_webhook",
        description="Potential Discord webhook URL",
        pattern=re.compile(r"https://discord(?:app)?\.com/api/webhooks/[\w-]+/[\w-]+"),
        category="collaboration",
        provider="Discord",
        tags=("webhook", "url"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
)

__all__ = ["PATTERNS"]
