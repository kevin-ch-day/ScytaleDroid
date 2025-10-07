"""Provider-specific string matching patterns used by detectors."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Pattern


@dataclass(frozen=True)
class StringPattern:
    """Represents a compiled regex and its provider metadata."""

    name: str
    description: str
    pattern: Pattern[str]


DEFAULT_PATTERNS: tuple[StringPattern, ...] = (
    StringPattern(
        name="google_api_key",
        description="Potential Google API key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    StringPattern(
        name="google_oauth_client",
        description="Potential Google OAuth client secret",
        pattern=re.compile(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"),
    ),
    StringPattern(
        name="firebase_database",
        description="Potential Firebase Realtime Database URL",
        pattern=re.compile(r"https://[\w\-]+\.firebaseio\.com"),
    ),
    StringPattern(
        name="firebase_storage",
        description="Potential Firebase Storage bucket",
        pattern=re.compile(r"gs://[\w\-]+\.appspot\.com"),
    ),
    StringPattern(
        name="aws_access_key",
        description="Potential AWS access key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    StringPattern(
        name="aws_secret_key",
        description="Potential AWS secret access key",
        pattern=re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])"),
    ),
    StringPattern(
        name="aws_session_token",
        description="Potential AWS session token",
        pattern=re.compile(r"ASIA[0-9A-Z]{16}"),
    ),
    StringPattern(
        name="generic_bearer",
        description="Potential bearer token",
        pattern=re.compile(r"Bearer\s+[A-Za-z0-9\-\._~+/]{8,}"),
    ),
    StringPattern(
        name="slack_webhook",
        description="Potential Slack webhook URL",
        pattern=re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ),
    StringPattern(
        name="stripe_secret_key",
        description="Potential Stripe secret key",
        pattern=re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24}"),
    ),
    StringPattern(
        name="github_token",
        description="Potential GitHub personal access token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"),
    ),
    StringPattern(
        name="twilio_api_key",
        description="Potential Twilio API key",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
    ),
    StringPattern(
        name="sendgrid_api_key",
        description="Potential SendGrid API key",
        pattern=re.compile(r"SG\.[A-Za-z0-9\-_.]{16,}\.[A-Za-z0-9\-_.]{16,}"),
    ),
    StringPattern(
        name="square_access_token",
        description="Potential Square access token",
        pattern=re.compile(r"sq0(atp|csp|dev|prod)-[A-Za-z0-9\-_]{22}"),
    ),
    StringPattern(
        name="azure_connection_string",
        description="Potential Azure connection string",
        pattern=re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}"),
    ),
)


__all__ = ["StringPattern", "DEFAULT_PATTERNS"]
