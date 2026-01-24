"""Cloud provider credential patterns."""

from __future__ import annotations

import re

from .base import DEFAULT_ORIGINS, StringPattern

PATTERNS: tuple[StringPattern, ...] = (
    # Google / Firebase
    StringPattern(
        name="google_api_key",
        description="Potential Google API key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        category="cloud",
        provider="Google",
        tags=("api_key", "google"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="google_oauth_client",
        description="Potential Google OAuth client ID",
        pattern=re.compile(r"\d{12,}-[a-z0-9\-]+\.apps\.googleusercontent\.com"),
        category="cloud",
        provider="Google",
        tags=("oauth", "client_id"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="firebase_database",
        description="Potential Firebase Realtime Database URL",
        pattern=re.compile(r"https://[\w\-]{1,64}\.(?:firebaseio\.com|firebasedatabase\.app)"),
        category="cloud",
        provider="Firebase",
        tags=("url", "database"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="firebase_storage",
        description="Potential Firebase Storage bucket",
        pattern=re.compile(r"gs://[\w\-]+\.appspot\.com"),
        category="cloud",
        provider="Firebase",
        tags=("storage", "bucket"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="firebase_fcm_sender_id",
        description="Potential Firebase Cloud Messaging sender ID",
        pattern=re.compile(r"(?i)(?:gcm|fcm|project(?:_|)number)[^0-9]{0,6}(\d{10,})"),
        category="cloud",
        provider="Firebase",
        tags=("messaging", "id"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="firebase_api_key",
        description="Potential Firebase web API key",
        pattern=re.compile(r"AIzaSy[0-9A-Za-z\-_]{33}"),
        category="cloud",
        provider="Firebase",
        tags=("api_key", "firebase"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    # AWS
    StringPattern(
        name="aws_access_key",
        description="Potential AWS access key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        category="cloud",
        provider="AWS",
        tags=("api_key", "aws"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="aws_secret_access_key",
        description="Potential AWS secret access key",
        pattern=re.compile(r"(?i)(?:aws|aws_secret_access_key)[^A-Za-z0-9]{0,6}([A-Za-z0-9/+=]{40})"),
        category="cloud",
        provider="AWS",
        tags=("secret", "aws"),
        min_length=40,
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="aws_session_token",
        description="Potential AWS session token",
        pattern=re.compile(r"ASIA[0-9A-Z]{16}"),
        category="cloud",
        provider="AWS",
        tags=("session", "aws"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="aws_s3_endpoint",
        description="Potential AWS S3 endpoint",
        pattern=re.compile(r"s3[\.-][a-z0-9\-]+\.amazonaws\.com"),
        category="cloud",
        provider="AWS",
        tags=("storage", "endpoint"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    # Azure / GCP
    StringPattern(
        name="azure_storage_connection",
        description="Potential Azure storage connection string",
        pattern=re.compile(
            r"DefaultEndpointsProtocol=[^;]{1,32};AccountName=[^;]{1,64};AccountKey=[^;]{20,128}",
            re.IGNORECASE,
        ),
        category="cloud",
        provider="Azure",
        tags=("connection", "storage"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="gcp_service_account",
        description="Potential GCP service account email",
        pattern=re.compile(r"[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com"),
        category="cloud",
        provider="Google Cloud",
        tags=("service_account", "email"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
)

__all__ = ["PATTERNS"]
