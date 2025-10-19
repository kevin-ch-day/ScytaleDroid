"""Shared regexes and keyword lists for string analysis modules."""

from __future__ import annotations

import re
from typing import Mapping

HTTP_URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
ENDPOINT_PATTERN = re.compile(r"(?P<url>(?:https?|wss?)://[^\s'\"<>]+)", re.IGNORECASE)
CONTENT_URI_PATTERN = re.compile(r"content://[^\s'\"<>]+", re.IGNORECASE)
FILE_URI_PATTERN = re.compile(r"file://[^\s'\"<>]+", re.IGNORECASE)
HOST_PATTERN = re.compile(
    r"^(?=.{4,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
HOST_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+(?:\.|$)")
JWT_PATTERN = re.compile(
    r"(?P<token>[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)
JWT_FULLMATCH_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
AWS_ACCESS_KEY_PATTERN = re.compile(r"A(?:KI|SI)A[0-9A-Z]{16}")
AWS_SECRET_KEY_PATTERN = re.compile(r"(?<![A-Z0-9])[A-Za-z0-9/+=]{40,64}(?![A-Za-z0-9/+=])")
GOOGLE_API_KEY_PATTERN = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
STRIPE_KEY_PATTERN = re.compile(r"s[kpr]_(?:live|test)_[0-9a-zA-Z]{16,}")
SLACK_TOKEN_PATTERN = re.compile(r"xox(?:p|b|o|a|s|r)-[0-9A-Za-z-]{10,}")
GITHUB_TOKEN_PATTERN = re.compile(r"gh[opsuhr]_[0-9A-Za-z]{36}")
TWILIO_TOKEN_PATTERN = re.compile(r"(?:AC|SK)[0-9a-fA-F]{32}")
SCHEME_PREFIXES = frozenset({"http://", "https://", "ws://", "wss://"})
BASE64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
BASE64_URLSAFE_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
BASE64_CANDIDATE_PATTERN = re.compile(r"[A-Za-z0-9+/=]{32,256}")
GRAPHQL_HINT = re.compile(r"(?:/graphql|\"query\"\s*:\s*\")", re.IGNORECASE)
GRPC_HINT = re.compile(r"\":authority\"|\":path\"", re.IGNORECASE)
FEATURE_KEYWORDS = ("feature", "flag", "toggle", "remote_config")
AUTH_KEYWORDS = frozenset({"auth", "oauth", "token", "bearer", "secret", "hmac", "signin"})
REDIRECTOR_HOSTS = frozenset({"t.co", "bit.ly", "goo.gl", "tinyurl.com", "lnkd.in"})
CONTEXT_TOKENIZER = re.compile(r"[A-Za-z0-9_]+")
INTERNAL_HOST_SUFFIXES = frozenset({"corp", "internal", "lan", "local", "intra"})
DOCUMENTARY_ROOTS = frozenset(
    {
        "w3.org",
        "w3c.org",
        "w3schools.com",
        "adobe.com",
        "apache.org",
        "gnu.org",
        "creativecommons.org",
        "ietf.org",
        "schema.org",
        "schemas.android.com",
    }
)
MULTI_LEVEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "com.br",
        "com.cn",
        "com.tr",
        "com.mx",
        "com.sg",
        "com.hk",
        "com.tw",
        "co.in",
        "co.jp",
        "ne.jp",
    }
)
ANALYTICS_PATTERNS: Mapping[str, tuple[str, re.Pattern[str]]] = {
    "ga": ("google_analytics", re.compile(r"UA-\d{4,}-\d+", re.IGNORECASE)),
    "gtag": ("gtag", re.compile(r"G-[A-Z0-9]{6,}", re.IGNORECASE)),
    "firebase": ("firebase", re.compile(r"1:[0-9]{8,}:[a-z0-9]{10,}", re.IGNORECASE)),
    "admob": ("admob", re.compile(r"ca-app-pub-[0-9]{16}/[0-9]{10}", re.IGNORECASE)),
    "adjust": ("adjust", re.compile(r"[0-9a-f]{8}[0-9a-z]{8}", re.IGNORECASE)),
    "appsflyer": ("appsflyer", re.compile(r"[0-9a-f]{32}af", re.IGNORECASE)),
    "segment": ("segment", re.compile(r"[A-Za-z0-9]{32}\.[A-Za-z0-9]{32}", re.IGNORECASE)),
    "mixpanel": ("mixpanel", re.compile(r"[0-9a-f]{24}", re.IGNORECASE)),
}

API_KEY_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "aws_access_key": AWS_ACCESS_KEY_PATTERN,
    "aws_secret": AWS_SECRET_KEY_PATTERN,
    "google_api_key": GOOGLE_API_KEY_PATTERN,
    "stripe": STRIPE_KEY_PATTERN,
    "slack": SLACK_TOKEN_PATTERN,
    "github": GITHUB_TOKEN_PATTERN,
    "twilio": TWILIO_TOKEN_PATTERN,
}

CLOUD_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "aws_s3_host": re.compile(r"(?P<bucket>[a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
    "aws_s3_uri": re.compile(r"s3://(?P<bucket>[a-z0-9._-]+)/?"),
    "gcs_host": re.compile(r"storage.googleapis.com/(?P<bucket>[a-z0-9._-]+)/?"),
    "gcs_uri": re.compile(r"gs://(?P<bucket>[a-z0-9._-]+)/?"),
    "firebase_project": re.compile(r"(?P<project>[a-z0-9-]+)\.firebase(?:io|app)\.com"),
    "firebase_storage": re.compile(r"firebasestorage.googleapis.com/v0/b/(?P<bucket>[a-z0-9._-]+)/?"),
}
S3_VIRTUAL_HOST_REGION = re.compile(
    r"(?P<bucket>[a-z0-9.-]+)\.s3[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com"
)
S3_VIRTUAL_HOST_GLOBAL = re.compile(r"(?P<bucket>[a-z0-9.-]+)\.s3\.amazonaws\.com")
S3_PATH_REGION = re.compile(r"s3[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com/(?P<bucket>[a-z0-9._-]+)/?")
S3_PATH_GLOBAL = re.compile(r"s3\.amazonaws\.com/(?P<bucket>[a-z0-9._-]+)/?")
S3_URI_PATTERN = re.compile(r"s3://(?P<bucket>[a-z0-9._-]+)/?")
GCS_HOST_PATTERN = re.compile(r"storage.googleapis.com/(?P<bucket>[a-z0-9._-]+)/?")
GCS_URI_PATTERN = re.compile(r"gs://(?P<bucket>[a-z0-9._-]+)/?")
AZURE_BLOB_PATTERN = re.compile(
    r"(?P<account>[a-z0-9-]+)\.blob.core.windows.net/(?P<container>[a-z0-9-]+)/?"
)
FIREBASE_DB_PATTERN = re.compile(r"(?P<project>[a-z0-9-]+)\.firebaseio.com")
FIREBASE_STORAGE_PATTERN = re.compile(r"firebasestorage.googleapis.com/v0/b/(?P<bucket>[a-z0-9._-]+)/?")
CLOUDFRONT_HOST_PATTERN = re.compile(r"(?P<host>[a-z0-9.-]+\.cloudfront\.net)")
KEYWORD_LOOKUP_PATTERN = re.compile(r"secret|token|hmac|aes|bearer|auth", re.IGNORECASE)

__all__ = [
    "ANALYTICS_PATTERNS",
    "API_KEY_PATTERNS",
    "AUTH_KEYWORDS",
    "AWS_ACCESS_KEY_PATTERN",
    "AWS_SECRET_KEY_PATTERN",
    "AZURE_BLOB_PATTERN",
    "BASE64_ALPHABET",
    "BASE64_CANDIDATE_PATTERN",
    "BASE64_URLSAFE_ALPHABET",
    "CLOUD_PATTERNS",
    "CLOUDFRONT_HOST_PATTERN",
    "CONTENT_URI_PATTERN",
    "CONTEXT_TOKENIZER",
    "DOCUMENTARY_ROOTS",
    "ENDPOINT_PATTERN",
    "FEATURE_KEYWORDS",
    "FILE_URI_PATTERN",
    "FIREBASE_DB_PATTERN",
    "FIREBASE_STORAGE_PATTERN",
    "GCS_HOST_PATTERN",
    "GCS_URI_PATTERN",
    "GOOGLE_API_KEY_PATTERN",
    "GITHUB_TOKEN_PATTERN",
    "GRAPHQL_HINT",
    "GRPC_HINT",
    "SLACK_TOKEN_PATTERN",
    "HOST_COMPONENT_PATTERN",
    "HOST_PATTERN",
    "HTTP_URL_PATTERN",
    "INTERNAL_HOST_SUFFIXES",
    "JWT_FULLMATCH_PATTERN",
    "JWT_PATTERN",
    "KEYWORD_LOOKUP_PATTERN",
    "MULTI_LEVEL_SUFFIXES",
    "REDIRECTOR_HOSTS",
    "SCHEME_PREFIXES",
    "S3_PATH_GLOBAL",
    "S3_PATH_REGION",
    "S3_URI_PATTERN",
    "S3_VIRTUAL_HOST_GLOBAL",
    "S3_VIRTUAL_HOST_REGION",
    "STRIPE_KEY_PATTERN",
    "TWILIO_TOKEN_PATTERN",
]
